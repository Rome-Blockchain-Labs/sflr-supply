use actix_web::{App, HttpResponse, HttpServer, web};
use ethers::{
    abi::parse_abi,
    contract::Contract,
    providers::{Http, Provider},
    types::{Address, U256},
};
use log::{error, info};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fs,
    str::FromStr,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

// Configuration
#[derive(Deserialize, Clone, Debug)]
struct Config {
    rpc_url: String,
    contract_address: String,
    cache_ttl_seconds: u64,
    listen_address: String,
    port: u16,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            rpc_url: "https://flare-api.flare.network/ext/C/rpc".to_string(),
            contract_address: "0x12e605bc104e93B45e1aD99F9e555f659051c2BB".to_string(),
            cache_ttl_seconds: 1800,
            listen_address: "0.0.0.0".to_string(),
            port: 8080,
        }
    }
}

// Response models
#[derive(Serialize)]
struct SupplyResponse {
    result: String,
}

#[derive(Serialize)]
struct StatsResponse {
    total_supply: String,
    exchange_rate: String,
    total_pooled_flr: String,
    staker_count: String,
}

#[derive(Serialize)]
struct InfoResponse {
    name: String,
    version: String,
    description: String,
    endpoints: HashMap<String, String>,
}

// Cache structure for contract data
struct ContractCache {
    supply: U256,
    exchange_rate: U256,
    total_pooled_flr: U256,
    staker_count: U256,
    last_updated: Instant,
    ttl: Duration,
}

impl ContractCache {
    fn new(ttl_seconds: u64) -> Self {
        Self {
            supply: U256::zero(),
            exchange_rate: U256::zero(),
            total_pooled_flr: U256::zero(),
            staker_count: U256::zero(),
            last_updated: Instant::now() - Duration::from_secs(ttl_seconds + 1),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    fn is_stale(&self) -> bool {
        self.last_updated.elapsed() > self.ttl
    }

    fn update(
        &mut self,
        supply: U256,
        exchange_rate: U256,
        total_pooled_flr: U256,
        staker_count: U256,
    ) {
        self.supply = supply;
        self.exchange_rate = exchange_rate;
        self.total_pooled_flr = total_pooled_flr;
        self.staker_count = staker_count;
        self.last_updated = Instant::now();
    }
}

// Application state
struct AppState {
    contract: Contract<Provider<Http>>,
    cache: Arc<RwLock<ContractCache>>,
}

// Core business logic
mod core {
    use super::*;

    // Calculate exchange rate following the same logic as in the subgraph
    // flrAmount * 10^18 / shareAmount (when shareAmount > 0)
    pub fn _calculate_exchange_rate(flr_amount: U256, share_amount: U256) -> U256 {
        if share_amount.is_zero() {
            return U256::zero();
        }
        let scaling_factor = U256::from(10).pow(U256::from(18));
        (flr_amount * scaling_factor) / share_amount
    }

    // Format a U256 value as a decimal string with proper precision
    pub fn format_decimal(value: U256, decimals: u8) -> String {
        if value.is_zero() {
            return "0".to_string();
        }

        let scaling_factor = U256::from(10).pow(U256::from(decimals));
        let integer_part = value / scaling_factor;

        // For fraction part, use modulo operation
        let remainder = value - (integer_part * scaling_factor);

        if remainder.is_zero() {
            return integer_part.to_string();
        }

        // Convert remainder to string and pad with leading zeros
        let fraction_str = remainder.to_string();
        let padding = decimals as usize - fraction_str.len();
        let mut padded_fraction = "0".repeat(padding) + &fraction_str;

        // Trim trailing zeros
        while padded_fraction.ends_with('0') && padded_fraction.len() > 1 {
            padded_fraction.pop();
        }

        format!("{integer_part}.{padded_fraction}")
    }

    pub async fn fetch_contract_data(
        contract: &Contract<Provider<Http>>,
    ) -> Result<(U256, U256, U256, U256), String> {
        // Call totalSupply()
        let total_supply: U256 = contract
            .method::<_, U256>("totalSupply", ())
            .map_err(|e| format!("Failed to create totalSupply call: {e}"))?
            .call()
            .await
            .map_err(|e| format!("totalSupply call failed: {e}"))?;

        // Call totalPooledFlr()
        let total_pooled_flr: U256 = contract
            .method::<_, U256>("totalPooledFlr", ())
            .map_err(|e| format!("Failed to create totalPooledFlr call: {e}"))?
            .call()
            .await
            .map_err(|e| format!("totalPooledFlr call failed: {e}"))?;

        // Call stakerCount()
        let staker_count: U256 = contract
            .method::<_, U256>("stakerCount", ())
            .map_err(|e| format!("Failed to create stakerCount call: {e}"))?
            .call()
            .await
            .map_err(|e| format!("stakerCount call failed: {e}"))?;

        // Call getPooledFlrByShares() to get exchange rate
        let scaling_factor = U256::from(10).pow(U256::from(18));
        let exchange_rate: U256 = contract
            .method::<_, U256>("getPooledFlrByShares", (scaling_factor,))
            .map_err(|e| format!("Failed to create getPooledFlrByShares call: {e}"))?
            .call()
            .await
            .map_err(|e| format!("getPooledFlrByShares call failed: {e}"))?;

        Ok((total_supply, exchange_rate, total_pooled_flr, staker_count))
    }

    pub async fn update_cache_periodically(state: web::Data<AppState>, interval_secs: u64) {
        let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

        loop {
            interval.tick().await;

            match fetch_contract_data(&state.contract).await {
                Ok((supply, exchange_rate, total_pooled_flr, staker_count)) => {
                    let mut cache = state.cache.write().unwrap();
                    cache.update(supply, exchange_rate, total_pooled_flr, staker_count);
                    info!(
                        "Cache updated: supply={supply}, exchange_rate={exchange_rate}, total_pooled_flr={total_pooled_flr}, staker_count={staker_count}"
                    );
                }
                Err(e) => {
                    error!("Failed to update cache: {e}");
                }
            }
        }
    }
}

// API handlers
mod api {
    use super::*;

    // Original endpoint for CoinGecko - returns raw value
    pub async fn _supply(path: web::Path<String>, state: web::Data<AppState>) -> HttpResponse {
        let token_id = path.to_lowercase();

        if token_id != "sflr" {
            return HttpResponse::NotFound().body("Token not found");
        }

        // Check cache first
        let cache = state.cache.read().unwrap();
        if !cache.is_stale() && !cache.supply.is_zero() {
            return HttpResponse::Ok().json(SupplyResponse {
                result: cache.supply.to_string(),
            });
        }

        // Cache is stale or empty, fetch fresh data
        drop(cache); // Release the lock before the async call

        match core::fetch_contract_data(&state.contract).await {
            Ok((supply, exchange_rate, total_pooled_flr, staker_count)) => {
                // Update cache
                let mut cache = state.cache.write().unwrap();
                cache.update(supply, exchange_rate, total_pooled_flr, staker_count);

                HttpResponse::Ok().json(SupplyResponse {
                    result: supply.to_string(),
                })
            }
            Err(e) => {
                error!("Error fetching supply: {e}");

                // Try to use stale cache as fallback
                let cache = state.cache.read().unwrap();
                if !cache.supply.is_zero() {
                    HttpResponse::Ok().json(SupplyResponse {
                        result: cache.supply.to_string(),
                    })
                } else {
                    HttpResponse::ServiceUnavailable().body("Supply data unavailable")
                }
            }
        }
    }

    // New endpoint for human-readable values
    pub async fn supply_formatted(
        path: web::Path<String>,
        state: web::Data<AppState>,
    ) -> HttpResponse {
        let token_id = path.to_lowercase();

        if token_id != "sflr" {
            return HttpResponse::NotFound().body("Token not found");
        }

        // Check cache first
        let cache = state.cache.read().unwrap();
        if !cache.is_stale() && !cache.supply.is_zero() {
            return HttpResponse::Ok().json(SupplyResponse {
                result: core::format_decimal(cache.supply, 18),
            });
        }

        // Cache is stale or empty, fetch fresh data
        drop(cache); // Release the lock before the async call

        match core::fetch_contract_data(&state.contract).await {
            Ok((supply, exchange_rate, total_pooled_flr, staker_count)) => {
                // Update cache
                let mut cache = state.cache.write().unwrap();
                cache.update(supply, exchange_rate, total_pooled_flr, staker_count);

                HttpResponse::Ok().json(SupplyResponse {
                    result: core::format_decimal(supply, 18),
                })
            }
            Err(e) => {
                error!("Error fetching supply: {e}");

                // Try to use stale cache as fallback
                let cache = state.cache.read().unwrap();
                if !cache.supply.is_zero() {
                    HttpResponse::Ok().json(SupplyResponse {
                        result: core::format_decimal(cache.supply, 18),
                    })
                } else {
                    HttpResponse::ServiceUnavailable().body("Supply data unavailable")
                }
            }
        }
    }

    pub async fn stats(state: web::Data<AppState>) -> HttpResponse {
        // Check cache first
        let cache = state.cache.read().unwrap();
        if !cache.is_stale() && !cache.supply.is_zero() {
            // Format numbers for human readability
            let formatted_supply = core::format_decimal(cache.supply, 18);
            let formatted_exchange_rate = core::format_decimal(cache.exchange_rate, 18);
            let formatted_pooled_flr = core::format_decimal(cache.total_pooled_flr, 18);

            return HttpResponse::Ok().json(StatsResponse {
                total_supply: formatted_supply,
                exchange_rate: formatted_exchange_rate,
                total_pooled_flr: formatted_pooled_flr,
                staker_count: cache.staker_count.to_string(),
            });
        }

        // Cache is stale or empty, fetch fresh data
        drop(cache); // Release the lock before the async call

        match core::fetch_contract_data(&state.contract).await {
            Ok((supply, exchange_rate, total_pooled_flr, staker_count)) => {
                // Update cache
                let mut cache = state.cache.write().unwrap();
                cache.update(supply, exchange_rate, total_pooled_flr, staker_count);

                // Format numbers for human readability
                let formatted_supply = core::format_decimal(supply, 18);
                let formatted_exchange_rate = core::format_decimal(exchange_rate, 18);
                let formatted_pooled_flr = core::format_decimal(total_pooled_flr, 18);

                HttpResponse::Ok().json(StatsResponse {
                    total_supply: formatted_supply,
                    exchange_rate: formatted_exchange_rate,
                    total_pooled_flr: formatted_pooled_flr,
                    staker_count: staker_count.to_string(),
                })
            }
            Err(e) => {
                error!("Error fetching stats: {e}");

                // Try to use stale cache as fallback
                let cache = state.cache.read().unwrap();
                if !cache.supply.is_zero() {
                    // Format numbers for human readability
                    let formatted_supply = core::format_decimal(cache.supply, 18);
                    let formatted_exchange_rate = core::format_decimal(cache.exchange_rate, 18);
                    let formatted_pooled_flr = core::format_decimal(cache.total_pooled_flr, 18);

                    HttpResponse::Ok().json(StatsResponse {
                        total_supply: formatted_supply,
                        exchange_rate: formatted_exchange_rate,
                        total_pooled_flr: formatted_pooled_flr,
                        staker_count: cache.staker_count.to_string(),
                    })
                } else {
                    HttpResponse::ServiceUnavailable().body("Stats data unavailable")
                }
            }
        }
    }

    pub async fn info() -> HttpResponse {
        let mut endpoints = HashMap::new();
        endpoints.insert(
            "/supply/sflr".to_string(),
            "Raw total supply (for CoinGecko)".to_string(),
        );
        endpoints.insert(
            "/total_supply/sflr".to_string(),
            "Raw total supply (for CoinGecko)".to_string(),
        );
        endpoints.insert(
            "/supply-formatted/sflr".to_string(),
            "Human-readable total supply".to_string(),
        );
        endpoints.insert(
            "/total_supply-formatted/sflr".to_string(),
            "Human-readable total supply".to_string(),
        );
        endpoints.insert(
            "/stats".to_string(),
            "Complete statistics including exchange rate".to_string(),
        );
        endpoints.insert("/health".to_string(), "API health check".to_string());
        endpoints.insert(
            "/info".to_string(),
            "API information and available endpoints".to_string(),
        );

        HttpResponse::Ok().json(InfoResponse {
            name: "SFLR Supply API".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            description: "API for retrieving SFLR token supply and statistics".to_string(),
            endpoints,
        })
    }

    pub async fn health() -> HttpResponse {
        HttpResponse::Ok().body("OK")
    }
}

// Configuration loader
fn load_config() -> Config {
    // Try config file first
    if let Ok(content) = fs::read_to_string("config.toml") {
        if let Ok(config) = toml::from_str(&content) {
            return config;
        }
    }

    // Fall back to environment variables
    let mut config = Config::default();

    if let Ok(url) = std::env::var("SFLR_RPC_URL") {
        config.rpc_url = url;
    }

    if let Ok(addr) = std::env::var("SFLR_CONTRACT_ADDRESS") {
        config.contract_address = addr;
    }

    if let Ok(ttl) = std::env::var("SFLR_CACHE_TTL_SECONDS")
        .map_err(|_| ())
        .and_then(|v| v.parse().map_err(|_| ()))
    {
        config.cache_ttl_seconds = ttl;
    }

    if let Ok(addr) = std::env::var("SFLR_LISTEN_ADDRESS") {
        config.listen_address = addr;
    }

    if let Ok(port) = std::env::var("SFLR_PORT")
        .map_err(|_| ())
        .and_then(|v| v.parse().map_err(|_| ()))
    {
        config.port = port;
    }

    config
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logging
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load configuration
    let config = load_config();

    info!("Starting SFLR Supply API");
    info!("RPC URL: {}", config.rpc_url);
    info!("Contract: {}", config.contract_address);

    // Create provider
    let provider = match Provider::<Http>::try_from(&config.rpc_url as &str) {
        Ok(provider) => provider,
        Err(e) => {
            error!("Failed to connect to RPC: {e}");
            std::process::exit(1);
        }
    };

    // Parse contract address
    let contract_address = match Address::from_str(&config.contract_address) {
        Ok(addr) => addr,
        Err(e) => {
            error!("Invalid contract address: {e}");
            std::process::exit(1);
        }
    };

    // Define contract ABI with functions we need
    let abi = match parse_abi(&[
        "function totalSupply() external view returns (uint256)",
        "function totalPooledFlr() external view returns (uint256)",
        "function stakerCount() external view returns (uint256)",
        "function getPooledFlrByShares(uint256 _sharesAmount) external view returns (uint256)",
    ]) {
        Ok(abi) => abi,
        Err(e) => {
            error!("Failed to parse ABI: {e}");
            std::process::exit(1);
        }
    };

    // Create contract instance
    let contract = Contract::new(contract_address, abi, Arc::new(provider));

    // Create app state
    let cache = Arc::new(RwLock::new(ContractCache::new(config.cache_ttl_seconds)));
    let app_state = web::Data::new(AppState {
        contract,
        cache: cache.clone(),
    });

    // Start background update task
    let update_interval_secs = config.cache_ttl_seconds / 2;
    let app_state_clone = app_state.clone();
    tokio::spawn(async move {
        core::update_cache_periodically(app_state_clone, update_interval_secs).await;
    });

    // Try to get initial data
    match core::fetch_contract_data(&app_state.contract).await {
        Ok((supply, exchange_rate, total_pooled_flr, staker_count)) => {
            let mut cache_guard = cache.write().unwrap();
            cache_guard.update(supply, exchange_rate, total_pooled_flr, staker_count);
            info!(
                "Initial data loaded: supply={supply}, exchange_rate={exchange_rate}, total_pooled_flr={total_pooled_flr}, staker_count={staker_count}"
            );
        }
        Err(e) => {
            error!("Failed to fetch initial data: {e}");
        }
    }

    // Start HTTP server
    let bind_address = format!("{}:{}", config.listen_address, config.port);
    info!("Listening on {bind_address}");
    info!("API endpoints available at /info");

    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            // CoinGecko compatible endpoints (raw values)
            .service(
                web::resource("/supply/{token_id}").route(web::get().to(api::supply_formatted)),
            )
            .service(
                web::resource("/total_supply/{token_id}")
                    .route(web::get().to(api::supply_formatted)),
            )
            // Stats and metadata endpoints
            .service(web::resource("/stats").route(web::get().to(api::stats)))
            .service(web::resource("/info").route(web::get().to(api::info)))
            // Health
            .service(web::resource("/health").route(web::get().to(api::health)))
            // Root path redirects to info
            .service(web::resource("/").route(web::get().to(api::info)))
    })
    .bind(bind_address)?
    .run()
    .await
}
