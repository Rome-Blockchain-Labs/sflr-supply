# SFLR Supply API

A lightweight API service that provides SFLR token supply information for
integration with CoinGecko and other platforms.

## Features

- `/supply/sflr` - Returns circulating supply
- `/total_supply/sflr` - Returns total supply
- `/stats` - Returns comprehensive token statistics including exchange rate
- `/info` - Displays all available API endpoints
- `/health` - Health check for monitoring

## Configuration

The API can be configured via environment variables:

```bash
SFLR_RPC_URL=https://flare-api.flare.network/ext/C/rpc
SFLR_CONTRACT_ADDRESS=0x12e605bc104e93B45e1aD99F9e555f659051c2BB
SFLR_CACHE_TTL_SECONDS=1800
SFLR_LISTEN_ADDRESS=0.0.0.0
SFLR_PORT=8080
```
