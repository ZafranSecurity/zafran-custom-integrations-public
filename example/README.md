# Example Integration Script

This directory contains a template Starlark script that demonstrates how to build a custom integration.

## Overview

The `example.star` script shows how to:
- Connect to an external API
- Fetch instances (assets) and vulnerabilities
- Transform API responses into the required proto format
- Collect data using the Zafran module

## How to Use This Template

1. **Copy the file** - Copy `example.star` and rename it for your integration (e.g., `my_scanner.star`)

2. **Update API endpoints** - Modify the `fetch_instances()` and `fetch_vulnerabilities()` functions to call your API

3. **Map your data** - Update `parse_to_instance()` and `parse_to_finding()` to transform your API response into the proto format

4. **Adjust configuration** - Update the configuration constants at the top of the script:
   - `USE_OAUTH` - Set to `True` if your API requires OAuth token exchange
   - `PAGE_SIZE` - Adjust based on your API's pagination limits

> **Important:** The configuration constants (`USE_OAUTH`, `PAGE_SIZE`, etc.) are for development and testing purposes. In production, only three parameters can be passed to your script: `api_url`, `api_key`, and `api_secret`. Any other configuration must be hardcoded as constants in your script before deployment.

## Script Structure

| Function | Purpose |
|----------|---------|
| `main` | Entry point that orchestrates the integration |
| `get_bearer_token` | (Optional) Gets a bearer token from OAuth endpoint |
| `fetch_paginated` | Helper to fetch data with pagination support |
| `fetch_instances` | Fetches raw instance/asset data from the API |
| `fetch_vulnerabilities` | Fetches raw vulnerability data from the API |
| `parse_to_instance` | Transforms raw asset data into `InstanceData` proto |
| `parse_to_finding` | Transforms raw vulnerability data into `Vulnerability` proto |

## Running the Example

```bash
# Linux
./starlark-runner -script example/example.star -params "api_url=https://api.example.com,api_key=your_key"

# macOS
./starlark-runner-mac -script example/example.star -params "api_url=https://api.example.com,api_key=your_key"
```

## Notes

- The example uses mock data for demonstration. In a real integration, uncomment the HTTP calls and remove the mock data.
- See the main [README](../README.md) for full documentation on available modules and proto types.

