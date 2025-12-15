# Automox Integration

This integration collects device inventory and vulnerability information from Automox.

## Configuration

The integration uses the following parameters:
- **api_secret**: Automox API token for authentication (required)
- **api_key**: Organization ID for fetching software vulnerabilities (optional)
- **api_url**: Custom Automox API base URL (optional, defaults to https://console.automox.com)

## Features

- Imports all devices from Automox using pagination
- Collects comprehensive device information including:
  - Operating system details (name, version, family)
  - Network interfaces (IP addresses and MAC addresses)
  - Agent status and version
  - Compliance status
  - Serial numbers
  - Last logged in user
- Processes software vulnerabilities when org_id is configured
- Creates vulnerability records from software CVE data
- Maps device properties to Zafran instance format
- Supports both IPv4 and IPv6 addresses

## Usage

Basic device import (without vulnerabilities):
```bash
./starlark-runner -script automox/automox.star -params "api_secret=your-api-token"
```

With software vulnerability collection:
```bash
./starlark-runner -script automox/automox.star -params "api_secret=your-api-token,api_key=your-org-id"
```

With custom API URL:
```bash
./starlark-runner -script automox/automox.star -params "api_secret=your-api-token,api_key=your-org-id,api_url=https://custom.automox.com"
```

## API Endpoints Used

- `/api/servers` - List all devices with pagination
- `/api/servers/{id}/packages?o={org_id}` - Get software inventory for a device (when api_key/org_id is provided)

## Data Mapping

### Instance Properties
- `os_version`: Operating system version
- `os_family`: Operating system family (Windows, macOS, Linux)
- `agent_version`: Automox agent version
- `compliant`: Compliance status (boolean)
- `last_logged_in_user`: Last user to log into the device
- `serial_number`: Device serial number
- `agent_status`: Current agent connection status

### Identifiers
- Serial number is used as the primary identifier when available

### Vulnerabilities
When api_key (org_id) is provided, the integration:
- Fetches software inventory for each device
- Extracts CVE information from software packages
- Creates vulnerability records with CVSS scores
- Includes remediation suggestions

## Notes

- The integration uses pagination with 500 devices per page for optimal performance
- Both public and private IP addresses are collected
- MAC addresses are extracted from NIC details when available
- CVE data can be provided as either CSV strings or arrays
- Vulnerability processing requires the api_key parameter to contain the organization ID
- The api_url parameter supports both HTTP and HTTPS URLs, with or without protocol prefix
- Trailing slashes in the api_url are automatically removed for consistency