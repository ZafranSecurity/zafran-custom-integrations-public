# Jamf Integration

This integration collects computer and mobile device inventory from Jamf Pro.

## Configuration

The integration requires:
- **api_url**: The base URL of your Jamf Pro server (e.g., `https://yourinstance.jamfcloud.com`)
- **api_key**: OAuth2 client ID for API authentication
- **api_secret**: OAuth2 client secret for API authentication

Additional settings are configured as constants in the script:
- **days_ago**: Number of days to look back for inventory (default: 60)
- **include_computers**: Import computer inventory (default: true)
- **include_mobile**: Import mobile device inventory (default: true)

## Features

- Supports both computer and mobile device inventory
- OAuth2 authentication with automatic token refresh
- Collects detailed device information including:
  - Hardware details (serial number, model, manufacturer)
  - Operating system information
  - Network interfaces (IP addresses and MAC addresses)
  - Extension attributes (both device and user)
  - Security information
  - Custom attributes with nested data flattening
- Filters devices by last contact/inventory date
- Handles pagination for large inventories

## Usage

```bash
./starlark-runner -script jamf.star -params "api_url=https://yourinstance.jamfcloud.com,api_key=your-client-id,api_secret=your-client-secret"
```

## Notes

- The integration only imports devices with private IP addresses by default
- Extension attributes are sanitized and prefixed with "ext_attr_"
- Automatic token refresh occurs every 100 requests or on 403 errors
- Complex nested data structures are flattened for easier access
- Mobile device names have spaces replaced with hyphens