# Fortify on Demand Integration

This integration collects application security data from Fortify on Demand (FoD).

## Configuration

The integration requires:
- **api_url**: Fortify API base URL (default: https://api.ams.fortify.com)
- **api_key**: API client ID
- **api_secret**: API client secret

## Features

- OAuth2 authentication using client credentials
- Fetches all applications accessible to the authenticated user
- For each application, collects:
  - Application metadata (type, business criticality, dates)
  - All releases
  - Vulnerabilities from each release
- Maps Fortify findings to CVE-like identifiers
- Includes CVSS scores and CWE mappings when available
- Handles API pagination for large datasets

## Usage

```bash
./starlark-runner -script fortify-on-demand/fortify-on-demand.star -params "api_url=https://api.ams.fortify.com,api_key=your-client-id,api_secret=your-client-secret"
```

## Notes

- Applications are treated as "instances" in the Zafran model
- Each vulnerability is linked to its parent application
- All vulnerabilities are marked as static analysis findings (not runtime)
- Severity mapping:
  - Critical: 10.0
  - High: 7.0
  - Medium: 5.0
  - Low: 2.0
- CVSS scores from Fortify override the default severity scores when available

## API Endpoints Used

- `/oauth/token` - OAuth2 token endpoint
- `/api/v3/applications` - List applications
- `/api/v3/applications/{id}/releases` - Get releases for an application
- `/api/v3/releases/{id}/vulnerabilities` - Get vulnerabilities for a release