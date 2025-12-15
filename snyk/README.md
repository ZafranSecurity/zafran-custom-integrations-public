# Snyk Integration

This integration fetches security vulnerability data from Snyk, including targets (code repositories) and vulnerability issues.

## Features

- OAuth 2.0 client credentials authentication
- Fetches all organizations accessible to the service account
- Collects targets (code repository assets) as instances
- Collects all Snyk issue types as vulnerability findings:
  - SCA (package_vulnerability) - open source dependency vulnerabilities
  - SAST (code) - static code analysis findings
  - IaC (config) - infrastructure as code misconfigurations
  - License - license compliance issues
  - Cloud - cloud security misconfigurations
- Extracts CWE IDs from vulnerability classes
- Supports pagination for large datasets

## Configuration

### Parameters

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `api_url` | Snyk API base URL | No | `https://api.snyk.io` |
| `api_key` | Client ID (UUID format) | Yes | - |
| `api_secret` | Client Secret | Yes | - |

### Snyk Setup

1. Create a Snyk Service Account in your Snyk organization settings
2. Generate API credentials (Client ID and Client Secret)
3. Ensure the service account has appropriate permissions to:
   - View organizations
   - View targets
   - View issues

## Usage

```bash
./starlark-runner -script snyk/snyk.star -params "api_key=YOUR_CLIENT_ID,api_secret=YOUR_CLIENT_SECRET"
```

With custom API URL (e.g., for Snyk EU or AU regions):
```bash
./starlark-runner -script snyk/snyk.star -params "api_url=https://api.eu.snyk.io,api_key=YOUR_CLIENT_ID,api_secret=YOUR_CLIENT_SECRET"
```

## Data Collected

### Instances (Targets)

Each Snyk target (code repository) is collected as an instance with:
- `instance_id`: Target UUID
- `name`: Display name of the target
- Properties:
  - `is_private`: Whether the target is private
  - `origin`: Source of the target (e.g., github, gitlab)
  - `remote_url`: URL to the repository
  - `org_id`: Snyk organization ID
  - `org_name`: Snyk organization name
  - `created_at`: Target creation timestamp

### Vulnerabilities (Issues)

Each Snyk issue is collected as a vulnerability with:
- `cve`: CVE identifier (from NVD) or Snyk ID
- `description`: Issue title
- `instance_id`: Linked project/target ID
- `component`: Affected package/file information
  - `type`: APPLICATION for SCA, FILE for SAST
  - `product`: Package name (SCA) or file path (SAST)
  - `version`: Package version (SCA only)
- `CVSS`: CVSS scores from NVD or Snyk (derived from severity for SAST)
- `cwe_ids`: CWE identifiers extracted from issue classes
- `remediation`: Link to Snyk advisory or remediation guidance

### Issue Types Collected

| Type | API Parameter | Description | Source Name |
|------|---------------|-------------|-------------|
| SCA | `package_vulnerability` | Open source dependency vulnerabilities | Snyk Open Source |
| SAST | `code` | Static code analysis findings | Snyk Code |
| IaC | `config` | Infrastructure as Code misconfigurations | Snyk IaC |
| License | `license` | License compliance issues | Snyk Open Source |
| Cloud | `cloud` | Cloud security misconfigurations | Snyk Cloud |

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /oauth2/token` | Get OAuth access token |
| `GET /rest/orgs` | List all organizations |
| `GET /rest/orgs/{orgId}/targets` | List targets in organization |
| `GET /rest/orgs/{orgId}/issues` | List issues in organization |

## Notes

- The integration uses Snyk's REST API with version `2025-03-10`
- Only open issues are collected (status: `open`)
- Collects both SCA (`package_vulnerability`) and SAST (`code`) issue types
- CVE identifiers are extracted from NVD problem sources when available
- For SAST issues without CVEs, a `SNYK-CODE-` prefixed identifier is used
- CVSS scores prefer NVD source, then Snyk, then Red Hat/SUSE
- For SAST issues without CVSS, scores are derived from `effective_severity_level`
- CWE IDs are extracted from the `classes` attribute of each issue
