# Checkmarx One Integration

This integration fetches security scan results from Checkmarx One, including projects (instances) and vulnerabilities from multiple scan engines.

## Features

- OAuth 2.0 client credentials authentication
- Supports custom deployments (e.g., tenant.cxone.cloud) and standard regions
- Fetches all projects as instances
- Collects vulnerabilities from multiple scan types:
  - SCA (Software Composition Analysis) - dependency vulnerabilities
  - SAST (Static Application Security Testing) - code vulnerabilities
  - KICS (IaC scanning) - infrastructure misconfigurations
  - API Security - API vulnerabilities
- Extracts CVSS scores (v2.0, v3.1, v4.0)
- Extracts CWE IDs
- Includes remediation suggestions

## Configuration

### Parameters

| Parameter | Description | Required | Example |
|-----------|-------------|----------|---------|
| `api_url` | Checkmarx One base URL | Yes | `https://tenant.cxone.cloud` |
| `api_key` | OAuth Client ID | Yes | `SrvZafranCx1` |
| `api_secret` | OAuth Client Secret | Yes | `secret123...` |

### Supported Deployments

**Custom Deployments:**
- URL format: `https://{tenant}.cxone.cloud`
- Auth endpoint: `{base_url}/auth/realms/{tenant}/protocol/openid-connect/token`

**Standard Regions:**
- US: `https://ast.checkmarx.net`
- US-2: `https://us.ast.checkmarx.net`
- EU: `https://eu.ast.checkmarx.net`
- EU-2: `https://eu-2.ast.checkmarx.net`
- DEU: `https://deu.ast.checkmarx.net`
- ANZ: `https://anz.ast.checkmarx.net`
- IND: `https://ind.ast.checkmarx.net`
- SNG: `https://sng.ast.checkmarx.net`
- MEA: `https://mea.ast.checkmarx.net`

## Usage

```bash
./starlark-runner -script checkmarx/checkmarx.star -params "api_url=https://tenant.cxone.cloud,api_key=YOUR_CLIENT_ID,api_secret=YOUR_CLIENT_SECRET"
```

## Data Collected

### Instances (Projects)

Each Checkmarx project is collected as an instance with:
- `instance_id`: Project UUID
- `name`: Project name
- Properties:
  - `GROUPS`: Associated group IDs
  - `REPO_URL`: Repository URL
  - `MAIN_BRANCH`: Main branch name
  - `ORIGIN`: Project origin
  - `CRITICALITY`: Project criticality level

### Vulnerabilities

#### SCA Vulnerabilities
- `cve`: CVE identifier or Checkmarx vulnerability ID
- `component`: Library/package information (vendor, product, version)
- `CVSS`: CVSS scores from multiple versions
- `cwe_ids`: CWE identifiers
- `remediation`: Upgrade suggestions

#### SAST Vulnerabilities
- `cve`: Query name or Checkmarx SAST ID
- `component`: File path where vulnerability was found
- `CVSS`: Derived from severity
- `cwe_ids`: CWE identifiers
- `remediation`: Code review guidance

#### KICS (IaC) Vulnerabilities
- `cve`: KICS query ID
- `component`: Configuration file path
- `CVSS`: Derived from severity
- `remediation`: Infrastructure configuration guidance

#### API Security Vulnerabilities
- `cve`: Risk ID or Checkmarx API Security ID
- `component`: API endpoint
- `CVSS`: Derived from severity
- `remediation`: API security guidance

## API Endpoints Used

| Endpoint | Purpose |
|----------|---------|
| `POST /auth/realms/{tenant}/protocol/openid-connect/token` | OAuth authentication |
| `GET /api/projects` | List all projects |
| `GET /api/scans` | Get scans for a project |
| `POST /api/sca/export/requests` | Create SCA export |
| `GET /api/sca/export/requests` | Check export status |
| `GET /api/sca/export/requests/{id}/download` | Download SCA results |
| `GET /api/sast-results` | Get SAST scan results |
| `GET /api/kics-results` | Get KICS scan results |
| `GET /api/apisec-results` | Get API Security results |

## Scan Type Support

| Type | API | Status | Source Name |
|------|-----|--------|-------------|
| SCA | Export API | Supported | Checkmarx SCA |
| SAST | Results API | Supported | Checkmarx SAST |
| KICS | Results API | Supported | Checkmarx KICS |
| API Security | Results API | Supported | Checkmarx API Security |

## Notes

- The integration fetches results from the latest completed scan for each project
- SCA results use the export API (same as Go implementation) for detailed vulnerability data
- SAST, KICS, and API Security use the direct results API
- For projects without completed scans, vulnerabilities are skipped
- CVSS scores are extracted directly when available, or derived from severity level
