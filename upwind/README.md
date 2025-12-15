# Upwind Security Integration

This integration fetches vulnerability findings from the Upwind Security API and creates instances for affected cloud resources.

## Authentication

The integration uses OAuth2 client credentials flow. You'll need:
- **Client ID** (`api_key`)
- **Client Secret** (`api_secret`)

These can be generated in the Upwind console under API settings.

## Usage

```bash
./starlark-runner -script upwind/upwind.star \
  -params "api_key=YOUR_CLIENT_ID,api_secret=YOUR_CLIENT_SECRET" \
  -output upwind.json
```

### Optional Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `api_url` | Upwind API base URL (default: `https://api.upwind.io`) | `api_url=https://api.upwind.io` |
| `severity` | Filter by severity level | `severity=CRITICAL` or `severity=HIGH` |
| `in_use` | Filter for packages currently in use | `in_use=true` |

### Examples

```bash
# Fetch all vulnerabilities
./starlark-runner -script upwind/upwind.star \
  -params "api_key=...,api_secret=..." \
  -output upwind.json

# Fetch only CRITICAL vulnerabilities
./starlark-runner -script upwind/upwind.star \
  -params "api_key=...,api_secret=...,severity=CRITICAL" \
  -output upwind_critical.json

# Fetch only vulnerabilities for packages in use (runtime)
./starlark-runner -script upwind/upwind.star \
  -params "api_key=...,api_secret=...,in_use=true" \
  -output upwind_runtime.json
```

## Data Collected

### Instances

Each unique cloud resource with vulnerabilities becomes an instance with:

| Field | Description |
|-------|-------------|
| `instance_id` | Upwind resource ID |
| `name` | Resource name |
| `operating_system` | OS name and version (from container image) |

#### Instance Properties

- `cloud_provider` - AWS, AZURE, GCP, or BYOC
- `cloud_account_id` - Cloud account identifier
- `cloud_account_name` - Cloud account name
- `region` - Cloud region
- `resource_type` - Type of resource (e.g., Pod, EC2 instance)
- `namespace` - Kubernetes namespace (if applicable)
- `cluster_id` - Kubernetes cluster ID (if applicable)
- `external_id` - Cloud provider's resource ID
- `image_uri` - Container image URI
- `image_digest` - Container image digest
- `image_tag` - Container image tag
- `internet_exposed` - Whether the resource has internet exposure

### Vulnerabilities

Each vulnerability finding includes:

| Field | Description |
|-------|-------------|
| `instance_id` | Links to the affected resource |
| `cve` | CVE identifier (e.g., CVE-2023-1234) |
| `description` | Vulnerability description from NVD |
| `in_runtime` | Whether the vulnerable package is in use |
| `component.product` | Package name |
| `component.version` | Package version |
| `component.type` | Package type (LIBRARY, OPERATING_SYSTEM, APPLICATION) |
| `CVSS` | CVSS scores (v2, v3, v4 when available) |
| `remediation.suggestion` | Fix recommendation (e.g., "Update to version X.Y.Z") |

## API Endpoints Used

- `POST https://auth.upwind.io/oauth/token` - OAuth2 token exchange
- `GET /v1/organizations/{org-id}/vulnerability-findings` - List vulnerability findings with pagination

## Notes

- The integration automatically extracts the organization ID from the JWT token
- Pagination uses cursor-based tokens via the `Link` header
- Large organizations may have many findings; use severity/in_use filters to reduce data volume
- The API may return 500 errors under load; the integration includes retry logic (5 retries)
- Default chunk size is 5000 findings per page for faster processing
