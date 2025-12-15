# Cyver Integration

This integration collects penetration testing findings from Cyver's vulnerability management platform.

## Configuration

The integration requires:
- **api_url**: The Cyver API endpoint URL (e.g., `https://{your_portal_name}.cyver.io/api`)
- **api_key**: Cyver API authentication key
- **api_secret**: Not used by Cyver, but part of the standard parameter interface

Additional settings can be configured as parameters:
- **limit**: Maximum number of findings to process (optional, useful for testing)

## Features

- Fetches penetration testing findings from Cyver API
- Groups vulnerabilities by project (pentest engagement)
- Collects detailed vulnerability information including:
  - Finding codes (e.g., F-2025-0086)
  - Comprehensive descriptions (name + description + impact)
  - CVSS v3.1 scores and vectors
  - CWE identifiers
  - Remediation recommendations
- Maps findings to project-based instances using projectId
- Extracts clean instance names from project identifiers

## Usage

### Basic Usage

```bash
./starlark-runner-mac -script cyver/cyver.star -params "api_url=https://{your_portal_name}.cyver.io/api,api_key=YOUR_API_KEY"
```

### With Output File

```bash
./starlark-runner-mac -script cyver/cyver.star -params "api_url=https://{your_portal_name}.cyver.io/api,api_key=YOUR_API_KEY" -output cyver_output2.json.json
```

### Testing with Limited Results

```bash
./starlark-runner-mac -script cyver/cyver.star -params "api_url=https://{your_portal_name}.cyver.io/api,api_key=YOUR_API_KEY,limit=10" -output cyver_output2.json.json
```

## Data Mapping

### Instance Mapping
- **instance_id**: Cyver project UUID
- **name**: Parsed from project name

### Vulnerability Mapping
- **cve**: Cyver finding code and its name
- **description**: Concatenation of finding name, description, and impact description
- **component.type**: Set to APPLICATION (type 1)
- **CVSS**: Uses CVSS v3.1 scores and vectors from Cyver
- **cwe_ids**: Extracted from Cyver's CWE list (converted from `CWE-611` to `611`)
- **remediation**: Maps recommendation field to remediation suggestion

## Instance Name Parsing

The integration extracts clean instance names from Cyver project names:
- `CYBER-1111 - Test Instance` → `TestInstance` (spaces removed)

## Notes

- Each project (pentest engagement) becomes a unique instance
- Multiple findings from the same project are associated with the same instance
- Findings without a projectId are skipped
- The integration requires a valid API key for authentication
- Description field combines finding name, description, and impact for comprehensive context
- All instances are grouped by Cyver project UUID for accurate tracking

