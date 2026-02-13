# Generic Adapter

A flexible adapter that expects the source system to provide correctly formatted JSON data.

## Overview

This adapter is designed for sources that can format their data according to the Zafran data model. The source is responsible for transforming its data into the expected JSON structure.

## Parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| api_url | Yes | Full URL of the API endpoint (e.g., https://api.example.com/data) |
| api_key | Yes | API authentication key (sent as Bearer token) |
| api_secret | No | Optional API secret (sent as X-API-Secret header) |

## API Endpoint Expected

The adapter expects the source to provide a **single endpoint** that returns both instances and vulnerabilities in one JSON response.

**Endpoint**: The URL specified in the `api_url` parameter

## Expected JSON Format

The API endpoint must return a single JSON response containing both instances and vulnerabilities:

```json
{
  "instances": [
    {
      "instance_id": "unique-id",
      "name": "display-name",
      "operating_system": "Ubuntu 22.04",
      "ip_addresses": ["192.168.1.1", "10.0.0.5"],
      "mac_addresses": ["00:11:22:33:44:55"],
      "identifiers": [
        {
          "type": "AWS_EC2_INSTANCE_ID",
          "value": "i-1234567890abcdef0"
        },
        {
          "type": "LINUX_UUID",
          "value": "550e8400-e29b-41d4-a716-446655440000"
        }
      ],
      "properties": {
        "key1": {
          "type": "STRING",
          "value": "value1"
        },
        "key2": {
          "type": "INT",
          "value": 123
        },
        "last_seen": {
          "type": "DATETIME",
          "value": "2024-01-15T10:30:00Z"
        }
      },
      "labels": ["production", "web-server"],
      "tags": [
        {
          "key": "environment",
          "value": "prod"
        },
        {
          "key": "team",
          "value": "platform"
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "instance_id": "unique-id",
      "cve": "CVE-2023-1234",
      "title": "Vulnerability Title",
      "description": "Detailed description of the vulnerability",
      "severity": "HIGH",
      "in_runtime": true,
      "component": {
        "type": "LIBRARY",
        "product": "openssl",
        "vendor": "openssl",
        "version": "1.1.1",
        "fixed_version": "1.1.1t"
      },
      "cvss": [
        {
          "version": "3.1",
          "base_score": 9.8,
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        }
      ],
      "remediation": {
        "suggestion": "Update to version 1.1.1t or later",
        "source": "Scanner Name"
      },
      "cwe_ids": [79, 89],
      "discovered_at": "2024-01-15T10:30:00Z"
    }
  ]
}
```

### Instance Fields

**Required Fields:**
- `instance_id` (string) - Unique identifier for the instance
- `name` (string) - Display name for the instance

**Optional Fields:**
- `operating_system` (string) - Operating system name and version
- `ip_addresses` (array of strings) - IP addresses
- `mac_addresses` (array of strings) - MAC addresses
- `identifiers` (array of objects) - System identifiers
- `properties` (object) - Additional metadata as key-value pairs
- `labels` (array of strings) - Simple labels
- `tags` (array of objects) - Key-value tags

#### Identifier Types

Valid `type` values for identifiers:
- `AWS_EC2_INSTANCE_ID`
- `AZURE_VM_ID`
- `GCP_INSTANCE_ID`
- `LINUX_UUID`
- `SERIAL_NUMBER`
- `HOSTNAME`
- `MAC_ADDRESS`

#### Property Types

Valid `type` values for properties:
- `STRING` - Text value
- `INT` - Integer value
- `FLOAT` - Floating point value
- `BOOL` - Boolean value
- `DATETIME` - ISO 8601 datetime string

### Vulnerability Fields

**Required Fields:**
- `instance_id` (string) - Must match an instance_id from the instances array
- `cve` (string) OR `title` (string) - At least one is required

**Optional Fields:**
- `title` (string) - Vulnerability title
- `description` (string) - Detailed description
- `severity` (string) - Severity level (e.g., LOW, MEDIUM, HIGH, CRITICAL)
- `in_runtime` (boolean) - Whether vulnerability is exploitable in runtime
- `component` (object) - Affected software component
- `cvss` (array of objects) - CVSS scoring information
- `remediation` (object) - Fix recommendations
- `cwe_ids` (array of integers) - CWE identifiers
- `discovered_at` (string) - ISO 8601 datetime when discovered

#### Component Types

Valid `type` values for components:
- `APPLICATION`
- `LIBRARY`
- `OPERATING_SYSTEM`
- `FILE`
- `FRAMEWORK`
- `CONTAINER`

## Authentication

The adapter supports two authentication methods:

1. **Bearer Token (Required)**: The `api_key` parameter is sent as a Bearer token in the Authorization header
2. **API Secret (Optional)**: If provided, `api_secret` is sent in the `X-API-Secret` header

Example request headers:
```
Authorization: Bearer your-api-key-here
X-API-Secret: your-api-secret-here
Content-Type: application/json
```

## Usage Example

```bash
./starlark-runner-linux \
  -script generic/generic.star \
  -params "api_url=https://api.example.com/data,api_key=your-api-key-here,api_secret=your-secret"
```

## Implementation Guide for Source Systems

To make your API compatible with this adapter:

1. **Create a single endpoint** that returns both instances and vulnerabilities in one JSON response
2. **Format your data** according to the JSON schema above
3. **Handle authentication** by accepting Bearer token in Authorization header
4. **Return all data** in a single response (pagination not currently supported)
5. **Ensure data consistency**: All `instance_id` values in vulnerabilities must reference valid instances from the instances array

### Minimal Example

The simplest possible response:

```json
{
  "instances": [
    {
      "instance_id": "server-001",
      "name": "Production Web Server"
    }
  ],
  "vulnerabilities": [
    {
      "instance_id": "server-001",
      "cve": "CVE-2023-1234",
      "severity": "HIGH"
    }
  ]
}
```

## Error Handling

The adapter will:
- Log errors for invalid data but continue processing other items
- Skip instances without required fields (instance_id, name)
- Skip vulnerabilities without required fields (instance_id, cve/title)
- Log warnings for invalid enum values (identifier types, component types, property types)

## Limitations

- No pagination support - all data must be returned in a single response
- No incremental updates - full dataset is processed each run
- HTTP GET requests only
- Simple Bearer token authentication

## Future Enhancements

Potential improvements for future versions:
- Pagination support for large datasets
- POST request support for complex queries
- OAuth2 authentication flow
- Delta/incremental updates
- Webhooks for real-time updates

## Support

For questions or issues with this adapter, please refer to the main repository documentation.
