# Starlark Runner

A command-line tool for executing and testing Starlark integration scripts using the ScriptExecutor.

## Features

- Execute Starlark scripts with parameter passing
- JSON output of collected instances and vulnerabilities
- Full module support (http, json, crypto, etc.) via the ScriptExecutor
- Script validation and error reporting

## Building

```bash
cd apps/collection/sync_cloud_services
go build -o cmd/starlark-runner/starlark-runner ./cmd/starlark-runner
```

## Usage

### Running a Script

Execute a script and output results to stdout:
```bash
./starlark-runner -script example.star
```

Execute with parameters:
```bash
./starlark-runner -script example.star -params "api_url=https://api.example.com,api_key=secret"
```

Save output to file:
```bash
./starlark-runner -script example.star -output results.json
```

### Command Line Options

- `-script` - Path to the Starlark script file (required)
- `-output` - Optional output file for JSON results (default: stdout)
- `-params` - Comma-separated key=value parameters to pass to the script
- `-help` - Show help message

### Script Requirements

The script must define a `main` function that accepts keyword arguments:

```python
load("zafran", "zafran")

def main(**kwargs):
    # Get standard parameters (only these 3 are provided)
    api_url = kwargs.get("api_url", "")
    api_key = kwargs.get("api_key", "")
    api_secret = kwargs.get("api_secret", "")
    
    # Get proto types
    pb = zafran.proto_file
    
    # Your integration logic here
    # Use zafran.collect_instance() and zafran.collect_vulnerability() to collect data
```

### Standard Parameters

Scripts receive exactly three parameters via kwargs:
- `api_url` - The API endpoint URL for the integration
- `api_key` - The API key for authentication
- `api_secret` - The API secret for authentication (if needed)

Any additional configuration values should be defined as constants within the script.

### Available Modules

All modules from the ScriptExecutor are available:

- `http` - HTTP client for API calls
- `json` - JSON encoding/decoding
- `time` - Time and date functions
- `uuid` - UUID generation
- `net` - Network utilities (IP validation, etc.)
- `crypto` - Cryptographic functions (MD5, SHA256, etc.)
- `base64` - Base64 encoding/decoding
- `gzip` - Compression utilities
- `hash` - Additional hash functions
- `log` - Logging functions
- `zafran` - Main module for proto types and data collection

### The Zafran Module

The `zafran` module is the primary interface for creating and collecting instances and vulnerabilities:

- `zafran.proto_file` - Access to all proto message types and enums
- `zafran.collect_instance(instance)` - Collect an instance (max 100,000 per flush)
- `zafran.collect_vulnerability(vuln)` - Collect a vulnerability (max 1,000,000 per flush)
- `zafran.flush()` - Send collected data and clear the in-memory store (see below)

#### Proto Types Available via zafran.proto_file:

**Instance Types:**
- `InstanceData` - Main instance data structure
- `AssetInstanceInformation` - IP and MAC address information
- `InstanceIdentifier` - Instance identifier with type
- `InstancePropertyValue` - Property value with type
- `InstanceTag` - Tag with key/value or label
- `InetEvidence` - Internet-facing evidence
- `SBOMComponent` - Software Bill of Materials component for software inventory

**Vulnerability Types:**
- `Vulnerability` - Main vulnerability structure
- `Component` - Software component information
- `CVSS` - CVSS score information
- `Remediation` - Remediation suggestion

**Enums:**
- `IdentifierType` - AWS_EC2_INSTANCE_ID, AZURE_VM_ID, etc.
- `InstancePropertyType` - STRING, INT, FLOAT, BOOL, DATETIME
- `ComponentType` - APPLICATION, LIBRARY, OPERATING_SYSTEM, etc.
- `InstanceType` - MACHINE, CONTAINER_IMAGE, SERVERLESS, etc.

#### Using zafran.flush()

The `zafran.flush()` function sends all collected instances and vulnerabilities to Zafran and clears the in-memory store. This is useful for:

- **Large datasets**: Avoid accumulating all data in memory by flushing periodically
- **Paginated APIs**: Flush after processing each page of results
- **Long-running scripts**: Send data incrementally instead of all at once at the end

**Behavior:**
- Sends all collected instances and their associated vulnerabilities
- Clears the in-memory store after successful send
- Returns `None` on success
- If called with no instances collected, it's a no-op (orphan vulnerabilities are dropped with a warning)
- Any unflushed data is automatically sent when the script completes (backward compatible)

**Example with paginated API:**

```python
load("zafran", "zafran")
load("http", "http")

def main(**kwargs):
    pb = zafran.proto_file
    api_url = kwargs.get("api_url", "")
    api_key = kwargs.get("api_key", "")

    page = 1
    while True:
        response = http.get(
            api_url + "/assets?page=" + str(page),
            headers={"Authorization": "Bearer " + api_key}
        )
        data = response.json()

        if not data.get("items"):
            break

        for item in data["items"]:
            # Collect instance
            instance = pb.InstanceData(
                instance_id=item["id"],
                name=item["name"],
                operating_system=item.get("os", "")
            )
            zafran.collect_instance(instance)

            # Collect vulnerabilities for this instance
            for vuln in item.get("vulnerabilities", []):
                v = pb.Vulnerability(
                    instance_id=item["id"],
                    cve=vuln["cve"],
                    description=vuln.get("description", "")
                )
                zafran.collect_vulnerability(v)

        # Flush after each page to avoid memory buildup
        zafran.flush()
        page += 1
```

**Important notes:**
- Always collect instances before their associated vulnerabilities
- Vulnerabilities reference instances by `instance_id` - if you flush vulnerabilities without their instances, they will be dropped
- The instance/vulnerability limits (100,000 and 1,000,000) apply per flush, not globally

### Example Script

See `example.star` for a complete example integration script that demonstrates:
- Loading required modules including zafran
- Accessing proto types via zafran.proto_file
- Processing parameters
- Creating instances and vulnerabilities using proto messages
- Using logging
- Making HTTP requests (mocked in example)
- Collecting data with zafran.collect_instance() and zafran.collect_vulnerability()

### Output Format

The tool outputs JSON with the following structure:

```json
{
  "instances": [
    {
      "instance_id": "server-001",
      "name": "web-server-01",
      "operating_system": "Ubuntu 22.04",
      "asset_information": {
        "ip_addresses": ["192.168.1.100"],
        "mac_addresses": ["00:11:22:33:44:55"]
      },
      "identifiers": [
        {
          "key": 6,  // LINUX_UUID
          "value": "server-001",
          "scanner_type": "mock"
        }
      ],
      "instance_properties": {},
      "labels": ["production", "critical"],
      "key_value_tags": {
        "environment": "production",
        "team": "platform"
      },
      "sbom_components": [
        {
          "component": {
            "type": 1,  // APPLICATION
            "product": "com.google.Chrome",
            "vendor": "Google",
            "version": "120.0.6099.129",
            "display_name": "Google Chrome"
          },
          "file_paths": ["/Applications/Google Chrome.app"]
        }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "instance_id": "server-001",
      "cve": "CVE-2023-1234",
      "in_runtime": true,
      "component": {
        "type": 10,  // LIBRARY
        "product": "openssl",
        "vendor": "openssl",
        "version": "1.1.1"
      },
      "remediation": {
        "suggestion": "Update to latest version",
        "source": "Vendor Advisory"
      },
      "CVSS": [
        {
          "version": "3.1",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "base_score": 9.8
        }
      ],
      "description": "Critical vulnerability in OpenSSL"
    }
  ]
}
```

### Creating Proto Messages

Here's how to create instances and vulnerabilities using the proto API:

```python
load("zafran", "zafran")

# Get proto types
pb = zafran.proto_file

# Create an instance
instance = pb.InstanceData(
    instance_id="server-001",
    name="web-server-01",
    operating_system="Ubuntu 22.04",
    asset_information=pb.AssetInstanceInformation(
        ip_addresses=["192.168.1.100", "10.0.0.50"],
        mac_addresses=["00:11:22:33:44:55"]
    ),
    identifiers=[
        pb.InstanceIdentifier(
            key=pb.IdentifierType.LINUX_UUID,
            value="server-001",
            scanner_type="my-scanner"
        )
    ],
    labels=[
      pb.InstanceLabel(label="production"),
      pb.InstanceLabel(label="critical")
    ],
    key_value_tags=[
      pb.InstanceTagKeyValue(
        key="environment",
        value="production"
      ),
      pb.InstanceTagKeyValue(
        key="team",
        value="platform"
      )
    ]
)
```

**Tag Types:**
- **Key-value tags**: Use `InstanceTag(key_value=InstanceTagKeyValue(key="...", value="..."))`. The `value` field is required and must not be empty.
- **Label tags**: Use `InstanceTag(label=InstanceTagLabel(label="..."))`. These are simple labels without a value.

```python
# Collect the instance
zafran.collect_instance(instance)

# Create a vulnerability
vuln = pb.Vulnerability(
    instance_id="server-001",
    cve="CVE-2023-1234",
    in_runtime=True,
    component=pb.Component(
        type=pb.ComponentType.LIBRARY,
        product="openssl",
        vendor="openssl",
        version="1.1.1"
    ),
    remediation=pb.Remediation(
        suggestion="Update to version 3.0.0 or later",
        source="Vendor Advisory"
    ),
    CVSS=[pb.CVSS(
        version="3.1",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        base_score=9.8
    )],
    description="Critical vulnerability in OpenSSL"
)

# Collect the vulnerability
zafran.collect_vulnerability(vuln)
```

### Adding SBOM Components to Instances

SBOM (Software Bill of Materials) components can be attached to instances to track installed software. This is useful for integrations that collect software inventory (e.g., MDM systems like Jamf):

```python
load("zafran", "zafran")

pb = zafran.proto_file

# Create SBOM components for installed software
sbom_components = []

# Add an application
sbom_components.append(pb.SBOMComponent(
    component=pb.Component(
        type=pb.ComponentType.APPLICATION,
        product="com.google.Chrome",  # Bundle ID or package name
        vendor="Google",
        version="120.0.6099.129",
        display_name="Google Chrome"
    ),
    file_paths=["/Applications/Google Chrome.app"]
))

# Add a library
sbom_components.append(pb.SBOMComponent(
    component=pb.Component(
        type=pb.ComponentType.LIBRARY,
        product="openssl",
        vendor="openssl",
        version="3.0.12"
    ),
    file_paths=["/usr/lib/libssl.so"]
))

# Create instance with SBOM components
instance = pb.InstanceData(
    instance_id="device-001",
    name="workstation-01",
    operating_system="macOS 14.2",
    sbom_components=sbom_components
)

zafran.collect_instance(instance)
```

Note: SBOM components are for tracking software inventory on instances. For reporting vulnerabilities associated with software, use `zafran.collect_vulnerability()` instead.

## Testing Scripts

1. Create your Starlark script following the pattern in `example.star`
2. Test with mock data first
3. Add real API integration
4. Use the logging module to debug issues
5. Validate output JSON structure

### REPL Mode

The tool now supports REPL (Read-Eval-Print Loop) mode for interactive script development and testing:

```bash
# Start REPL mode
./starlark-runner -repl

# Start REPL with pre-loaded script
./starlark-runner -repl -script example.star

# Start REPL with pre-loaded script and parameters
./starlark-runner -repl -script example.star -params "api_url=https://api.example.com"
```

In REPL mode, you have access to:
- All loaded modules from the script
- Special REPL commands:
  - `show_collected()` - Display collected instances and vulnerabilities
  - `clear_collected()` - Clear all collected data
  - `get_collected()` - Get collected data as dict
  - `save_collected(file)` - Save collected data to JSON file
  - `quit()` or Ctrl+D - Exit REPL mode

## Future Enhancements

- Better error messages with line numbers
- Script validation before execution
- Support for loading scripts from URLs or S3
