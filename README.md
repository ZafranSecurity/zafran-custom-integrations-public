# Starlark Runner

A command-line tool for executing and testing Starlark integration scripts.

## Features

- Execute Starlark scripts with parameter passing
- JSON output of collected instances and vulnerabilities
- Full module support (http, json, crypto, etc.)
- Script validation and error reporting

## Platform Compatibility

Two binaries are provided:
- `starlark-runner` - For Linux systems
- `starlark-runner-mac` - For macOS systems

Use the appropriate binary for your operating system. All examples below use `starlark-runner`, but macOS users should substitute with `starlark-runner-mac`.

## Usage

### Running a Script

Execute a script and output results to stdout:
```bash
# Linux
./starlark-runner -script example.star

# macOS
./starlark-runner-mac -script example.star
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

- `-script` - Path to the Starlark script file (required for normal execution)
- `-output` - Optional output file for JSON results (default: stdout)
- `-params` - Comma-separated key=value parameters to pass to the script
- `-repl` - Start interactive REPL mode (see [REPL Mode](#repl-mode))
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

The following modules are available:

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
- `zafran.collect_instance(instance)` - Collect an instance (max 10,000 per execution)
- `zafran.collect_vulnerability(vuln)` - Collect a vulnerability (max 1,000,000 per execution)

#### Proto Types Available via zafran.proto_file:

**Instance Types:**
- `InstanceData` - Main instance data structure
- `AssetInstanceInformation` - IP and MAC address information
- `InstanceIdentifier` - Instance identifier with type
- `InstancePropertyValue` - Property value with type
- `InstanceTag` - Tag with key/value or label
- `InetEvidence` - Internet-facing evidence

**Vulnerability Types:**
- `Vulnerability` - Main vulnerability structure
- `Component` - Software component information
- `CVSS` - CVSS score information
- `Remediation` - Remediation suggestion

**Enums:**
- `IdentifierType` - AWS_EC2_INSTANCE_ID, AZURE_VM_ID, etc.
- `InstancePropertyType` - STRING, INT, FLOAT, BOOL, DATETIME
- `ComponentType` - APPLICATION, LIBRARY, OPERATING_SYSTEM, etc.

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
      "tags": []
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
    tags=[
        # Key-value tag
        pb.InstanceTag(key_value=pb.InstanceTagKeyValue(
            key="environment",
            value="production"
        )),
        # Label tag
        pb.InstanceTag(label=pb.InstanceTagLabel(
            label="critical"
        ))
    ]
)

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

## Testing Scripts

1. Create your Starlark script following the pattern in `example.star`
2. Test with mock data first
3. Add real API integration
4. Use the logging module to debug issues
5. Validate output JSON structure

### REPL Mode

The tool supports REPL (Read-Eval-Print Loop) mode for interactive script development and testing:

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

