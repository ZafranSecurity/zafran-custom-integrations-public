load('http', 'http')
load('json', 'json')
load('zafran', 'zafran')
load('log', 'log')

# Default configuration
DEFAULT_PAGE_SIZE = 100
MAX_ITERATIONS = 10000

def main(**kwargs):
    """
    Generic adapter that expects the source to provide correctly formatted JSON.
    
    The source API must provide a single endpoint that returns both instances and vulnerabilities.
    
    Parameters:
        api_url: Full URL of the API endpoint (required)
        api_key: API authentication key (required)
        api_secret: Optional API secret for authentication (optional)
    """
    
    # Get parameters
    api_url = kwargs.get('api_url', '')
    api_key = kwargs.get('api_key', '')
    api_secret = kwargs.get('api_secret', '')
    
    # Validate required parameters
    if not api_url:
        log.error("api_url parameter is required")
        return
    
    if not api_key:
        log.error("api_key parameter is required")
        return
    
    # Normalize API URL
    api_url = api_url.rstrip('/')
    if not api_url.startswith('http://') and not api_url.startswith('https://'):
        api_url = 'https://' + api_url
    
    log.info("Starting generic adapter with API URL: %s" % api_url)
    
    # Get proto types
    pb = zafran.proto_file
    
    # Fetch combined data
    log.info("Fetching data from API...")
    data = fetch_data(api_url, api_key, api_secret)
    
    if not data:
        log.error("Failed to fetch data from API")
        return
    
    instances_data = data.get("instances", [])
    vulnerabilities_data = data.get("vulnerabilities", [])
    
    # Process instances
    if instances_data:
        log.info("Processing %d instances" % len(instances_data))
        instance_count = 0
        for instance_json in instances_data:
            instance = parse_instance(instance_json, pb)
            if instance:
                zafran.collect_instance(instance)
                instance_count += 1
        
        log.info("Successfully processed %d instances" % instance_count)
    else:
        log.warn("No instances found in data")
    
    # Process vulnerabilities
    if vulnerabilities_data:
        log.info("Processing %d vulnerabilities" % len(vulnerabilities_data))
        vuln_count = 0
        for vuln_json in vulnerabilities_data:
            vulnerability = parse_vulnerability(vuln_json, pb)
            if vulnerability:
                zafran.collect_vulnerability(vulnerability)
                vuln_count += 1
        
        log.info("Successfully processed %d vulnerabilities" % vuln_count)
    else:
        log.warn("No vulnerabilities found in data")
    
    # Flush once at the end after collecting both instances and vulnerabilities
    zafran.flush()
    
    log.info("Generic adapter completed successfully")


def fetch_data(api_url, api_key, api_secret):
    """
    Fetch combined data from the source API.
    
    Expected JSON format:
    {
        "instances": [
            {
                "instance_id": "unique-id",
                "name": "display-name",
                "operating_system": "Ubuntu 22.04",
                "ip_addresses": ["192.168.1.1"],
                "mac_addresses": ["00:11:22:33:44:55"],
                "identifiers": [
                    {"type": "AWS_EC2_INSTANCE_ID", "value": "i-1234567890abcdef0"}
                ],
                "properties": {
                    "key1": {"type": "STRING", "value": "value1"},
                    "key2": {"type": "INT", "value": 123}
                },
                "labels": ["production", "web-server"],
                "tags": [
                    {"key": "environment", "value": "prod"}
                ]
            }
        ],
        "vulnerabilities": [
            {
                "instance_id": "unique-id",
                "cve": "CVE-2023-1234",
                "title": "Vulnerability Title",
                "description": "Detailed description",
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
                    "suggestion": "Update to version 1.1.1t",
                    "source": "Scanner Name"
                },
                "cwe_ids": [79, 89],
                "discovered_at": "2024-01-15T10:30:00Z"
            }
        ]
    }
    """
    
    headers = {
        "Authorization": "Bearer %s" % api_key,
        "Content-Type": "application/json"
    }
    
    # Include api_secret in header if provided
    if api_secret:
        headers["X-API-Secret"] = api_secret
    
    log.info("Fetching data from: %s" % api_url)
    response = http.get(url=api_url, headers=headers)
    
    status_code = response.get("status_code", 0)
    
    if status_code == 200:
        body = response.get("body", "")
        data = json.decode(body)
        
        instances_count = len(data.get("instances", []))
        vulnerabilities_count = len(data.get("vulnerabilities", []))
        
        log.info("Successfully fetched data: %d instances, %d vulnerabilities" % (instances_count, vulnerabilities_count))
        return data
    else:
        log.error("Failed to fetch data. Status code: %d, Response: %s" % (status_code, response.get("body", "")))
        return None


def parse_instance(instance_json, pb):
    """
    Parse instance JSON to InstanceData proto.
    
    The source must provide JSON matching the expected format.
    Required fields: instance_id, name
    """
    
    instance_id = instance_json.get("instance_id", "")
    name = instance_json.get("name", "")
    
    if not instance_id:
        log.warn("Skipping instance without instance_id")
        return None
    
    if not name:
        log.warn("Skipping instance without name: %s" % instance_id)
        return None
    
    # Create asset information
    asset_info = pb.AssetInstanceInformation(
        ip_addresses=instance_json.get("ip_addresses", []),
        mac_addresses=instance_json.get("mac_addresses", [])
    )
    
    # Parse identifiers
    identifiers = []
    for identifier_json in instance_json.get("identifiers", []):
        identifier_type_str = identifier_json.get("type", "")
        identifier_value = identifier_json.get("value", "")
        
        if identifier_type_str and identifier_value:
            # Map string to enum
            if hasattr(pb.IdentifierType, identifier_type_str):
                identifier_type = getattr(pb.IdentifierType, identifier_type_str)
                identifiers.append(
                    pb.InstanceIdentifier(
                        key=identifier_type,
                        value=identifier_value
                    )
                )
            else:
                log.warn("Invalid identifier type: %s" % identifier_type_str)
    
    # Parse properties
    properties = {}
    for prop_key, prop_data in instance_json.get("properties", {}).items():
        prop_type_str = prop_data.get("type", "STRING")
        prop_value = prop_data.get("value")
        
        if prop_value != None:
            # Map string to enum
            if hasattr(pb.InstancePropertyType, prop_type_str):
                prop_type = getattr(pb.InstancePropertyType, prop_type_str)
                
                # Convert value to string for proto
                if prop_type == pb.InstancePropertyType.STRING:
                    value_str = str(prop_value)
                elif prop_type == pb.InstancePropertyType.INT:
                    value_str = str(int(prop_value))
                elif prop_type == pb.InstancePropertyType.FLOAT:
                    value_str = str(float(prop_value))
                elif prop_type == pb.InstancePropertyType.BOOL:
                    value_str = str(bool(prop_value))
                elif prop_type == pb.InstancePropertyType.DATETIME:
                    value_str = str(prop_value)
                else:
                    value_str = str(prop_value)
                
                properties[prop_key] = pb.InstancePropertyValue(
                    type=prop_type,
                    value=value_str
                )
            else:
                log.warn("Invalid property type for %s: %s" % (prop_key, prop_type_str))
    
    # Parse labels
    labels = []
    for label_str in instance_json.get("labels", []):
        labels.append(pb.InstanceLabel(label=label_str))
    
    # Parse tags
    tags = []
    for tag_json in instance_json.get("tags", []):
        key = tag_json.get("key", "")
        value = tag_json.get("value", "")
        if key:
            tags.append(pb.InstanceTagKeyValue(key=key, value=value))
    
    # Create instance
    instance = pb.InstanceData(
        instance_id=instance_id,
        name=name,
        operating_system=instance_json.get("operating_system", ""),
        asset_information=asset_info,
        identifiers=identifiers,
        instance_properties=properties,
        labels=labels,
        key_value_tags=tags
    )
    
    return instance


def parse_vulnerability(vuln_json, pb):
    """
    Parse vulnerability JSON to Vulnerability proto.
    
    The source must provide JSON matching the expected format.
    Required fields: instance_id, cve or title
    """
    
    instance_id = vuln_json.get("instance_id", "")
    cve = vuln_json.get("cve", "")
    title = vuln_json.get("title", "")
    
    if not instance_id:
        log.warn("Skipping vulnerability without instance_id")
        return None
    
    if not cve and not title:
        log.warn("Skipping vulnerability without CVE or title for instance: %s" % instance_id)
        return None
    
    # Parse component
    component = None
    fixed_version = ""
    component_json = vuln_json.get("component", {})
    if component_json:
        component_type_str = component_json.get("type", "LIBRARY")
        fixed_version = component_json.get("fixed_version", "")
        
        if hasattr(pb.ComponentType, component_type_str):
            component_type = getattr(pb.ComponentType, component_type_str)
            component = pb.Component(
                type=component_type,
                product=component_json.get("product", ""),
                vendor=component_json.get("vendor", ""),
                version=component_json.get("version", ""),
                display_name=component_json.get("display_name", "")
            )
        else:
            log.warn("Invalid component type: %s" % component_type_str)
    
    # Parse CVSS
    cvss_list = []
    for cvss_json in vuln_json.get("cvss", []):
        cvss = pb.CVSS(
            version=cvss_json.get("version", "3.1"),
            base_score=float(cvss_json.get("base_score", 0.0)),
            vector=cvss_json.get("vector", "")
        )
        cvss_list.append(cvss)
    
    # Parse remediation
    remediation = None
    remediation_json = vuln_json.get("remediation", {})
    if remediation_json:
        # Use fixed_in_version from remediation, or fall back to fixed_version from component
        fixed_in_version = remediation_json.get("fixed_in_version", "")
        if not fixed_in_version and fixed_version:
            fixed_in_version = fixed_version
        
        remediation = pb.Remediation(
            suggestion=remediation_json.get("suggestion", ""),
            source=remediation_json.get("source", ""),
            fixed_in_version=fixed_in_version
        )
    elif fixed_version:
        # If no remediation but we have a fixed_version, create a remediation
        remediation = pb.Remediation(
            suggestion="",
            source="",
            fixed_in_version=fixed_version
        )
    
    # Create vulnerability
    vulnerability = pb.Vulnerability(
        instance_id=instance_id,
        cve=cve,
        scanner_name=title,
        description=vuln_json.get("description", ""),
        severity=vuln_json.get("severity", ""),
        in_runtime=vuln_json.get("in_runtime", False),
        component=component,
        CVSS=cvss_list,
        remediation=remediation,
        cwe_ids=vuln_json.get("cwe_ids", []),
        scanner_id=vuln_json.get("scanner_id", ""),
        external_url=vuln_json.get("external_url", ""),
        references_url=vuln_json.get("references_url", "")
    )
    
    return vulnerability
