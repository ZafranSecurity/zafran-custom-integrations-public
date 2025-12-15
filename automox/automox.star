load('http', http_get='get')
load('json', 'json')
load('net', 'ip_address')
load('uuid', 'new_uuid')
load('zafran', 'zafran')
load('log', 'log')

# Constants
DEFAULT_API_BASE_URL = "https://console.automox.com"

def get_automox_devices(headers, base_url):
    """Retrieve all devices from Automox using pagination."""
    query = {
        "limit": "500",
        "page": "0"
    }
    
    devices = []
    
    while True:
        # Build URL with query params
        url = base_url + "/api/servers?limit=%s&page=%s" % (query["limit"], query["page"])
        response = http_get(url, headers=headers)
        
        if response.get("status_code") != 200:
            log.error("Failed to fetch devices from Automox. Status: %d" % response.get("status_code"))
            return devices
        
        batch = json.decode(response.get("body"))
        
        if not batch:
            break  # Stop fetching if no more results are returned
        
        devices.extend(batch)
        query["page"] = str(int(query["page"]) + 1)
    
    log.info("Loaded %d devices" % len(devices))
    return devices

def build_instances(devices, headers, base_url, org_id=None):
    """Convert Automox device data into Zafran instance format."""
    pb = zafran.proto_file
    
    for device in devices:
        device_id = str(device.get("id", new_uuid()))
        
        # Collect IP addresses
        ip_addresses = []
        for ip in device.get("ip_addrs", []):
            if ip:
                ip_addresses.append(ip)
        for ip in device.get("ip_addrs_private", []):
            if ip:
                ip_addresses.append(ip)
        
        # Collect MAC addresses
        mac_addresses = []
        if device.get("detail", {}).get("NICS"):
            for nic in device["detail"]["NICS"]:
                mac = nic.get("MAC", "")
                if mac:
                    mac_addresses.append(mac)
        
        # Create instance with new proto structure
        instance = pb.InstanceData(
            instance_id=device_id,
            name=device.get("name", ""),
            operating_system=device.get("os_name", ""),
            asset_information=pb.AssetInstanceInformation(
                ip_addresses=ip_addresses,
                mac_addresses=mac_addresses
            )
        )
        
        # Add properties
        properties = {}
        
        if device.get("os_version"):
            properties["os_version"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("os_version")
            )
        
        if device.get("os_family"):
            properties["os_family"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("os_family")
            )
        
        if device.get("agent_version"):
            properties["agent_version"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("agent_version")
            )
        
        if "compliant" in device:
            properties["compliant"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.BOOL,
                value=str(device.get("compliant"))
            )
        
        if device.get("last_logged_in_user"):
            properties["last_logged_in_user"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("last_logged_in_user")
            )
        
        if device.get("serial_number"):
            properties["serial_number"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("serial_number")
            )
        
        if device.get("status", {}).get("agent_status"):
            properties["agent_status"] = pb.InstancePropertyValue(
                type=pb.InstancePropertyType.STRING,
                value=device.get("status", {}).get("agent_status")
            )
        
        if properties:
            instance.instance_properties = properties
        
        # Add identifiers
        identifiers = []
        if device.get("serial_number"):
            identifiers.append(pb.InstanceIdentifier(
                key=pb.IdentifierType.SERIAL_NUMBER,
                value=device.get("serial_number"),
                scanner_type="automox"
            ))
        
        if identifiers:
            instance.identifiers = identifiers
        
        # Collect the instance using new zafran method
        zafran.collect_instance(instance)
        
        # Process software and vulnerabilities if org_id is provided
        if org_id:
            process_software_vulnerabilities(org_id, device_id, headers, base_url)

def process_software_vulnerabilities(org_id, device_id, headers, base_url):
    """Fetch software inventory and create vulnerabilities."""
    pb = zafran.proto_file
    
    automox_software_url = "%s/api/servers/%s/packages?o=%s" % (base_url, device_id, org_id)
    
    software_response = http_get(automox_software_url, headers=headers)
    
    if software_response.get("status_code") != 200:
        log.warn("Failed to fetch software inventory for device %s: %d" % (device_id, software_response.get("status_code")))
        return
    
    software_inventory = json.decode(software_response.get("body"))
    
    for soft in software_inventory:
        # Process CVEs if present
        cves = soft.get("cves", [])
        if type(cves) == "string":
            # Parse CSV string of CVEs
            cve_list = [cve.strip() for cve in cves.split(",") if cve.strip()]
        elif type(cves) == "list":
            cve_list = cves
        else:
            cve_list = []
        
        for cve in cve_list:
            if not cve:
                continue
            
            # Create CVSS objects list
            cvss_list = []
            if soft.get("cve_score"):
                cvss_list.append(pb.CVSS(
                    version="3.1",
                    base_score=float(soft.get("cve_score", 0))
                ))
            
            # Create vulnerability with new proto structure
            vuln = pb.Vulnerability(
                instance_id=device_id,
                cve=cve,
                description="Vulnerability in %s %s" % (soft.get("display_name", "Unknown"), soft.get("version", "")),
                in_runtime=True,
                component=pb.Component(
                    type=pb.ComponentType.LIBRARY,
                    product=soft.get("display_name", soft.get("name", "Unknown")),
                    vendor=soft.get("display_name", soft.get("name", "Unknown")).split()[0] if soft.get("display_name") else "Unknown",
                    version=soft.get("version", "")
                ),
                CVSS=cvss_list
            )
            
            # Add remediation info if available
            if soft.get("version"):
                vuln.remediation = pb.Remediation(
                    suggestion="Update %s to latest version" % soft.get("display_name", "package"),
                    source="Automox"
                )
            
            zafran.collect_vulnerability(vuln)

def main(**kwargs):
    """Main entry point for the integration.
    
    Standard parameters:
    - api_secret: The API token for Automox authentication
    - api_key: The organization ID (optional) for fetching software vulnerabilities
    - api_url: Custom Automox API base URL (optional, defaults to https://console.automox.com)
    """
    # Get standard parameters
    api_token = kwargs.get('api_secret', '')  # API token
    org_id = kwargs.get('api_key', '')  # Use api_key parameter for org_id
    base_url = kwargs.get('api_url', DEFAULT_API_BASE_URL)  # Custom API URL or default
    
    if not api_token:
        log.error('api_secret (API token) parameter is required')
        return
    
    headers = {
        "Authorization": "Bearer " + api_token,
        "Content-Type": "application/json"
    }
    
    # Ensure base_url has proper format (no trailing slash)
    if base_url.endswith("/"):
        base_url = base_url[:-1]
    
    # Ensure https:// prefix
    if not base_url.startswith("http://") and not base_url.startswith("https://"):
        base_url = "https://" + base_url
    
    log.info("Fetching devices from Automox at %s..." % base_url)
    devices = get_automox_devices(headers, base_url)
    
    if not devices:
        log.warn("No devices retrieved from Automox")
        return
    
    log.info("Processing %d devices..." % len(devices))
    build_instances(devices, headers, base_url, org_id)