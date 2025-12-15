load('http', http_post='post', http_get='get', 'url_encode')
load('json', 'json')
load('net', 'ip_address')
load('time', 'time')
load('zafran', 'zafran')
load('log', 'log')

# Constants
MAX_REQUESTS = 100  # Refresh token after this many requests
DEFAULT_DAYS_AGO = 60  # Number of days to look back for inventory
INCLUDE_COMPUTERS = True  # Whether to include computers in the scan
INCLUDE_MOBILE = True  # Whether to include mobile devices in the scan

def sanitize_string(s):
    """Sanitize string for use as property key."""
    if s:
        return s.replace(" ", "_").replace(".", "").replace("+", "").replace("(", "").replace(")", "").lower()
    else:
        return None

def get_bearer_token(client_id, client_secret, jamf_url):
    """Obtain OAuth2 bearer token."""
    headers = {'Content-Type': 'application/x-www-form-urlencoded', 'accept': 'application/json'}
    # Manually construct URL-encoded string
    encoded_params = "client_id=%s&client_secret=%s&grant_type=client_credentials" % (
        url_encode(client_id), 
        url_encode(client_secret)
    )
    url = "%s/api/oauth/token" % jamf_url
    resp = http_post(url, headers=headers, body=encoded_params)
    
    if resp.get("status_code") != 200:
        log.error("Failed to retrieve bearer token. Status code: %d" % resp.get("status_code", 0))
        return None, 0
    
    body_json = json.decode(resp.get("body", ""))
    if not body_json:
        log.error("Invalid JSON response for bearer token")
        return None, 0
    
    token = body_json['access_token']
    return token, 0

def get_valid_token(token, request_count, client_id, client_secret, jamf_url):
    """Check if token needs refresh and get valid token."""
    if token and request_count < MAX_REQUESTS:
        return token, request_count + 1
    else:
        log.info("Fetching new token after %d requests" % request_count)
        return get_bearer_token(client_id, client_secret, jamf_url)

def build_url_with_params(url, params):
    """Build URL with query parameters."""
    if not params:
        return url
    
    param_parts = []
    for key, value in params.items():
        param_parts.append("%s=%s" % (url_encode(str(key)), url_encode(str(value))))
    
    query_string = "&".join(param_parts)
    
    if "?" in url:
        return url + "&" + query_string
    else:
        return url + "?" + query_string

def http_request(method, url, headers=None, params=None, body=None, token=None, request_count=None, client_id=None, client_secret=None, jamf_url=None):
    """Make HTTP request with automatic token refresh."""
    token, request_count = get_valid_token(token, request_count, client_id, client_secret, jamf_url)
    if not token:
        return None, token, request_count
    
    headers = headers or {}
    headers["Authorization"] = "Bearer %s" % token
    
    # Build URL with params for GET requests
    if method == "GET" and params:
        url = build_url_with_params(url, params)
    
    if method == "GET":
        response = http_get(url=url, headers=headers)
    elif method == "POST":
        response = http_post(url=url, headers=headers, body=body)
    else:
        log.error("Unsupported HTTP method: %s" % method)
        return None, token, request_count
    
    if response.get("status_code") == 403:
        log.info("403 Forbidden. Fetching new token and retrying...")
        token, request_count = get_bearer_token(client_id, client_secret, jamf_url)
        if not token:
            return None, token, request_count
        headers["Authorization"] = "Bearer %s" % token
        if method == "GET":
            response = http_get(url=url, headers=headers)
        elif method == "POST":
            response = http_post(url=url, headers=headers, body=body)
    
    return response, token, request_count

def is_private_ip(ip):
    """Check if IP is private."""
    return (
        ip.startswith("10.") or
        ip.startswith("192.168.") or
        (ip.startswith("172.") and int(ip.split(".")[1]) >= 16 and int(ip.split(".")[1]) <= 31)
    )

def get_jamf_inventory(token, request_count, client_id, client_secret, jamf_url, start_date):
    """Fetch computer inventory from Jamf."""
    hasNextPage = True
    page = 0
    page_size = 100
    endpoints = []
    url = jamf_url + '/api/v1/computers-inventory'
    
    while hasNextPage:
        params = {"page": str(page), "page-size": str(page_size), "filter": 'general.lastContactTime=ge="%sT00:00:00Z"' % start_date}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count, 
                                                 client_id=client_id, client_secret=client_secret, jamf_url=jamf_url)
        if not resp or resp.get("status_code") != 200:
            log.error("Failed to retrieve inventory. Status code: %d" % (resp.get("status_code") if resp else 0))
            return endpoints, token, request_count
        
        inventory = json.decode(resp.get("body"))
        if not inventory:
            log.error("Invalid or empty JSON response for inventory")
            return endpoints, token, request_count
        
        results = inventory.get('results', [])
        if not results:
            hasNextPage = False
            continue
        
        endpoints.extend(results)
        page += 1
    
    return endpoints, token, request_count

def get_jamf_details(token, request_count, client_id, client_secret, jamf_url, inventory):
    """Fetch detailed information for each computer."""
    endpoints_final = []
    for item in inventory:
        uid = item.get('id')
        if not uid:
            log.warn("ID not found in inventory item")
            continue
        
        url = "%s/api/v1/computers-inventory-detail/%s" % (jamf_url, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count, 
                                                 client_id=client_id, client_secret=client_secret, jamf_url=jamf_url)
        if not resp or resp.get("status_code") != 200:
            log.error("Failed to retrieve details for ID: %s, Status code: %d" % (uid, resp.get("status_code") if resp else 0))
            continue
        
        extra = json.decode(resp.get("body"))
        if not extra:
            log.error("Invalid JSON for detail")
            continue
        
        item.update(extra)
        endpoints_final.append(item)
    
    return endpoints_final, token, request_count

def get_mobile_device_inventory(token, request_count, client_id, client_secret, jamf_url, start_date):
    """Fetch mobile device inventory from Jamf."""
    hasNextPage = True
    page = 0
    page_size = 100
    mobile_devices = []
    url = jamf_url + "/api/v2/mobile-devices/detail"
    
    while hasNextPage:
        params = {"page": str(page), "page-size": str(page_size), "section": "GENERAL", 
                 "filter": 'lastInventoryUpdateDate=ge="%sT00:00:00Z"' % start_date}
        resp, token, request_count = http_request("GET", url, params=params, token=token, request_count=request_count,
                                                 client_id=client_id, client_secret=client_secret, jamf_url=jamf_url)
        if not resp or resp.get("status_code") != 200:
            log.error("Failed to retrieve mobile device inventory. Status code: %d" % (resp.get("status_code") if resp else 0))
            return mobile_devices, token, request_count
        
        inventory = json.decode(resp.get("body"))
        if not inventory:
            log.error("Invalid or empty JSON response for mobile inventory")
            return mobile_devices, token, request_count
        
        results = inventory.get('results', [])
        if not results:
            hasNextPage = False
            continue
        
        mobile_devices.extend(results)
        page += 1
    
    return mobile_devices, token, request_count

def get_mobile_device_details(token, request_count, client_id, client_secret, jamf_url, inventory):
    """Fetch detailed information for each mobile device."""
    mobile_devices_final = []
    for item in inventory:
        uid = item.get('mobileDeviceId')
        if not uid:
            log.warn("ID not found in mobile device item")
            continue
        
        url = "%s/api/v2/mobile-devices/%s/detail" % (jamf_url, uid)
        resp, token, request_count = http_request("GET", url, token=token, request_count=request_count,
                                                 client_id=client_id, client_secret=client_secret, jamf_url=jamf_url)
        if not resp or resp.get("status_code") != 200:
            log.error("Failed to retrieve details for mobile device ID: %s, Status code: %d" % (uid, resp.get("status_code") if resp else 0))
            continue
        
        extra = json.decode(resp.get("body"))
        if not extra:
            log.error("Invalid JSON for mobile detail")
            continue
        
        item.update(extra)
        mobile_devices_final.append(item)
    
    return mobile_devices_final, token, request_count

def process_computer_asset(item):
    """Process a computer asset and create instance."""
    pb = zafran.proto_file
    
    asset_id = item.get("udid")
    if not asset_id:
        log.warn("Asset ID not found")
        return
    
    general = item.get("general", {})
    hardware = item.get("hardware", {})
    operating_system = item.get("operatingSystem", {})
    
    # Get IPs (only private IPs)
    ip_addresses = []
    for key in ["lastIpAddress", "ipAddress", "lastReportedIp"]:
        ip = general.get(key)
        if ip and is_private_ip(ip):
            ip_addresses.append(ip)
    
    # Get MAC addresses
    mac_addresses = []
    for mac in [hardware.get("macAddress"), hardware.get("altMacAddress")]:
        if mac:
            mac_addresses.append(mac)
    
    # Build identifiers list
    identifiers = []
    if hardware.get("serialNumber"):
        identifiers.append(pb.InstanceIdentifier(
            key=pb.IdentifierType.SERIAL_NUMBER,
            value=hardware.get("serialNumber")
        ))
    
    # Add properties
    properties = {}
    
    # Basic properties
    if operating_system.get("version"):
        properties["os_version"] = pb.InstancePropertyValue(
            value=operating_system.get("version"),
            type=pb.InstancePropertyType.STRING
        )
    if hardware.get("model"):
        properties["model"] = pb.InstancePropertyValue(
            value=hardware.get("model"),
            type=pb.InstancePropertyType.STRING
        )
    if hardware.get("make"):
        properties["manufacturer"] = pb.InstancePropertyValue(
            value=hardware.get("make"),
            type=pb.InstancePropertyType.STRING
        )
    if hardware.get("serialNumber"):
        properties["serial_number"] = pb.InstancePropertyValue(
            value=hardware.get("serialNumber"),
            type=pb.InstancePropertyType.STRING
        )
    
    # Security information
    security = item.get("security", {})
    if security.get("firewall"):
        properties["firewall_enabled"] = pb.InstancePropertyValue(
            bool_value=security.get("firewall"),
            type=pb.InstancePropertyType.BOOLEAN
        )
    if security.get("gatekeeperStatus"):
        properties["gatekeeper_status"] = pb.InstancePropertyValue(
            value=security.get("gatekeeperStatus"),
            type=pb.InstancePropertyType.STRING
        )
    
    # Disk encryption
    disk = item.get("diskEncryption", {})
    if disk.get("bootPartitionEncryptionDetails", {}).get("encryptionStatus"):
        properties["disk_encryption_status"] = pb.InstancePropertyValue(
            value=disk["bootPartitionEncryptionDetails"]["encryptionStatus"],
            type=pb.InstancePropertyType.STRING
        )
    
    # User information
    user = item.get("userAndLocation", {})
    if user.get("username"):
        properties["assigned_user"] = pb.InstancePropertyValue(
            value=user.get("username"),
            type=pb.InstancePropertyType.STRING
        )
    if user.get("realName"):
        properties["user_real_name"] = pb.InstancePropertyValue(
            value=user.get("realName"),
            type=pb.InstancePropertyType.STRING
        )
    
    # Extension attributes
    ext_attrs = item.get("extensionAttributes", [])
    for ext in ext_attrs:
        ext_name = sanitize_string(ext.get("name"))
        ext_values = ext.get("values") or ext.get("value")
        if ext_name and ext_values:
            if type(ext_values) == "list":
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=",".join(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
            else:
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=str(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
    
    # User extension attributes
    user_ext_attrs = user.get("extensionAttributes", [])
    for ext in user_ext_attrs:
        ext_name = sanitize_string(ext.get("name"))
        ext_values = ext.get("values") or ext.get("value")
        if ext_name and ext_values:
            if type(ext_values) == "list":
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=",".join(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
            else:
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=str(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
    
    # Create instance with all fields
    instance = pb.InstanceData(
        instance_id=asset_id,
        name=general.get("name", ""),
        operating_system=operating_system.get("name", ""),
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=ip_addresses,
            mac_addresses=mac_addresses
        ),
        identifiers=identifiers,
        instance_properties=properties
    )
    
    zafran.collect_instance(instance)

def process_mobile_asset(item):
    """Process a mobile device asset and create instance."""
    pb = zafran.proto_file
    
    asset_id = item.get("udid") or item.get("mobileDeviceId")
    if not asset_id:
        log.warn("Mobile asset ID not found")
        return
    
    general = item.get("general", {})
    hardware = item.get("hardware", {})
    
    # Get IPs (only private IPs)
    ip_addresses = []
    for key in ["lastIpAddress", "ipAddress", "lastReportedIp"]:
        ip = general.get(key)
        if ip and is_private_ip(ip):
            ip_addresses.append(ip)
    
    # Get MAC addresses
    mac_addresses = []
    mac = hardware.get("macAddress") or item.get("wifiMacAddress")
    if mac:
        mac_addresses.append(mac)
    
    # Build identifiers list
    identifiers = []
   
    # Add properties
    properties = {}
    
    # Basic properties
    if general.get("osVersion"):
        properties["os_version"] = pb.InstancePropertyValue(
            value=general.get("osVersion"),
            type=pb.InstancePropertyType.STRING
        )
    if item.get("model"):
        properties["model"] = pb.InstancePropertyValue(
            value=item.get("model"),
            type=pb.InstancePropertyType.STRING
        )
    properties["manufacturer"] = pb.InstancePropertyValue(
        value="Apple",
        type=pb.InstancePropertyType.STRING
    )
    
    # Extension attributes
    ext_attrs = item.get("extensionAttributes", [])
    for ext in ext_attrs:
        ext_name = sanitize_string(ext.get("name"))
        ext_values = ext.get("values") or ext.get("value")
        if ext_name and ext_values:
            if type(ext_values) == "list":
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=",".join(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
            else:
                properties["ext_attr_%s" % ext_name] = pb.InstancePropertyValue(
                    value=str(ext_values),
                    type=pb.InstancePropertyType.STRING
                )
    
    # Create instance with all fields
    instance = pb.InstanceData(
        instance_id=str(asset_id),
        name=item.get("name", "").replace(" ", "-"),
        operating_system="iOS",
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=ip_addresses,
            mac_addresses=mac_addresses
        ),
        identifiers=identifiers,
        instance_properties=properties
    )
    
    zafran.collect_instance(instance)

def main(**kwargs):
    """Main entry point for the integration.
    
    Standard parameters:
    - api_url: The Jamf URL (e.g., "https://jamf.example.com")
    - api_key: The OAuth2 client ID
    - api_secret: The OAuth2 client secret
    
    Note: days_ago, include_computers, and include_mobile are now constants defined at the top of the file
    """
    # Get standard parameters
    jamf_url = kwargs.get('api_url', '').rstrip('/')  # Jamf URL
    client_id = kwargs.get('api_key', '')  # OAuth2 client ID
    client_secret = kwargs.get('api_secret', '')  # OAuth2 client secret
    
    # Use constants instead of parameters
    days_ago = DEFAULT_DAYS_AGO
    include_computers = INCLUDE_COMPUTERS
    include_mobile = INCLUDE_MOBILE
    
    if not jamf_url:
        log.error('api_url (Jamf URL) parameter is required')
        return
    
    if not client_id or not client_secret:
        log.error('api_key (client ID) and api_secret (client secret) parameters are required')
        return
    
    # Calculate start date
    duration_str = "-%dh" % (days_ago * 24)
    ago_duration = time.parse_duration(duration_str)
    start_time = time.now() + ago_duration
    start_date = str(start_time)[:10]  # "YYYY-MM-DD"
    
    log.info("Authenticating with Jamf...")
    token, request_count = get_bearer_token(client_id, client_secret, jamf_url)
    if not token:
        log.error("Failed to get bearer token")
        return
    
    # Process computer inventory
    if include_computers:
        log.info("Fetching computer inventory since %s..." % start_date)
        inventory, token, request_count = get_jamf_inventory(token, request_count, client_id, client_secret, jamf_url, start_date)
        
        if inventory:
            log.info("Found %d computers, fetching details..." % len(inventory))
            details, token, request_count = get_jamf_details(token, request_count, client_id, client_secret, jamf_url, inventory)
            
            log.info("Processing %d computers..." % len(details))
            for item in details:
                process_computer_asset(item)
        else:
            log.warn("No computer inventory data found")
    
    # Process mobile device inventory
    if include_mobile:
        log.info("Fetching mobile device inventory since %s..." % start_date)
        mobile_inventory, token, request_count = get_mobile_device_inventory(token, request_count, client_id, client_secret, jamf_url, start_date)
        
        if mobile_inventory:
            log.info("Found %d mobile devices, fetching details..." % len(mobile_inventory))
            mobile_details, token, request_count = get_mobile_device_details(token, request_count, client_id, client_secret, jamf_url, mobile_inventory)
            
            log.info("Processing %d mobile devices..." % len(mobile_details))
            for item in mobile_details:
                process_mobile_asset(item)
        else:
            log.warn("No mobile device inventory data found")
