load('http', 'http')
load('json', 'json')
load('zafran', 'zafran')
load('log', 'log')
load('base64', 'base64')

def main(**kwargs):
    """
    Main function to fetch data from Fortify on Demand
    
    Parameters:
    - api_url: Fortify base URL (default: https://api.ams.fortify.com)
    - api_key: API key (client ID)
    - api_secret: API secret (client secret)
    """
    # Get parameters
    base_url = kwargs.get('api_url', 'https://api.ams.fortify.com')
    api_key = kwargs.get('api_key', '')
    api_secret = kwargs.get('api_secret', '')
    
    if not api_key or not api_secret:
        log.error('api_key and api_secret parameters are required')
        return
    
    # Ensure base_url has https:// prefix
    if not base_url.startswith("http"):
        base_url = "https://" + base_url
    
    # Get proto types
    pb = zafran.proto_file
    
    # Get access token
    log.info("Authenticating with Fortify on Demand...")
    access_token = get_fortify_access_token(api_key, api_secret, base_url)
    if not access_token:
        log.error("Failed to authenticate with Fortify on Demand")
        return
    
    log.info("Successfully authenticated")
    
    # Get applications
    log.info("Fetching applications...")
    applications = get_applications(access_token, base_url)
    
    if not applications:
        log.warn("No applications found")
        return
    
    log.info("Found %d applications" % len(applications))
    
    # Process each application
    for app in applications:
        process_application(app, access_token, base_url, pb)

def get_fortify_access_token(api_key, api_secret, base_url):
    """
    Get access token from Fortify on Demand using API Key and Secret
    """
    # Try OAuth token endpoint
    token_url = "%s/oauth/token" % base_url
    
    # Form data for token request - include client_id and client_secret in body
    token_data = "grant_type=client_credentials&scope=api-tenant&client_id=%s&client_secret=%s" % (api_key, api_secret)
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    response = http.post(url=token_url, headers=headers, body=token_data)
    
    if response and response.get("status_code") == 200:
        token_response = json.decode(response.get("body", ""))
        return token_response.get("access_token", "")
    else:
        log.error("OAuth token exchange failed with status: %d" % response.get("status_code", 0))
        if response.get("body"):
            log.error("Response: %s" % response.get("body"))
        return None

def make_fortify_request(access_token, base_url, endpoint, params=None):
    """
    Make a request to Fortify on Demand API with proper error handling
    """
    url = "%s/api/v3/%s" % (base_url, endpoint)
    
    # Add query parameters manually
    if params:
        param_parts = []
        for key, value in params.items():
            param_parts.append("%s=%s" % (key, value))
        query_string = "&".join(param_parts)
        url = "%s?%s" % (url, query_string)
    
    headers = {
        "Authorization": "Bearer %s" % access_token,
        "Accept": "application/json"
    }
    
    response = http.get(url=url, headers=headers)
    
    if response and response.get("status_code") == 200:
        return json.decode(response.get("body", ""))
    elif response and response.get("status_code") == 401:
        log.error("Authentication failed - check API key and secret")
    elif response and response.get("status_code") == 403:
        log.error("Access denied - check API permissions and scopes")
    elif response and response.get("status_code") == 429:
        log.error("Rate limit exceeded - please retry later")
    else:
        if response:
            log.error("API request failed with status: %d" % response.get("status_code", 0))
    return {}

def get_applications(access_token, base_url):
    """
    Get applications from Fortify on Demand with pagination
    """
    all_applications = []
    offset = 0
    limit = 50  # API maximum
    
    while True:
        params = {
            "limit": str(limit),
            "offset": str(offset),
            "orderBy": "applicationName",
            "orderByDirection": "ASC"
        }
        response = make_fortify_request(access_token, base_url, "applications", params)
        
        items = response.get("items", [])
        if not items:
            break
            
        all_applications.extend(items)
        offset += limit
        
        # Check if we've retrieved all items
        if len(items) < limit:
            break
    
    return all_applications

def get_releases(access_token, base_url, application_id):
    """
    Get releases for a specific application with pagination
    """
    all_releases = []
    offset = 0
    limit = 50  # API maximum
    
    while True:
        endpoint = "applications/%s/releases" % application_id
        params = {
            "limit": str(limit),
            "offset": str(offset),
            "orderBy": "releaseName"
        }
        response = make_fortify_request(access_token, base_url, endpoint, params)
        
        items = response.get("items", [])
        if not items:
            break
            
        all_releases.extend(items)
        offset += limit
        
        # Check if we've retrieved all items
        if len(items) < limit:
            break
    
    return all_releases

def get_vulnerabilities(access_token, base_url, release_id):
    """
    Get vulnerabilities for a specific release with pagination
    """
    all_vulnerabilities = []
    offset = 0
    limit = 50  # API maximum
    
    while True:
        endpoint = "releases/%s/vulnerabilities" % release_id
        params = {
            "limit": str(limit),
            "offset": str(offset),
            "filters": "severityString:Critical|High|Medium|Low"
        }
        response = make_fortify_request(access_token, base_url, endpoint, params)
        
        items = response.get("items", [])
        if not items:
            break
            
        all_vulnerabilities.extend(items)
        offset += limit
        
        # Check if we've retrieved all items
        if len(items) < limit:
            break
    
    return all_vulnerabilities

def process_application(app, access_token, base_url, pb):
    """Process a Fortify application and create an instance"""
    
    app_name = app.get("applicationName", "unknown-app")
    app_id = str(app.get("applicationId", ""))
    
    if not app_id:
        log.warn("Application ID not found, skipping")
        return
    
    log.info("Processing application: %s" % app_name)
    
    # Build identifiers
    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.IDENTIFIER_TYPE_UNSPECIFIED,
            value=app_id,
            scanner_type="fortify"
        )
    ]
    
    # Build properties
    properties = {}
    
    if app.get("applicationType"):
        properties["app_type"] = pb.InstancePropertyValue(
            value=app.get("applicationType"),
            type=pb.InstancePropertyType.STRING
        )
    
    if app.get("businessCriticalityType"):
        properties["business_criticality"] = pb.InstancePropertyValue(
            value=app.get("businessCriticalityType"),
            type=pb.InstancePropertyType.STRING
        )
    
    if app.get("createdDate"):
        properties["created_date"] = pb.InstancePropertyValue(
            value=app.get("createdDate"),
            type=pb.InstancePropertyType.STRING
        )
    
    if app.get("updatedDate"):
        properties["updated_date"] = pb.InstancePropertyValue(
            value=app.get("updatedDate"),
            type=pb.InstancePropertyType.STRING
        )
    
    # Get releases for this application
    releases = get_releases(access_token, base_url, app_id)
    
    properties["release_count"] = pb.InstancePropertyValue(
        value=str(len(releases)),
        type=pb.InstancePropertyType.STRING
    )
    
    # Create instance
    instance = pb.InstanceData(
        instance_id=app_id,
        name=app_name,
        operating_system="",  # Not applicable for applications
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[],
            mac_addresses=[]
        ),
        identifiers=identifiers,
        instance_properties=properties
    )
    
    zafran.collect_instance(instance)
    
    # Process vulnerabilities for each release
    vuln_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    total_vulns = 0
    
    for release in releases:
        release_id = str(release.get("releaseId", ""))
        if not release_id:
            continue
            
        log.info("Processing release: %s" % release.get("releaseName", ""))
        vulnerabilities = get_vulnerabilities(access_token, base_url, release_id)
        
        for vuln_data in vulnerabilities:
            process_vulnerability(vuln_data, app_id, pb)
            
            # Count vulnerabilities by severity
            severity = vuln_data.get("severityString", "")
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            total_vulns += 1
    
    log.info("Application %s: %d total vulnerabilities (Critical: %d, High: %d, Medium: %d, Low: %d)" % 
             (app_name, total_vulns, vuln_counts["Critical"], vuln_counts["High"], 
              vuln_counts["Medium"], vuln_counts["Low"]))

def process_vulnerability(vuln_data, app_id, pb):
    """Convert Fortify vulnerability to Zafran vulnerability"""
    
    vuln_id = str(vuln_data.get("vulnId", ""))
    if not vuln_id:
        return
    
    # Map Fortify severity to score
    score_map = {
        "Critical": 10.0,
        "High": 7.0,
        "Medium": 5.0,
        "Low": 2.0
    }
    
    severity = vuln_data.get("severityString", "Medium")
    severity_score = score_map.get(severity, 5.0)
    
    # Get CVSS score if available
    cvss_score = vuln_data.get("cvssScore", 0)
    if cvss_score:
        severity_score = float(cvss_score)
    
    # Create CVSS list
    cvss_list = [
        pb.CVSS(
            version="2.0" if cvss_score else "3.1",
            base_score=severity_score
        )
    ]
    
    # Get CWE if available
    cwe_ids = []
    cwe = vuln_data.get("cwe")
    if cwe:
        # Convert to int if it's a string number
        if type(cwe) == "string" and cwe.isdigit():
            cwe_ids.append(int(cwe))
        elif type(cwe) == "int":
            cwe_ids.append(cwe)
    
    # Create unique vulnerability ID
    cve = "FORTIFY-%s" % vuln_id
    
    # Create vulnerability
    vuln = pb.Vulnerability(
        instance_id=app_id,
        cve=cve,
        description=vuln_data.get("primaryLocationFull", vuln_data.get("category", "Application security vulnerability")),
        in_runtime=False,  # Static analysis findings
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=vuln_data.get("category", ""),
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        cwe_ids=cwe_ids,
        remediation=pb.Remediation(
            suggestion=vuln_data.get("details", {}).get("recommendation", "See Fortify on Demand for remediation details"),
            source="Fortify on Demand"
        )
    )
    
    zafran.collect_vulnerability(vuln)