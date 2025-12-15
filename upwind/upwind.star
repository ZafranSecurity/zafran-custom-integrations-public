# Upwind Starlark integration script
# Fetches vulnerability findings from Upwind Security API
# Collects vulnerabilities and creates instances for affected cloud resources

load('http', 'http')
load('json', 'json')
load('zafran', 'zafran')
load('log', 'log')
load('base64', 'base64')

# Upwind API configuration
DEFAULT_BASE_URL = "https://api.upwind.io"
AUTH_URL = "https://auth.upwind.io/oauth/token"
DEFAULT_CHUNK_SIZE = 5000
MAX_ITERATIONS = 100000

def main(**kwargs):
    """
    Main function to fetch data from Upwind Security

    Parameters:
    - api_url: Upwind API base URL (default: https://api.upwind.io)
    - api_key: Client ID
    - api_secret: Client Secret
    - severity: Filter by severity (CRITICAL, HIGH, MEDIUM, LOW) - optional
    - in_use: Filter for packages in use only (true/false) - optional
    """
    # Get parameters
    base_url = kwargs.get('api_url', DEFAULT_BASE_URL)
    client_id = kwargs.get('api_key', '')
    client_secret = kwargs.get('api_secret', '')
    severity_filter = kwargs.get('severity', '')
    in_use_filter = kwargs.get('in_use', '')

    if not client_id or not client_secret:
        log.error('api_key (client_id) and api_secret (client_secret) parameters are required')
        return

    # Ensure base_url has https:// prefix
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    # Remove trailing slash
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    # Get proto types
    pb = zafran.proto_file

    # Get access token and organization ID
    log.info("Authenticating with Upwind...")
    auth_result = get_oauth_token(client_id, client_secret, base_url)
    if not auth_result:
        log.error("Failed to authenticate with Upwind")
        return

    access_token = auth_result.get("access_token", "")
    org_id = auth_result.get("org_id", "")

    if not access_token:
        log.error("No access token received")
        return

    if not org_id:
        log.error("Could not determine organization ID from token")
        return

    log.info("Successfully authenticated. Organization ID: %s" % org_id)

    # Track seen resources for instance creation
    seen_resources = {}

    # Build filters
    filters = {}
    if severity_filter:
        filters["severity"] = severity_filter
        log.info("Filtering by severity: %s" % severity_filter)
    if in_use_filter:
        filters["in-use"] = in_use_filter
        log.info("Filtering by in-use: %s" % in_use_filter)

    # Fetch and process vulnerability findings
    log.info("Fetching vulnerability findings...")
    process_vulnerability_findings(access_token, base_url, org_id, pb, seen_resources, filters)

    log.info("Created %d unique resource instances from vulnerability findings" % len(seen_resources))
    log.info("Upwind integration completed successfully")


def get_oauth_token(client_id, client_secret, base_url):
    """
    Get OAuth access token from Upwind using client credentials flow.
    Also extracts organization ID from the JWT token.
    """
    # Determine the audience based on the base_url
    audience = base_url
    if not audience.startswith("https://"):
        audience = "https://" + audience

    # Form data for token request
    token_data = "grant_type=client_credentials&client_id=%s&client_secret=%s&audience=%s" % (
        client_id, client_secret, audience
    )

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = http.post(url=AUTH_URL, headers=headers, body=token_data)

    if response and response.get("status_code") == 200:
        token_response = json.decode(response.get("body", ""))
        access_token = token_response.get("access_token", "")

        if not access_token:
            log.error("No access token in response")
            return None

        # Extract org_id from JWT token (it's in the payload)
        org_id = extract_org_from_jwt(access_token)

        return {
            "access_token": access_token,
            "org_id": org_id
        }
    else:
        status = response.get("status_code", 0) if response else 0
        log.error("OAuth token exchange failed with status: %d" % status)
        if response and response.get("body"):
            log.error("Response: %s" % response.get("body"))
        return None


def extract_org_from_jwt(token):
    """
    Extract organization ID from JWT token payload.
    JWT format: header.payload.signature (all base64 encoded)
    """
    parts = token.split(".")
    if len(parts) != 3:
        log.error("Invalid JWT format")
        return ""

    # Decode the payload (middle part)
    payload_b64 = parts[1]

    # Add padding if needed (base64 requires multiple of 4)
    padding = len(payload_b64) % 4
    if padding:
        payload_b64 = payload_b64 + ("=" * (4 - padding))

    # Replace URL-safe characters
    payload_b64 = payload_b64.replace("-", "+").replace("_", "/")

    payload_json = base64.decode(payload_b64)
    if not payload_json:
        log.error("Failed to decode JWT payload")
        return ""

    payload = json.decode(payload_json)
    if not payload:
        log.error("Failed to parse JWT payload as JSON")
        return ""

    # Try common claim names for organization
    org_id = payload.get("org_id", "")
    if not org_id:
        org_id = payload.get("organization_id", "")
    if not org_id:
        org_id = payload.get("org", "")
    if not org_id:
        # Check in custom claims or permissions
        permissions = payload.get("permissions", [])
        scope = payload.get("scope", "")
        # Log the payload structure to help debug
        log.info("JWT payload keys: %s" % str(list(payload.keys())))

    return org_id


def make_upwind_request(access_token, base_url, org_id, endpoint, params=None, retries=5):
    """
    Make a request to Upwind REST API with retry logic for transient errors
    """
    url = "%s/v1/organizations/%s/%s" % (base_url, org_id, endpoint)

    # Build query string
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

    # Retry loop for transient failures
    for attempt in range(retries):
        response = http.get(url=url, headers=headers)
        status_code = response.get("status_code", 0) if response else 0

        # Success cases
        if status_code == 200 or status_code == 206:
            return {
                "data": json.decode(response.get("body", "")),
                "headers": response.get("headers", {})
            }

        # Non-retryable errors
        if status_code == 401:
            log.error("Authentication failed - check client credentials")
            return None
        if status_code == 403:
            log.error("Access denied - check API permissions")
            return None
        if status_code == 404:
            log.error("Resource not found: %s" % endpoint)
            return None

        # Retryable errors - 429, 500, 502, 503, 504, 0 (timeout)
        if status_code == 429 or status_code >= 500 or status_code == 0:
            if attempt < retries - 1:
                log.info("Request failed (status %d), retrying %d/%d..." % (status_code, attempt + 2, retries))
                # Brief pause before retry (Starlark doesn't have sleep, but the retry itself adds delay)
                continue
            else:
                log.error("Request failed after %d retries (status %d)" % (retries, status_code))
                return None

        # Other errors - don't retry
        log.error("API request failed with status %d for endpoint: %s" % (status_code, endpoint))
        if response and response.get("body"):
            log.error("Response: %s" % response.get("body", "")[:500])
        return None

    return None


def extract_page_token(headers):
    """
    Extract pagination token from Link header.
    Link header format: <url?page-token=xxx>; rel="next"
    """
    if not headers:
        return None

    link_header = headers.get("Link", "")
    if not link_header:
        link_header = headers.get("link", "")

    if not link_header:
        return None

    # Parse the link header to find rel="next"
    # Format: <url>; rel="next", <url>; rel="prev"
    parts = link_header.split(",")
    for part in parts:
        if 'rel="next"' in part or "rel='next'" in part:
            # Extract URL from angle brackets
            url_start = part.find("<")
            url_end = part.find(">")
            if url_start >= 0 and url_end > url_start:
                url = part[url_start + 1:url_end]
                # Extract page-token from URL
                if "page-token=" in url:
                    token_start = url.find("page-token=") + len("page-token=")
                    token_end = url.find("&", token_start)
                    if token_end < 0:
                        token_end = len(url)
                    return url[token_start:token_end]

    return None


def process_vulnerability_findings(access_token, base_url, org_id, pb, seen_resources, filters=None):
    """
    Fetch and process all vulnerability findings.
    Also creates instances from unique resources.
    """
    page_token = None
    total_findings = 0
    total_expected = None
    page_num = 0

    for i in range(MAX_ITERATIONS):
        page_num = page_num + 1
        params = {
            "per-page": str(DEFAULT_CHUNK_SIZE)
        }
        # Add filters
        if filters:
            for key, value in filters.items():
                params[key] = value
        if page_token:
            params["page-token"] = page_token

        result = make_upwind_request(access_token, base_url, org_id, "vulnerability-findings", params)

        if not result:
            log.error("Failed to fetch vulnerability findings on page %d, stopping pagination" % page_num)
            log.info("Partial results: %d findings processed, %d instances created" % (total_findings, len(seen_resources)))
            break

        findings = result.get("data", [])
        if not findings:
            log.info("No more findings on page %d" % page_num)
            break

        # Handle case where data might be wrapped in a response object
        if type(findings) == "dict":
            # Try to get total from pagination info
            pagination = findings.get("pagination", {})
            if pagination and not total_expected:
                total_expected = pagination.get("totalItems", 0)
                if total_expected:
                    log.info("Total vulnerability findings expected: %d" % total_expected)
            findings = findings.get("data", findings.get("items", []))

        batch_size = len(findings)
        for finding in findings:
            process_vulnerability_finding(finding, pb, seen_resources)
            total_findings = total_findings + 1

        # Progress logging
        if total_expected:
            pct = (total_findings * 100) / total_expected
            log.info("Page %d: processed %d findings (%d total, %.1f%%, %d instances)" % (
                page_num, batch_size, total_findings, pct, len(seen_resources)))
        else:
            log.info("Page %d: processed %d findings (%d total, %d instances)" % (
                page_num, batch_size, total_findings, len(seen_resources)))

        # Check for next page
        page_token = extract_page_token(result.get("headers"))
        if not page_token:
            log.info("No more pages (no next page token)")
            break

    log.info("Completed: processed %d vulnerability findings" % total_findings)


def process_vulnerability_finding(finding, pb, seen_resources):
    """
    Convert an Upwind vulnerability finding to a Zafran vulnerability.
    Also creates an instance for the resource if not seen before.
    """
    finding_id = finding.get("id", "")
    if not finding_id:
        return

    # Extract vulnerability info
    vuln_info = finding.get("vulnerability", {})
    cve = vuln_info.get("nvd_cve_id", "")
    if not cve:
        cve = vuln_info.get("name", "")
    if not cve:
        cve = "UPWIND-%s" % finding_id[:8]

    description = vuln_info.get("nvd_description", "")
    if not description:
        description = vuln_info.get("description", "")

    # Extract resource info for instance_id
    resource = finding.get("resource", {})
    instance_id = resource.get("id", "")
    if not instance_id:
        instance_id = resource.get("external_id", "")
    if not instance_id:
        # Use image info as fallback
        image = finding.get("image", {})
        instance_id = image.get("digest", image.get("uri", ""))

    # Create instance from resource if not seen before
    if instance_id and instance_id not in seen_resources:
        seen_resources[instance_id] = True
        create_instance_from_resource(finding, instance_id, pb)

    # Extract package info for component
    package = finding.get("package", {})
    component_product = package.get("name", "")
    component_version = package.get("version", "")
    component_type_str = package.get("type", "")

    # Map package type to component type
    component_type = pb.ComponentType.APPLICATION
    if component_type_str:
        type_lower = component_type_str.lower()
        if type_lower in ["library", "lib", "npm", "pypi", "gem", "maven", "nuget"]:
            component_type = pb.ComponentType.LIBRARY
        elif type_lower in ["os", "operating_system", "apk", "deb", "rpm"]:
            component_type = pb.ComponentType.OPERATING_SYSTEM

    # Build CVSS list
    cvss_list = []

    # CVSS v3
    cvss_v3_score = vuln_info.get("nvd_cvss_v3_score", "")
    if cvss_v3_score:
        score = 0.0
        if type(cvss_v3_score) == "string":
            if cvss_v3_score:
                score = float(cvss_v3_score)
        else:
            score = float(cvss_v3_score)
        if score > 0:
            cvss_list.append(pb.CVSS(
                version="3.1",
                vector="",
                base_score=score
            ))

    # CVSS v2 (fallback if no v3)
    if not cvss_list:
        cvss_v2_score = vuln_info.get("nvd_cvss_v2_score", "")
        if cvss_v2_score:
            score = 0.0
            if type(cvss_v2_score) == "string":
                if cvss_v2_score:
                    score = float(cvss_v2_score)
            else:
                score = float(cvss_v2_score)
            if score > 0:
                cvss_list.append(pb.CVSS(
                    version="2.0",
                    vector="",
                    base_score=score
                ))

    # CVSS v4
    cvss_v4_score = vuln_info.get("nvd_cvss_v4_score", "")
    if cvss_v4_score:
        score = 0.0
        if type(cvss_v4_score) == "string":
            if cvss_v4_score:
                score = float(cvss_v4_score)
        else:
            score = float(cvss_v4_score)
        if score > 0:
            cvss_list.append(pb.CVSS(
                version="4.0",
                vector="",
                base_score=score
            ))

    # Build remediation
    remediation_suggestion = "See Upwind for remediation details"
    remediation_list = finding.get("remediation", [])
    if remediation_list:
        for rem in remediation_list:
            data = rem.get("data", {})
            fixed_version = data.get("fixed_in_version", "")
            if fixed_version:
                remediation_suggestion = "Update to version %s" % fixed_version
                break

    # Check if in runtime (package in use)
    in_runtime = package.get("in_use", False)

    # Create vulnerability
    vuln = pb.Vulnerability(
        instance_id=instance_id,
        cve=cve,
        description=description,
        in_runtime=in_runtime,
        component=pb.Component(
            type=component_type,
            product=component_product,
            vendor="",
            version=component_version
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion=remediation_suggestion,
            source="Upwind Security"
        )
    )

    zafran.collect_vulnerability(vuln)


def create_instance_from_resource(finding, instance_id, pb):
    """
    Create an instance from the resource information in a vulnerability finding.
    """
    resource = finding.get("resource", {})
    image = finding.get("image", {})

    # Build instance name from resource or image
    instance_name = resource.get("name", "")
    if not instance_name:
        instance_name = image.get("name", "")
    if not instance_name:
        instance_name = instance_id

    # Get operating system from image
    os_info = ""
    os_name = image.get("os_name", "")
    os_version = image.get("os_version", "")
    if os_name:
        if os_version:
            os_info = "%s %s" % (os_name, os_version)
        else:
            os_info = os_name

    # Build properties
    properties = {}

    # Resource properties
    cloud_provider = resource.get("cloud_provider", "")
    if cloud_provider:
        properties["cloud_provider"] = pb.InstancePropertyValue(
            value=cloud_provider,
            type=pb.InstancePropertyType.STRING
        )

    cloud_account_id = resource.get("cloud_account_id", "")
    if cloud_account_id:
        properties["cloud_account_id"] = pb.InstancePropertyValue(
            value=cloud_account_id,
            type=pb.InstancePropertyType.STRING
        )

    cloud_account_name = resource.get("cloud_account_name", "")
    if cloud_account_name:
        properties["cloud_account_name"] = pb.InstancePropertyValue(
            value=cloud_account_name,
            type=pb.InstancePropertyType.STRING
        )

    region = resource.get("region", "")
    if region:
        properties["region"] = pb.InstancePropertyValue(
            value=region,
            type=pb.InstancePropertyType.STRING
        )

    resource_type = resource.get("type", "")
    if resource_type:
        properties["resource_type"] = pb.InstancePropertyValue(
            value=resource_type,
            type=pb.InstancePropertyType.STRING
        )

    namespace = resource.get("namespace", "")
    if namespace:
        properties["namespace"] = pb.InstancePropertyValue(
            value=namespace,
            type=pb.InstancePropertyType.STRING
        )

    cluster_id = resource.get("cluster_id", "")
    if cluster_id:
        properties["cluster_id"] = pb.InstancePropertyValue(
            value=cluster_id,
            type=pb.InstancePropertyType.STRING
        )

    external_id = resource.get("external_id", "")
    if external_id:
        properties["external_id"] = pb.InstancePropertyValue(
            value=external_id,
            type=pb.InstancePropertyType.STRING
        )

    # Image properties
    image_uri = image.get("uri", "")
    if image_uri:
        properties["image_uri"] = pb.InstancePropertyValue(
            value=image_uri,
            type=pb.InstancePropertyType.STRING
        )

    image_digest = image.get("digest", "")
    if image_digest:
        properties["image_digest"] = pb.InstancePropertyValue(
            value=image_digest,
            type=pb.InstancePropertyType.STRING
        )

    image_tag = image.get("tag", "")
    if image_tag:
        properties["image_tag"] = pb.InstancePropertyValue(
            value=image_tag,
            type=pb.InstancePropertyType.STRING
        )

    # Internet exposure
    internet_exposure = resource.get("internet_exposure", {})
    if internet_exposure:
        ingress = internet_exposure.get("ingress", {})
        if ingress:
            active_comm = ingress.get("active_communication", False)
            properties["internet_exposed"] = pb.InstancePropertyValue(
                value=str(active_comm),
                type=pb.InstancePropertyType.BOOL
            )

    # Build tags from risk categories
    tags = []
    risk_categories = resource.get("risk_categories", [])
    for category in risk_categories:
        tags.append(pb.InstanceTag(label=pb.InstanceTagLabel(label=category)))

    # Build identifiers based on cloud provider
    identifiers = []
    if external_id:
        if cloud_provider == "AWS" and "i-" in external_id:
            identifiers.append(pb.InstanceIdentifier(
                key=pb.IdentifierType.AWS_EC2_INSTANCE_ID,
                value=external_id,
                scanner_type="upwind"
            ))
        elif cloud_provider == "AZURE":
            identifiers.append(pb.InstanceIdentifier(
                key=pb.IdentifierType.AZURE_VM_ID,
                value=external_id,
                scanner_type="upwind"
            ))
        # Note: GCP doesn't have a specific identifier type in the proto

    # Create instance
    instance = pb.InstanceData(
        instance_id=instance_id,
        name=instance_name,
        operating_system=os_info,
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[],
            mac_addresses=[]
        ),
        identifiers=identifiers,
        instance_properties=properties,
        tags=tags
    )

    zafran.collect_instance(instance)
