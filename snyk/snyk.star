# Snyk Starlark integration script
# Fetches targets (instances) and vulnerabilities from Snyk API

load('http', 'http')
load('json', 'json')
load('zafran', 'zafran')
load('log', 'log')

# Snyk API configuration
DEFAULT_BASE_URL = "https://api.snyk.io"
API_VERSION = "2025-03-10"
DEFAULT_CHUNK_SIZE = 100
MAX_ITERATIONS = 1000

def main(**kwargs):
    """
    Main function to fetch data from Snyk

    Parameters:
    - api_url: Snyk API base URL (default: https://api.snyk.io)
    - api_key: Client ID (UUID)
    - api_secret: Client Secret
    """
    # Get parameters
    base_url = kwargs.get('api_url', DEFAULT_BASE_URL)
    client_id = kwargs.get('api_key', '')
    client_secret = kwargs.get('api_secret', '')

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

    # Get access token
    log.info("Authenticating with Snyk...")
    access_token = get_oauth_token(client_id, client_secret, base_url)
    if not access_token:
        log.error("Failed to authenticate with Snyk")
        return

    log.info("Successfully authenticated")

    # Get all organizations
    log.info("Fetching organizations...")
    orgs = get_all_orgs(access_token, base_url)

    if not orgs:
        log.warn("No organizations found")
        return

    log.info("Found %d organizations" % len(orgs))

    # Process each organization
    for org in orgs:
        process_organization(org, access_token, base_url, pb)


def get_oauth_token(client_id, client_secret, base_url):
    """
    Get OAuth access token from Snyk using client credentials flow
    """
    token_url = "%s/oauth2/token" % base_url

    # Form data for token request
    token_data = "grant_type=client_credentials&client_id=%s&client_secret=%s" % (client_id, client_secret)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = http.post(url=token_url, headers=headers, body=token_data)

    if response and response.get("status_code") == 200:
        token_response = json.decode(response.get("body", ""))
        return token_response.get("access_token", "")
    else:
        status = response.get("status_code", 0) if response else 0
        log.error("OAuth token exchange failed with status: %d" % status)
        if response and response.get("body"):
            log.error("Response: %s" % response.get("body"))
        return None


def make_snyk_request(access_token, base_url, endpoint, params=None):
    """
    Make a request to Snyk REST API
    """
    # Add version parameter
    if params == None:
        params = {}
    params["version"] = API_VERSION

    url = "%s/rest/%s" % (base_url, endpoint)

    # Build query string
    if params:
        param_parts = []
        for key, value in params.items():
            param_parts.append("%s=%s" % (key, value))
        query_string = "&".join(param_parts)
        url = "%s?%s" % (url, query_string)

    headers = {
        "Authorization": "Bearer %s" % access_token,
        "Accept": "application/vnd.api+json"
    }

    response = http.get(url=url, headers=headers)

    if response and response.get("status_code") == 200:
        return json.decode(response.get("body", ""))
    elif response and response.get("status_code") == 401:
        log.error("Authentication failed - check client credentials")
        return {}
    elif response and response.get("status_code") == 403:
        log.error("Access denied - check API permissions")
        return {}
    else:
        if response:
            log.error("API request failed with status: %d for endpoint: %s" % (response.get("status_code", 0), endpoint))
            log.error("Response body: %s" % response.get("body", ""))
        return {}


def extract_starting_after(links):
    """
    Extract pagination cursor from response links
    """
    if not links:
        return None

    next_link = links.get("next")
    if not next_link:
        return None

    # next_link is either a string URL or an object with href
    if type(next_link) == "string":
        url = next_link
    elif type(next_link) == "dict":
        url = next_link.get("href", "")
    else:
        return None

    if not url:
        return None

    # Parse starting_after from URL
    if "starting_after=" in url:
        parts = url.split("starting_after=")
        if len(parts) > 1:
            # Get the value (stop at & if present)
            value = parts[1].split("&")[0]
            return value

    return None


def get_all_orgs(access_token, base_url):
    """
    Get all organizations with pagination
    """
    all_orgs = []
    starting_after = None

    for i in range(MAX_ITERATIONS):
        params = {
            "limit": str(DEFAULT_CHUNK_SIZE)
        }
        if starting_after:
            params["starting_after"] = starting_after

        response = make_snyk_request(access_token, base_url, "orgs", params)

        data = response.get("data", [])
        if not data:
            break

        all_orgs.extend(data)

        # Check for next page
        starting_after = extract_starting_after(response.get("links"))
        if not starting_after:
            break

    return all_orgs


def process_organization(org, access_token, base_url, pb):
    """
    Process a single organization: fetch targets and vulnerabilities
    """
    org_id = org.get("id", "")
    org_name = ""
    if org.get("attributes"):
        org_name = org["attributes"].get("name", "")

    if not org_id:
        log.warn("Organization ID not found, skipping")
        return

    log.info("Processing organization: %s (%s)" % (org_name, org_id))

    # Fetch and process targets (instances)
    targets = get_all_targets(access_token, base_url, org_id)
    log.info("Found %d targets in org %s" % (len(targets), org_name))

    for i, target in enumerate(targets):
        process_target(target, org_id, org_name, pb, log_details=(i == 0))

    # Define all issue types to fetch
    issue_types = [
        ("package_vulnerability", "sca", "SCA"),
        ("code", "sast", "SAST"),
        ("config", "iac", "IaC"),
        ("license", "license", "License"),
        ("cloud", "cloud", "Cloud"),
    ]

    # Fetch and process all issue types
    for api_type, internal_type, display_name in issue_types:
        issues = get_all_issues(access_token, base_url, org_id, api_type)
        log.info("Found %d %s issues in org %s" % (len(issues), display_name, org_name))

        for issue in issues:
            process_issue(issue, pb, issue_type=internal_type)


def get_all_targets(access_token, base_url, org_id):
    """
    Get all targets for an organization with pagination
    """
    all_targets = []
    starting_after = None

    for i in range(MAX_ITERATIONS):
        params = {
            "limit": str(DEFAULT_CHUNK_SIZE)
        }
        if starting_after:
            params["starting_after"] = starting_after

        endpoint = "orgs/%s/targets" % org_id
        response = make_snyk_request(access_token, base_url, endpoint, params)

        data = response.get("data", [])
        if not data:
            break

        all_targets.extend(data)

        # Check for next page
        starting_after = extract_starting_after(response.get("links"))
        if not starting_after:
            break

    return all_targets


def process_target(target, org_id, org_name, pb, log_details=False):
    """
    Convert a Snyk target to an instance
    """
    target_id = target.get("id", "")
    if not target_id:
        return

    attributes = target.get("attributes", {})

    # Log first target details for debugging
    if log_details:
        log.info("Target attributes: %s" % str(attributes))

    # Get display name - try display_name first, then url parts, then fall back to id
    # API returns snake_case: display_name, url, is_private, created_at
    display_name = attributes.get("display_name", "")
    if not display_name:
        # Try to extract name from url if available
        url = attributes.get("url", "")
        if url:
            # Extract repo name from URL like https://github.com/org/repo or git@github.com:org/repo
            parts = url.split("/")
            if len(parts) > 0:
                display_name = parts[-1]
                # Remove .git suffix if present
                if display_name.endswith(".git"):
                    display_name = display_name[:-4]
    if not display_name:
        display_name = target_id

    # Build properties
    # API returns snake_case: display_name, url, is_private, created_at
    properties = {}

    if attributes.get("is_private") != None:
        properties["is_private"] = pb.InstancePropertyValue(
            value=str(attributes.get("is_private")),
            type=pb.InstancePropertyType.BOOL
        )

    if attributes.get("origin"):
        properties["origin"] = pb.InstancePropertyValue(
            value=attributes.get("origin"),
            type=pb.InstancePropertyType.STRING
        )

    if attributes.get("url"):
        properties["url"] = pb.InstancePropertyValue(
            value=attributes.get("url"),
            type=pb.InstancePropertyType.STRING
        )

    if org_id:
        properties["org_id"] = pb.InstancePropertyValue(
            value=org_id,
            type=pb.InstancePropertyType.STRING
        )

    if org_name:
        properties["org_name"] = pb.InstancePropertyValue(
            value=org_name,
            type=pb.InstancePropertyType.STRING
        )

    if attributes.get("created_at"):
        properties["created_at"] = pb.InstancePropertyValue(
            value=attributes.get("created_at"),
            type=pb.InstancePropertyType.STRING
        )

    # Create instance
    instance = pb.InstanceData(
        instance_id=target_id,
        name=display_name,
        operating_system="",  # Not applicable for code targets
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[],
            mac_addresses=[]
        ),
        identifiers=[],  # Go version returns empty identifiers
        instance_properties=properties
    )

    zafran.collect_instance(instance)


def get_all_issues(access_token, base_url, org_id, issue_type="package_vulnerability"):
    """
    Get all issues (vulnerabilities) for an organization with pagination

    Args:
        access_token: OAuth access token
        base_url: Snyk API base URL
        org_id: Organization ID
        issue_type: Type of issues to fetch:
            - "package_vulnerability" for SCA issues
            - "code" for SAST issues
            - "config" for IaC issues
            - "license" for license issues
            - "cloud" for cloud issues
    """
    all_issues = []
    starting_after = None

    for i in range(MAX_ITERATIONS):
        params = {
            "limit": str(DEFAULT_CHUNK_SIZE),
            "type": issue_type,
            "status": "open"
        }
        if starting_after:
            params["starting_after"] = starting_after

        endpoint = "orgs/%s/issues" % org_id
        response = make_snyk_request(access_token, base_url, endpoint, params)

        data = response.get("data", [])
        if not data:
            break

        all_issues.extend(data)

        # Check for next page
        starting_after = extract_starting_after(response.get("links"))
        if not starting_after:
            break

    return all_issues


def get_snyk_source_name(issue_type):
    """Get the Snyk product name for the issue type"""
    source_names = {
        "sca": "Snyk Open Source",
        "sast": "Snyk Code",
        "iac": "Snyk IaC",
        "license": "Snyk Open Source",
        "cloud": "Snyk Cloud",
    }
    return source_names.get(issue_type, "Snyk")


def process_issue(issue, pb, issue_type="sca"):
    """
    Convert a Snyk issue to a vulnerability

    Args:
        issue: Issue data from Snyk API
        pb: Proto types
        issue_type: Issue type identifier:
            - "sca" for package vulnerabilities
            - "sast" for code issues
            - "iac" for infrastructure as code issues
            - "license" for license compliance issues
            - "cloud" for cloud security issues
    """
    issue_id = issue.get("id", "")
    if not issue_id:
        return

    attributes = issue.get("attributes", {})
    relationships = issue.get("relationships", {})

    # Get CVE from problems (primarily for SCA issues)
    cve = ""
    problems = attributes.get("problems", [])
    for problem in problems:
        if problem.get("source") == "NVD":
            cve = problem.get("id", "")
            break

    # If no NVD CVE, try to use SNYK ID or key
    if not cve:
        key = attributes.get("key", "")
        if key:
            cve = key
        else:
            # Create type-specific identifier
            type_prefixes = {
                "sca": "SNYK-SCA",
                "sast": "SNYK-CODE",
                "iac": "SNYK-IAC",
                "license": "SNYK-LICENSE",
                "cloud": "SNYK-CLOUD",
            }
            prefix = type_prefixes.get(issue_type, "SNYK")
            cve = "%s-%s" % (prefix, issue_id[:8])

    # Get instance_id from relationships (project/scan_item -> target)
    instance_id = ""
    scan_item = relationships.get("scan_item", {})
    if scan_item:
        scan_data = scan_item.get("data", {})
        if scan_data:
            # scan_item.data.id is the project ID, which is linked to a target
            # For simplicity, we use the project ID as instance_id reference
            instance_id = scan_data.get("id", "")

    if not instance_id:
        # Fallback: try to get from organization
        org_data = relationships.get("organization", {}).get("data", {})
        instance_id = org_data.get("id", "")

    # Extract CVSS scores
    cvss_list = []
    severities = attributes.get("severities", [])

    # Prefer NVD, then Snyk, then others
    preferred_sources = ["NVD", "Snyk", "Red Hat", "SUSE"]
    selected_severities = []

    for source in preferred_sources:
        for sev in severities:
            if sev.get("source") == source:
                selected_severities.append(sev)
        if selected_severities:
            break

    # If no preferred source found, use all
    if not selected_severities:
        selected_severities = severities

    # De-duplicate by version
    seen_versions = {}
    for sev in selected_severities:
        version = sev.get("version", "")
        if version and version not in seen_versions:
            seen_versions[version] = sev
            cvss_list.append(pb.CVSS(
                version=version,
                vector=sev.get("vector", ""),
                base_score=float(sev.get("score", 0))
            ))

    # For non-SCA issues without CVSS, derive from effective_severity_level
    if not cvss_list and issue_type != "sca":
        effective_severity = attributes.get("effective_severity_level", "")
        if effective_severity:
            # Map severity levels to approximate CVSS scores
            severity_to_cvss = {
                "critical": 9.0,
                "high": 7.5,
                "medium": 5.0,
                "low": 2.5,
                "info": 0.0
            }
            base_score = severity_to_cvss.get(effective_severity.lower(), 5.0)
            cvss_list.append(pb.CVSS(
                version="3.1",
                vector="",  # Non-SCA issues typically don't have CVSS vectors
                base_score=base_score
            ))

    # Extract component information from coordinates (for SCA issues)
    component_product = ""
    component_version = ""
    coordinates = attributes.get("coordinates", [])
    if coordinates:
        for coord in coordinates:
            representations = coord.get("representations", [])
            for rep in representations:
                dep = rep.get("dependency", {})
                if dep:
                    component_product = dep.get("packageName", "")
                    component_version = dep.get("packageVersion", "")
                    break
            if component_product:
                break

    # For non-SCA issues, try to get file path from coordinates
    if issue_type != "sca" and not component_product and coordinates:
        for coord in coordinates:
            representations = coord.get("representations", [])
            for rep in representations:
                # Non-SCA issues may have file path in source_location or resourcePath
                source_location = rep.get("source_location", {})
                if source_location:
                    file_path = source_location.get("file", "")
                    if file_path:
                        component_product = file_path
                        break
                # IaC/Cloud issues may have resourcePath
                resource_path = rep.get("resourcePath", "")
                if resource_path:
                    component_product = resource_path
                    break
            if component_product:
                break

    # Get description/title
    description = attributes.get("title", "")

    # Extract CWE IDs from classes (common for both SCA and SAST)
    cwe_ids = []
    classes = attributes.get("classes", [])
    for cls in classes:
        cls_id = cls.get("id", "")
        cls_source = cls.get("source", "")
        if cls_source == "CWE" and cls_id:
            # Extract numeric CWE ID from string like "CWE-79"
            if cls_id.startswith("CWE-"):
                cwe_num_str = cls_id[4:]
                # Check if it's a valid integer
                if cwe_num_str.isdigit():
                    cwe_ids.append(int(cwe_num_str))

    # Build remediation suggestion
    remediation_suggestion = "See Snyk for remediation details"
    key = attributes.get("key", "")
    if key and key.startswith("SNYK-"):
        remediation_suggestion = "View details at https://security.snyk.io/vuln/%s" % key
    elif issue_type == "sast":
        remediation_suggestion = "Review and fix the code issue identified by Snyk Code"
    elif issue_type == "iac":
        remediation_suggestion = "Review and fix the infrastructure configuration issue"
    elif issue_type == "license":
        remediation_suggestion = "Review license compliance and consider alternative packages"
    elif issue_type == "cloud":
        remediation_suggestion = "Review and remediate the cloud security configuration"

    # Determine component type based on issue type
    component_type = pb.ComponentType.APPLICATION
    if issue_type in ["sast", "iac"]:
        component_type = pb.ComponentType.FILE
    elif issue_type == "cloud":
        component_type = pb.ComponentType.PLATFORM

    # Create vulnerability
    vuln = pb.Vulnerability(
        instance_id=instance_id,
        cve=cve,
        description=description,
        in_runtime=False,  # Snyk is primarily SCA/SAST, not runtime
        component=pb.Component(
            type=component_type,
            product=component_product,
            vendor="",
            version=component_version
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion=remediation_suggestion,
            source=get_snyk_source_name(issue_type)
        ),
        cwe_ids=cwe_ids
    )

    zafran.collect_vulnerability(vuln)
