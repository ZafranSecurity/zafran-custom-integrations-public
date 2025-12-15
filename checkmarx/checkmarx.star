# Checkmarx One Starlark integration script
# Fetches projects (instances) and vulnerabilities from Checkmarx One API
# Supports SCA, SAST, KICS (IaC), and API Security scan results
#
# Optimized for scale:
# - Fetches all completed scans at once, then groups by project
# - Filters scans by date (last 365 days)
# - Batches SAST/KICS results queries using scan-ids filter

load('http', 'http')
load('json', 'json')
load('zafran', 'zafran')
load('log', 'log')
load('time', 'time')


def sleep(seconds):
    """
    Custom sleep function using time.now() and time.parse_duration().
    """
    duration = time.parse_duration("%ds" % seconds)
    target_time = time.now() + duration
    while time.now() < target_time:
        pass

# API configuration
DEFAULT_CHUNK_SIZE = 100
SCANS_CHUNK_SIZE = 50  # Smaller chunk for scans to avoid timeout
MAX_ITERATIONS = 10000  # Increased for large scan fetches
EXPORT_POLL_INTERVAL = 5  # seconds
EXPORT_POLL_MAX = 120  # max polls (10 minutes)
LOOKBACK_DAYS = 365  # Only fetch scans from last year
BATCH_SIZE = 50  # Number of projects per batch for scan lookup
RESULTS_BATCH_SIZE = 10  # Number of scans to batch for SAST/KICS/APISec results (API has limits)

def main(**kwargs):
    """
    Main function to fetch data from Checkmarx One

    Parameters:
    - api_url: Checkmarx One base URL (e.g., https://ast.checkmarx.net or https://tenant.cxone.cloud)
    - api_key: For OAuth: client_id, For API Key auth: the API key/refresh token
    - api_secret: For OAuth: client_secret, For API Key auth: leave empty or set tenant_name
    - modes: Comma-separated list of scan types to collect (default: sca,sast,kics,apisec)
             Options: sca, sast, kics, apisec

    The script auto-detects authentication type:
    - If api_secret is provided and looks like a secret: OAuth client credentials
    - If api_secret is empty or contains tenant name: API Key (refresh token) auth
    """
    # Get parameters
    base_url = kwargs.get('api_url', '')
    api_key = kwargs.get('api_key', '')
    api_secret = kwargs.get('api_secret', '')
    # Note: apisec removed from default - endpoint may not be available on all tenants
    modes_param = kwargs.get('modes', 'sca,sast,kics')

    # Parse modes
    enabled_modes = [m.strip().lower() for m in modes_param.split(',')]
    log.info("Enabled modes: %s" % str(enabled_modes))

    if not base_url:
        log.error('api_url parameter is required')
        return

    if not api_key:
        log.error('api_key parameter is required')
        return

    # Ensure base_url has https:// prefix
    if not base_url.startswith("http"):
        base_url = "https://" + base_url

    # Remove trailing slash
    if base_url.endswith("/"):
        base_url = base_url[:-1]

    # Parse tenant name from base_url for custom deployments
    # Format: https://tenant.cxone.cloud or standard regions
    tenant_name = extract_tenant_name(base_url)

    # Get proto types
    pb = zafran.proto_file

    # Authenticate
    log.info("Authenticating with Checkmarx One...")
    access_token = authenticate(base_url, tenant_name, api_key, api_secret)
    if not access_token:
        log.error("Failed to authenticate with Checkmarx One")
        return

    log.info("Successfully authenticated")

    # Fetch all projects first
    log.info("Fetching projects...")
    projects = get_all_projects(access_token, base_url)

    if not projects:
        log.warn("No projects found")
        return

    log.info("Found %d total projects" % len(projects))

    # Build project ID to project mapping
    projects_by_id = {}
    project_ids = []
    for project in projects:
        project_id = project.get("id", "")
        if project_id:
            projects_by_id[project_id] = project
            project_ids.append(project_id)

    # OPTIMIZATION: Fetch latest scan per project in batches using project-ids filter
    # This is much more efficient than fetching all scans and filtering
    log.info("Fetching latest scan for each project in batches...")
    project_scans = get_latest_scans_for_projects(access_token, base_url, project_ids)
    log.info("Found scans for %d projects with recent activity" % len(project_scans))

    # Create instances only for projects with scans (to avoid 10k limit)
    log.info("Creating instances for projects with recent scans...")
    for project_id in project_scans:
        if project_id in projects_by_id:
            create_project_instance(projects_by_id[project_id], pb)

    log.info("Created %d instances" % len(project_scans))

    # Separate scans by engine type based on enabled modes
    sca_scans = []
    sast_scans = []
    kics_scans = []
    apisec_scans = []

    for project_id, scan in project_scans.items():
        scan_id = scan.get("id", "")
        engines = get_completed_engines(scan)

        if "sca" in enabled_modes and "sca" in engines:
            sca_scans.append({"project_id": project_id, "scan_id": scan_id})
        if "sast" in enabled_modes and "sast" in engines:
            sast_scans.append({"project_id": project_id, "scan_id": scan_id})
        if "kics" in enabled_modes and "kics" in engines:
            kics_scans.append({"project_id": project_id, "scan_id": scan_id})
        if "apisec" in enabled_modes and "apisec" in engines:
            apisec_scans.append({"project_id": project_id, "scan_id": scan_id})

    log.info("Scan breakdown: SCA=%d, SAST=%d, KICS=%d, APISec=%d" % (
        len(sca_scans), len(sast_scans), len(kics_scans), len(apisec_scans)))

    # Process SCA vulnerabilities (requires individual exports - the bottleneck)
    if sca_scans and "sca" in enabled_modes:
        log.info("Processing %d SCA scans (requires individual exports)..." % len(sca_scans))
        process_sca_scans(access_token, base_url, sca_scans, pb)

    # Process SAST results
    if sast_scans and "sast" in enabled_modes:
        log.info("Processing %d SAST scans..." % len(sast_scans))
        process_batched_sast_scans(access_token, base_url, sast_scans, pb)

    # Process KICS results
    if kics_scans and "kics" in enabled_modes:
        log.info("Processing %d KICS scans..." % len(kics_scans))
        process_batched_kics_scans(access_token, base_url, kics_scans, pb)

    # Process API Security results
    if apisec_scans and "apisec" in enabled_modes:
        log.info("Processing %d API Security scans..." % len(apisec_scans))
        process_batched_apisec_scans(access_token, base_url, apisec_scans, pb)

    log.info("Completed Checkmarx data collection")


def extract_tenant_name(base_url):
    """
    Extract tenant name from URL
    For custom deployments like https://tenant.cxone.cloud, extract 'tenant'
    For standard regions, return empty (will be ignored)
    """
    # Remove protocol
    url = base_url
    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]

    # Check if it's a custom cxone.cloud deployment
    if ".cxone.cloud" in url:
        # Extract tenant from tenant.cxone.cloud
        parts = url.split(".")
        if len(parts) >= 3:
            return parts[0]

    # For standard regions, tenant is provided separately or in the URL path
    return ""


def authenticate(base_url, tenant_name, api_key, api_secret):
    """
    Authenticate with Checkmarx One using OAuth client credentials

    For custom deployments (e.g., tenant.cxone.cloud):
    - Auth URL: {base_url}/auth/realms/{tenant_name}/protocol/openid-connect/token

    For standard regions with OAuth:
    - Uses client_id and client_secret
    """
    # Determine auth URL
    if tenant_name:
        auth_url = "%s/auth/realms/%s/protocol/openid-connect/token" % (base_url, tenant_name)
    else:
        # Standard region - use IAM endpoint
        # Convert base URL to auth URL (e.g., ast.checkmarx.net -> iam.checkmarx.net)
        auth_base = base_url.replace("ast.", "iam.").replace("us.ast.", "us.iam.").replace("eu.ast.", "eu.iam.")
        auth_url = "%s/auth/realms/checkmarx_one/protocol/openid-connect/token" % auth_base

    # OAuth client credentials flow
    auth_data = "grant_type=client_credentials&client_id=%s&client_secret=%s" % (api_key, api_secret)

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    response = http.post(url=auth_url, headers=headers, body=auth_data)

    if response and response.get("status_code") == 200:
        token_response = json.decode(response.get("body", ""))
        return token_response.get("access_token", "")
    else:
        status = response.get("status_code", 0) if response else 0
        log.error("OAuth authentication failed with status: %d" % status)
        if response and response.get("body"):
            log.error("Response: %s" % response.get("body"))
        return None


def make_checkmarx_request(access_token, base_url, path, params=None, method="GET", body=None):
    """
    Make a request to Checkmarx One API
    """
    url = "%s/%s" % (base_url, path)

    # Build query string
    if params:
        param_parts = []
        for key, value in params.items():
            param_parts.append("%s=%s" % (key, value))
        query_string = "&".join(param_parts)
        url = "%s?%s" % (url, query_string)

    headers = {
        "Authorization": "Bearer %s" % access_token,
        "Accept": "application/json",
        "Content-Type": "application/json"
    }

    if method == "GET":
        response = http.get(url=url, headers=headers)
    elif method == "POST":
        if body:
            response = http.post(url=url, headers=headers, body=json.encode(body))
        else:
            response = http.post(url=url, headers=headers, body="")
    else:
        log.error("Unsupported HTTP method: %s" % method)
        return {}

    if response and response.get("status_code") == 200:
        return json.decode(response.get("body", ""))
    elif response and response.get("status_code") == 202:
        # Accepted - return the response for async operations
        return json.decode(response.get("body", ""))
    elif response and response.get("status_code") == 401:
        log.error("Authentication failed - check credentials")
        return {}
    elif response and response.get("status_code") == 403:
        log.error("Access denied - check API permissions")
        return {}
    elif response and response.get("status_code") == 404:
        # Not found - endpoint may not exist or feature not available
        log.info("Endpoint not found (404): %s - feature may not be available" % path)
        return {}
    else:
        if response:
            log.error("API request failed with status: %d for path: %s" % (response.get("status_code", 0), path))
        return {}


def get_all_projects(access_token, base_url):
    """
    Get all projects with pagination
    """
    all_projects = []
    offset = 0

    for i in range(MAX_ITERATIONS):
        params = {
            "offset": str(offset),
            "limit": str(DEFAULT_CHUNK_SIZE)
        }

        response = make_checkmarx_request(access_token, base_url, "api/projects", params)

        projects = response.get("projects", [])
        if not projects:
            break

        all_projects.extend(projects)
        offset += len(projects)

        # Check if we've fetched all
        total_count = response.get("totalCount", 0)
        if offset >= total_count:
            break

    return all_projects


def get_latest_scans_for_projects(access_token, base_url, project_ids):
    """
    OPTIMIZATION: Fetch latest scan for each project using batched project-ids filter.
    This is much more efficient than fetching all scans.

    Approach: For each batch of projects, fetch scans with limit high enough to get
    at least one per project, sorted by -created_at, then dedupe to get latest per project.
    """
    project_scans = {}

    # Hardcoded from-date (approximately 365 days ago from Dec 2025)
    from_date_str = "2024-12-04T00:00:00Z"

    # Process projects in batches
    batch_size = BATCH_SIZE  # 50 projects per batch
    total_batches = (len(project_ids) + batch_size - 1) // batch_size

    for batch_num in range(total_batches):
        batch_start = batch_num * batch_size
        batch_end = min(batch_start + batch_size, len(project_ids))
        batch_project_ids = project_ids[batch_start:batch_end]

        if (batch_num + 1) % 20 == 0:
            log.info("Processing scan batch %d of %d..." % (batch_num + 1, total_batches))

        # Join project IDs with semicolon for the API (as per Checkmarx API docs)
        project_ids_str = ";".join(batch_project_ids)

        # Fetch scans for this batch of projects
        # Use a higher limit to ensure we get scans for all projects in batch
        # Even if some projects have multiple scans, we only need the latest
        params = {
            "project-ids": project_ids_str,
            "statuses": "Completed",
            "from-date": from_date_str,
            "sort": "-created_at",
            "limit": str(batch_size * 2)  # Allow for some projects with multiple scans
        }

        response = make_checkmarx_request(access_token, base_url, "api/scans", params)

        scans = response.get("scans", [])

        # Dedupe - keep only the first (latest) scan per project
        for scan in scans:
            pid = scan.get("projectId", "")
            if pid and pid not in project_scans:
                project_scans[pid] = scan

    return project_scans


def get_completed_engines(scan):
    """
    Extract list of completed engines from a scan's status details.
    """
    engines = []
    status_details = scan.get("statusDetails", [])

    for detail in status_details:
        engine = detail.get("name", "")
        status = detail.get("status", "")
        if engine and status == "Completed":
            engines.append(engine)

    return engines


def process_sca_scans(access_token, base_url, sca_scans, pb):
    """
    Process SCA vulnerabilities for all scans.
    SCA requires individual export requests - this is the main bottleneck.
    """
    total = len(sca_scans)
    for i, scan_info in enumerate(sca_scans):
        project_id = scan_info["project_id"]
        scan_id = scan_info["scan_id"]

        if (i + 1) % 100 == 0:
            log.info("Processing SCA scan %d of %d..." % (i + 1, total))

        fetch_sca_vulnerabilities(access_token, base_url, scan_id, project_id, pb)


def process_batched_sast_scans(access_token, base_url, sast_scans, pb):
    """
    Process SAST results - one scan at a time.
    Note: The API requires scan-id (singular), not scan-ids, so we can't batch.
    """
    total_collected = 0
    total_scans = len(sast_scans)

    for i, scan_info in enumerate(sast_scans):
        scan_id = scan_info["scan_id"]
        project_id = scan_info["project_id"]

        if (i + 1) % 50 == 0:
            log.info("Processing SAST scan %d of %d..." % (i + 1, total_scans))

        # Fetch results for this single scan
        vulns = fetch_sast_results_for_scan(access_token, base_url, scan_id)

        for vuln in vulns:
            process_sast_vulnerability(vuln, project_id, pb)
            total_collected += 1

    log.info("Collected %d SAST vulnerabilities total" % total_collected)


def fetch_sast_results_for_scan(access_token, base_url, scan_id):
    """
    Fetch SAST results for a single scan.
    Note: API requires scan-id (singular), not scan-ids.
    """
    all_results = []
    offset = 0

    for i in range(MAX_ITERATIONS):
        params = {
            "scan-id": scan_id,
            "offset": str(offset),
            "limit": str(DEFAULT_CHUNK_SIZE)
        }

        response = make_checkmarx_request(access_token, base_url, "api/sast-results", params)

        results = response.get("results", [])
        if not results:
            break

        all_results.extend(results)
        offset += len(results)

        total_count = response.get("totalCount", 0)
        if offset >= total_count:
            break

    return all_results


def process_batched_kics_scans(access_token, base_url, kics_scans, pb):
    """
    Process KICS results - one scan at a time.
    Note: The API requires scan-id (singular), not scan-ids, so we can't batch.
    """
    total_collected = 0
    total_scans = len(kics_scans)

    for i, scan_info in enumerate(kics_scans):
        scan_id = scan_info["scan_id"]
        project_id = scan_info["project_id"]

        if (i + 1) % 50 == 0:
            log.info("Processing KICS scan %d of %d..." % (i + 1, total_scans))

        vulns = fetch_kics_results_for_scan(access_token, base_url, scan_id)

        for vuln in vulns:
            process_kics_vulnerability(vuln, project_id, pb)
            total_collected += 1

    log.info("Collected %d KICS vulnerabilities total" % total_collected)


def fetch_kics_results_for_scan(access_token, base_url, scan_id):
    """
    Fetch KICS results for a single scan.
    Note: API requires scan-id (singular), not scan-ids.
    """
    all_results = []
    offset = 0

    for i in range(MAX_ITERATIONS):
        params = {
            "scan-id": scan_id,
            "offset": str(offset),
            "limit": str(DEFAULT_CHUNK_SIZE)
        }

        response = make_checkmarx_request(access_token, base_url, "api/kics-results", params)

        results = response.get("results", [])
        if not results:
            break

        all_results.extend(results)
        offset += len(results)

        total_count = response.get("totalCount", 0)
        if offset >= total_count:
            break

    return all_results


def process_batched_apisec_scans(access_token, base_url, apisec_scans, pb):
    """
    Process API Security results - one scan at a time.
    Note: The API requires scan-id (singular), not scan-ids, so we can't batch.
    """
    total_collected = 0
    total_scans = len(apisec_scans)

    for i, scan_info in enumerate(apisec_scans):
        scan_id = scan_info["scan_id"]
        project_id = scan_info["project_id"]

        if (i + 1) % 50 == 0:
            log.info("Processing APISec scan %d of %d..." % (i + 1, total_scans))

        vulns = fetch_apisec_results_for_scan(access_token, base_url, scan_id)

        for vuln in vulns:
            process_apisec_vulnerability(vuln, project_id, pb)
            total_collected += 1

    log.info("Collected %d API Security vulnerabilities total" % total_collected)


def fetch_apisec_results_for_scan(access_token, base_url, scan_id):
    """
    Fetch API Security results for a single scan.
    Note: API requires scan-id (singular), not scan-ids.
    """
    all_results = []
    offset = 0

    for i in range(MAX_ITERATIONS):
        params = {
            "scan-id": scan_id,
            "offset": str(offset),
            "limit": str(DEFAULT_CHUNK_SIZE)
        }

        response = make_checkmarx_request(access_token, base_url, "api/apisec-results", params)

        results = response.get("results", [])
        if not results:
            break

        all_results.extend(results)
        offset += len(results)

        total_count = response.get("totalCount", 0)
        if offset >= total_count:
            break

    return all_results


def create_project_instance(project, pb):
    """
    Convert a Checkmarx project to an instance
    """
    project_id = project.get("id", "")
    project_name = project.get("name", "")

    if not project_id:
        return

    # Build properties
    properties = {}

    groups = project.get("groups", [])
    if groups:
        properties["GROUPS"] = pb.InstancePropertyValue(
            value=",".join(groups),
            type=pb.InstancePropertyType.STRING
        )

    repo_url = project.get("repoUrl", "")
    if repo_url:
        properties["REPO_URL"] = pb.InstancePropertyValue(
            value=repo_url,
            type=pb.InstancePropertyType.STRING
        )

    main_branch = project.get("mainBranch", "")
    if main_branch:
        properties["MAIN_BRANCH"] = pb.InstancePropertyValue(
            value=main_branch,
            type=pb.InstancePropertyType.STRING
        )

    origin = project.get("origin", "")
    if origin:
        properties["ORIGIN"] = pb.InstancePropertyValue(
            value=origin,
            type=pb.InstancePropertyType.STRING
        )

    criticality = project.get("criticality", 0)
    if criticality:
        properties["CRITICALITY"] = pb.InstancePropertyValue(
            value=str(criticality),
            type=pb.InstancePropertyType.INT
        )

    # Create instance
    instance = pb.InstanceData(
        instance_id=project_id,
        name=project_name,
        operating_system="",
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[],
            mac_addresses=[]
        ),
        identifiers=[],
        instance_properties=properties
    )

    zafran.collect_instance(instance)


def fetch_sca_vulnerabilities(access_token, base_url, scan_id, project_id, pb):
    """
    Fetch SCA vulnerabilities using the export API (like Go implementation)
    """
    log.info("Fetching SCA vulnerabilities for scan %s" % scan_id)

    # Create export request
    export_params = {
        "scanId": scan_id,
        "fileFormat": "ScanReportJson",
        "exportParameters": {
            "hideDevAndTestDependencies": True,
            "showOnlyEffectiveLicenses": True
        }
    }

    response = make_checkmarx_request(
        access_token, base_url,
        "api/sca/export/requests",
        method="POST",
        body=export_params
    )

    export_id = response.get("exportId", "")
    if not export_id:
        log.warn("Failed to create SCA export for scan %s" % scan_id)
        return

    log.info("Created SCA export with ID: %s" % export_id)

    # Poll for completion
    export_completed = False
    for i in range(EXPORT_POLL_MAX):
        status_response = make_checkmarx_request(
            access_token, base_url,
            "api/sca/export/requests",
            params={"exportId": export_id}
        )

        export_status = status_response.get("exportStatus", "")

        if export_status == "Completed":
            log.info("SCA export completed")
            export_completed = True
            break
        elif export_status == "Failed":
            error_msg = status_response.get("errorMessage", "Unknown error")
            log.error("SCA export failed: %s" % error_msg)
            return
        elif export_status in ["Pending", "Exporting"]:
            sleep(EXPORT_POLL_INTERVAL)
        else:
            log.error("Unknown SCA export status: %s" % export_status)
            return

    if not export_completed:
        log.error("Timed out waiting for SCA export")
        return

    # Download export
    download_path = "api/sca/export/requests/%s/download" % export_id
    risk_report = make_checkmarx_request(access_token, base_url, download_path)

    if not risk_report:
        log.warn("Failed to download SCA export")
        return

    # Process vulnerabilities
    vulnerabilities = risk_report.get("Vulnerabilities", [])
    log.info("Found %d SCA vulnerabilities" % len(vulnerabilities))

    for vuln in vulnerabilities:
        process_sca_vulnerability(vuln, project_id, pb)


def process_sca_vulnerability(vuln, project_id, pb):
    """
    Convert a Checkmarx SCA vulnerability to a vulnerability object
    """
    vuln_id = vuln.get("Id", "")
    cve_name = vuln.get("CveName", "")

    # Use CVE name if available, otherwise use Checkmarx ID
    cve = cve_name if cve_name else vuln_id
    if not cve:
        return

    # Extract component info
    package_name = vuln.get("PackageName", "")
    package_version = vuln.get("PackageVersion", "")

    # Parse vendor:product format
    vendor = ""
    product = package_name
    if ":" in package_name:
        parts = package_name.split(":", 1)
        vendor = parts[0]
        product = parts[1]

    # Extract CVSS scores
    cvss_list = []
    cvss2 = vuln.get("Cvss2")
    cvss3 = vuln.get("Cvss3")
    cvss4 = vuln.get("Cvss4")

    if cvss2:
        base_score = parse_base_score(cvss2.get("BaseScore", "0"))
        if base_score > 0:
            cvss_list.append(pb.CVSS(
                version="2.0",
                vector="",
                base_score=base_score
            ))

    if cvss3:
        base_score = parse_base_score(cvss3.get("BaseScore", "0"))
        if base_score > 0:
            cvss_list.append(pb.CVSS(
                version="3.1",
                vector="",
                base_score=base_score
            ))

    if cvss4:
        base_score = parse_base_score(cvss4.get("BaseScore", "0"))
        if base_score > 0:
            cvss_list.append(pb.CVSS(
                version="4.0",
                vector="",
                base_score=base_score
            ))

    # If no CVSS, derive from severity
    if not cvss_list:
        severity = vuln.get("Severity", "")
        base_score = severity_to_cvss(severity)
        if base_score > 0:
            cvss_list.append(pb.CVSS(
                version="3.1",
                vector="",
                base_score=base_score
            ))

    # Extract CWE
    cwe_ids = []
    cwe = vuln.get("Cwe", "")
    if cwe and cwe.startswith("CWE-"):
        cwe_num_str = cwe[4:]
        if cwe_num_str.isdigit():
            cwe_ids.append(int(cwe_num_str))

    # Build remediation
    fix_text = vuln.get("FixResolutionText", "")
    remediation_suggestion = ""
    if fix_text and product:
        remediation_suggestion = "Upgrade %s to version %s or higher." % (product, fix_text)
    elif fix_text:
        remediation_suggestion = fix_text

    description = vuln.get("Description", "")

    # Create vulnerability
    vulnerability = pb.Vulnerability(
        instance_id=project_id,
        cve=cve,
        description=description,
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.LIBRARY,
            product=product,
            vendor=vendor,
            version=package_version
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion=remediation_suggestion,
            source="Checkmarx SCA"
        ),
        cwe_ids=cwe_ids
    )

    zafran.collect_vulnerability(vulnerability)


def process_sast_vulnerability(result, project_id, pb):
    """
    Convert a Checkmarx SAST result to a vulnerability object
    """
    # SAST results may not have 'id' field - use similarityID or resultHash as fallback
    result_id = result.get("id", "")
    if not result_id:
        result_id = str(result.get("similarityID", ""))
    if not result_id:
        result_id = result.get("resultHash", "")
    if not result_id:
        # Skip results without any identifier
        return

    # SAST vulnerabilities don't have CVEs - use query name as CVE identifier
    query_name = result.get("queryName", "")
    cve = query_name if query_name else "CX-SAST-%s" % result_id[:12]

    # Get severity and derive CVSS
    severity = result.get("severity", "")
    base_score = severity_to_cvss(severity)

    cvss_list = []
    if base_score > 0:
        cvss_list.append(pb.CVSS(
            version="3.1",
            vector="",
            base_score=base_score
        ))

    # Extract CWE (API returns cweID not cweId)
    cwe_ids = []
    cwe_id = result.get("cweID", 0)
    if not cwe_id:
        cwe_id = result.get("cweId", 0)  # Fallback
    if cwe_id:
        cwe_ids.append(cwe_id)

    # Get file location as component
    nodes = result.get("nodes", [])
    file_name = ""
    if nodes:
        first_node = nodes[0]
        file_name = first_node.get("fileName", "")

    description = result.get("description", "")
    if not description:
        description = query_name

    # Create vulnerability
    vulnerability = pb.Vulnerability(
        instance_id=project_id,
        cve=cve,
        description=description,
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.FILE,
            product=file_name,
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion="Review and fix the code issue identified by Checkmarx SAST",
            source="Checkmarx SAST"
        ),
        cwe_ids=cwe_ids
    )

    zafran.collect_vulnerability(vulnerability)


def process_kics_vulnerability(result, project_id, pb):
    """
    Convert a Checkmarx KICS result to a vulnerability object
    """
    # KICS results may not have 'id' field - use similarityID or resultHash as fallback
    result_id = result.get("id", "")
    if not result_id:
        result_id = str(result.get("similarityID", ""))
    if not result_id:
        result_id = result.get("resultHash", "")
    if not result_id:
        # Skip results without any identifier
        return

    # KICS vulnerabilities use query ID or name as CVE identifier
    query_id = result.get("queryId", "")
    query_name = result.get("queryName", "")
    cve = query_name if query_name else (query_id if query_id else "CX-KICS-%s" % result_id[:12])

    # Get severity and derive CVSS
    severity = result.get("severity", "")
    base_score = severity_to_cvss(severity)

    cvss_list = []
    if base_score > 0:
        cvss_list.append(pb.CVSS(
            version="3.1",
            vector="",
            base_score=base_score
        ))

    # Get file location
    file_name = result.get("fileName", "")

    description = result.get("description", "")
    if not description:
        description = query_name

    # Create vulnerability
    vulnerability = pb.Vulnerability(
        instance_id=project_id,
        cve=cve,
        description=description,
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.FILE,
            product=file_name,
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion="Review and fix the infrastructure configuration issue",
            source="Checkmarx KICS"
        ),
        cwe_ids=[]
    )

    zafran.collect_vulnerability(vulnerability)


def process_apisec_vulnerability(result, project_id, pb):
    """
    Convert a Checkmarx API Security result to a vulnerability object
    """
    # APISec results may not have 'id' field - use similarityID or resultHash as fallback
    result_id = result.get("id", "")
    if not result_id:
        result_id = str(result.get("similarityID", ""))
    if not result_id:
        result_id = result.get("resultHash", "")
    if not result_id:
        # Skip results without any identifier
        return

    # API Security vulnerabilities - use risk name or ID as CVE identifier
    risk_id = result.get("riskId", "")
    risk_name = result.get("riskName", "")
    cve = risk_name if risk_name else (risk_id if risk_id else "CX-APISEC-%s" % result_id[:12])

    # Get severity and derive CVSS
    severity = result.get("severity", "")
    base_score = severity_to_cvss(severity)

    cvss_list = []
    if base_score > 0:
        cvss_list.append(pb.CVSS(
            version="3.1",
            vector="",
            base_score=base_score
        ))

    # Get endpoint as component
    endpoint = result.get("endpoint", "")

    description = result.get("description", "")
    if not description:
        description = risk_name

    # Create vulnerability
    vulnerability = pb.Vulnerability(
        instance_id=project_id,
        cve=cve,
        description=description,
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=endpoint,
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion="Review and fix the API security issue",
            source="Checkmarx API Security"
        ),
        cwe_ids=[]
    )

    zafran.collect_vulnerability(vulnerability)


def parse_base_score(score_str):
    """
    Parse base score string to float
    """
    if not score_str:
        return 0.0

    # Handle string or numeric input
    if type(score_str) == "string":
        # Try to convert
        score_str = score_str.strip()
        if not score_str:
            return 0.0
        # Simple float parsing - check if it looks like a valid number
        clean_str = score_str.replace(".", "").replace("-", "")
        if clean_str.isdigit():
            return float(score_str)
        return 0.0
    else:
        if score_str:
            return float(score_str)
        return 0.0


def severity_to_cvss(severity):
    """
    Map Checkmarx severity to approximate CVSS score
    """
    severity_map = {
        "Critical": 9.5,
        "High": 7.5,
        "Medium": 5.5,
        "Low": 2.5,
        "Info": 0.0,
        "Informational": 0.0,
        "None": 0.0,
        "CRITICAL": 9.5,
        "HIGH": 7.5,
        "MEDIUM": 5.5,
        "LOW": 2.5,
        "INFO": 0.0
    }
    return severity_map.get(severity, 5.0)
