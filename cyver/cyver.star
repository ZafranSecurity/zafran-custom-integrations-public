# Cyver Integration - Updated version
# Fetches ALL projects and their findings from Cyver API v2.2

load("http", "http")
load("json", "json")
load("log", "log")
load("zafran", "zafran")

def fetch_data(api_url, api_key, params=None):
    """GET data from the API with optional query parameters."""
    # Build URL with query params
    url = api_url
    if params:
        query_parts = []
        for key, value in params.items():
            query_parts.append("%s=%s" % (key, str(value)))
        if query_parts:
            url = url + "?" + "&".join(query_parts)

    headers = {
        "accept": "application/json",
        "X-API-Key": api_key,
        "User-Agent": "curl/8.5.0"
    }

    log.info("Fetching from:", url)
    response = http.get(url, headers=headers)

    if response["status_code"] != 200:
        log.error("HTTP error:", response["status_code"])
        log.error("Response body (first 500 chars):", response["body"][:500])
        return None

    # Check if response is JSON before decoding
    body = response["body"]
    if body.startswith("<"):
        log.error("Received HTML instead of JSON. Response starts with:", body[:200])
        return None

    # Parse JSON from response body
    return json.decode(body)

def fetch_paginated_projects(base_url, api_key, max_result_count=100):
    """
    Fetch all projects using pagination.

    Args:
        base_url: Base API URL
        api_key: API key for authentication
        max_result_count: Items per page (default 100)

    Returns:
        List of all projects
    """
    projects_url = base_url.rstrip("/") + "/v2.2/client/projects"
    all_projects = []
    skip_count = 0

    while True:
        params = {
            "MaxResultCount": max_result_count,
            "SkipCount": skip_count
        }

        log.info("Fetching projects page (skip=%d, max=%d)" % (skip_count, max_result_count))
        data = fetch_data(projects_url, api_key, params)

        if not data:
            log.error("Failed to fetch projects page at skip_count", skip_count)
            break

        # Extract result
        result = data.get("result", {})
        items = result.get("items", [])
        total_count = result.get("totalCount", 0)

        if not items:
            log.info("No more projects to fetch")
            break

        all_projects.extend(items)
        log.info("Fetched %d projects (total so far: %d, API total: %s)" % (len(items), len(all_projects), str(total_count)))

        # Check if we've fetched all
        if len(items) < max_result_count:
            log.info("Received fewer items than max, we're done")
            break

        if total_count > 0 and len(all_projects) >= total_count:
            log.info("Fetched all %d projects" % total_count)
            break

        skip_count += max_result_count

    return all_projects

def fetch_finding_by_id(base_url, api_key, finding_id):
    """
    Fetch a single finding by ID from /client/findings/:id endpoint.

    Args:
        base_url: Base API URL
        api_key: API key
        finding_id: Finding UUID

    Returns:
        Finding dict or None
    """
    finding_url = base_url.rstrip("/") + "/v2.2/client/findings/" + finding_id

    data = fetch_data(finding_url, api_key)

    if not data:
        return None

    # Extract result
    result = data.get("result", {})
    return result

def fetch_all_findings_for_projects(base_url, api_key, projects):
    """
    Fetch all findings for a list of projects using their findingIdList.

    Args:
        base_url: Base API URL
        api_key: API key
        projects: List of project dicts

    Returns:
        Dict mapping project_id -> list of findings
    """
    project_findings = {}
    total_findings = 0

    for project in projects:
        project_id = project.get("id", "")
        project_name = project.get("name", "")
        finding_id_list = project.get("findingIdList", [])

        if not finding_id_list:
            log.info("Project %s has no findings" % project_name)
            project_findings[project_id] = []
            continue

        log.info("Fetching %d findings for project: %s" % (len(finding_id_list), project_name))

        findings = []
        for finding_id in finding_id_list:
            finding = fetch_finding_by_id(base_url, api_key, finding_id)
            if finding:
                findings.append(finding)
                total_findings += 1

                # Log progress every 20 findings
                if total_findings % 20 == 0:
                    log.info("Fetched %d findings so far..." % total_findings)
            else:
                log.warn("Failed to fetch finding ID: %s" % finding_id)

        project_findings[project_id] = findings
        log.info("Fetched %d findings for project %s" % (len(findings), project_name))

    log.info("Fetched total of %d findings across all projects" % total_findings)
    return project_findings

def parse_instance_name_from_project(project_name):
    """
    From projectName take the second part after "-" (per spec) and remove spaces.
    Fallbacks keep things robust if formatting varies.
    """
    if not project_name:
        return ""

    result = ""

    # Prefer splitting on " - " (space-hyphen-space)
    if " - " in project_name:
        parts = project_name.split(" - ")
        if len(parts) >= 2:
            result = parts[1].strip()
    # Fallback: split on the first hyphen if no " - " is present
    elif "-" in project_name:
        parts = project_name.split("-")
        if len(parts) >= 2:
            # Join all parts after first hyphen
            result = "-".join(parts[1:]).strip()
    else:
        # If no hyphen at all, just use the original
        result = project_name.strip()

    # Remove all spaces from the result
    return result.replace(" ", "")

def parse_project_name(project_name):
    """
    From projectName remove spaces, and replace them with "-"
    Fallbacks keep things robust if formatting varies.
    """
    if not project_name:
        return ""

    project_name.replace(" - ", "-")
    project_name.replace(" ", "-")

    return project_name


def create_instance_from_project(project, pb):
    """
    Create an instance from a project object.

    Args:
        project: Project dict from API
        pb: Proto types

    Returns:
        InstanceData proto message
    """
    project_id = project.get("id", "")
    project_name = project.get("name", "")

    if not project_id:
        return None

    # Parse instance name from project name
    instance_name = parse_instance_name_from_project(project_name)
#     instance_name=parse_project_name(project_name)
    if not instance_name:
        instance_name = project_name

    # Build identifiers list
    identifiers = []
    identifiers.append(pb.InstanceIdentifier(
        key=pb.IdentifierType.IDENTIFIER_TYPE_UNSPECIFIED,
        value=project_id
    ))

    # Create instance
    instance = pb.InstanceData(
        instance_id=project_id,
        name=instance_name,
        identifiers=identifiers,
    )

    return instance

def build_vulnerability_item(finding, instance_id, instance_name, pb):
    """Build a single vulnerability object from a finding."""
    cvss = finding.get("cvss", {})
    vector = cvss.get("cvss31Vector", "")
    score = cvss.get("cvss31Score")

    # Ensure cweList is a list (can be empty)
    cwe_list_raw = finding.get("cweList", [])

    # Convert CWE strings ("CWE-799") to integers (799) as required by proto
    cwe_list = []
    for cwe_str in cwe_list_raw:
        if cwe_str and cwe_str.startswith("CWE-"):
            cwe_num = cwe_str[4:]  # Remove "CWE-" prefix
            cwe_list.append(int(cwe_num))

    # Convert score to float if it exists
    base_score = None
    if score != None:
        base_score = float(score)

    # Build CVSS list
    cvss_list = []
    if vector and base_score != None:
        cvss_list.append(pb.CVSS(
            version="3.1",
            vector=vector,
            base_score=base_score
        ))

    # Build description: name + description + impactDescription
    name = finding.get("name", "")
    description = finding.get("description", "")
    impact_description = finding.get("impactDescription", "")

    full_description = name
    if description:
        full_description = full_description + "\n" + description
    if impact_description:
        full_description = full_description + "\n" + impact_description

    cve_id = finding.get("code", "")
    cve_title = finding.get("name", "")
    full_cve = cve_id + " - " + cve_title

    # Build vulnerability using proto constructors
    vulnerability = pb.Vulnerability(
        instance_id=instance_id,
        cve=full_cve,
        description=full_description,
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=instance_name.lower()
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            source="Cyver",
            suggestion=finding.get("recommendation", "")
        ),
        cwe_ids=cwe_list
    )

    return vulnerability

def main(**kwargs):
    """
    Main function for the Cyver integration.

    Standard parameters:
    - api_url: Cyver API URL (e.g., "https://vm.layer8.pt/api")
    - api_key: API authentication key (required)
    - api_secret: API secret (not used by Cyver)

    Additional parameters:
    - limit_projects: Maximum number of projects to process (optional, for testing)
    - page_size: Number of projects per API page (default: 100)
    """

    # Get proto types from zafran
    pb = zafran.proto_file

    # Get standard parameters with defaults
    api_url = kwargs.get("api_url", "")
    api_key = kwargs.get("api_key", "")

    # Get additional parameters
    limit_projects = kwargs.get("limit_projects", "")
    page_size = kwargs.get("page_size", "100")

    if not api_key:
        log.error("API key is required. Pass it via -params 'api_key=YOUR_KEY'")
        return None

    if not api_url:
        log.error("API URL is required. Pass it via -params 'api_url=https://vm.layer8.pt/api'")
        return None

    log.info("=" * 60)
    log.info("Starting Cyver integration")
    log.info("API URL:", api_url)
    log.info("=" * 60)

    # Step 1: Fetch all projects
    log.info("Step 1: Fetching all projects...")
    projects = fetch_paginated_projects(api_url, api_key, int(page_size))

    if not projects:
        log.error("No projects found")
        return None

    log.info("Found %d total projects" % len(projects))

    # Apply limit if specified
    if limit_projects:
        limit_int = int(limit_projects)
        projects = projects[:limit_int]
        log.info("Limited to %d projects for testing" % limit_int)

    # Step 2: Create instances from projects
    log.info("=" * 60)
    log.info("Step 2: Creating instances from projects...")
    project_map = {}  # Map project_id -> project data

    for project in projects:
        project_id = project.get("id", "")
        if not project_id:
            continue

        instance = create_instance_from_project(project, pb)
        if instance:
            zafran.collect_instance(instance)
            project_map[project_id] = project
            log.info("Collected project instance: %s (ID: %s)" % (instance.name, project_id))

    log.info("Collected %d project instances" % len(project_map))

    # Step 3: Fetch ALL findings for each project
    log.info("=" * 60)
    log.info("Step 3: Fetching all findings for each project...")
    project_findings = fetch_all_findings_for_projects(api_url, api_key, projects)

    # Step 4: Create vulnerabilities from findings
    log.info("=" * 60)
    log.info("Step 4: Creating vulnerabilities from findings...")

    total_vulnerabilities = 0

    for project_id, findings in project_findings.items():
        if project_id not in project_map:
            # This shouldn't happen, but handle it gracefully
            log.warn("Found findings for project %s but project not in map" % project_id)
            continue

        project = project_map[project_id]
        project_name = project.get("name", "")
        instance_name = parse_instance_name_from_project(project_name)
#         instance_name=parse_project_name(project_name)
        if not instance_name:
            instance_name = project_name

        log.info("Processing %d findings for project: %s" % (len(findings), project_name))

        for finding in findings:
            # Build and collect vulnerability
            vulnerability = build_vulnerability_item(finding, project_id, instance_name, pb)
            zafran.collect_vulnerability(vulnerability)
            total_vulnerabilities += 1

            if total_vulnerabilities % 50 == 0:
                log.info("Collected %d vulnerabilities so far..." % total_vulnerabilities)

    log.info("Collected total of %d vulnerabilities" % total_vulnerabilities)

    log.info("=" * 60)
    log.info("Cyver integration completed successfully")
    log.info("Total project instances: %d" % len(project_map))
    log.info("=" * 60)

    return None
