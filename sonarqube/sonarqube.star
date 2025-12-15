load('http', 'http')
load('json', 'json')
load('log', 'log')
load('zafran', 'zafran')
load('base64', 'base64')

# Constants
DEFAULT_PAGE_SIZE = 100

def main(**kwargs):
    """
    Main function for SonarQube Cloud integration.
    
    Accepts parameters:
    - api_url: SonarQube Cloud API URL (e.g., api.sonarcloud.io)
    - api_key: Authentication token for SonarQube Cloud
    """
    
    # Get parameters
    api_url = kwargs.get("api_url", "sonarcloud.io")
    api_key = kwargs.get("api_key", "")
    
    if not api_key:
        log.error('api_key parameter is required')
        return
    
    # Ensure api_url has https:// prefix
    if not api_url.startswith("http"):
        api_url = "https://" + api_url
    
    # Get proto types
    pb = zafran.proto_file
    
    log.info("Fetching organizations from SonarQube Cloud...")
    organizations = fetch_organizations(api_url, api_key)
    
    if not organizations:
        log.warn("No organizations found")
        return
    
    log.info("Found %d organizations" % len(organizations))
    
    # Process each organization
    total_projects = 0
    for org in organizations:
        org_key = org.get("key", "")
        org_name = org.get("name", "")
        log.info("Processing organization: %s" % org_name)
        
        projects = fetch_all_projects(api_url, api_key, org_key)
        total_projects += len(projects)
        
        # Process each project
        for project in projects:
            process_project(project, api_url, api_key, pb)
    
    log.info("Completed processing %d projects across all organizations" % total_projects)

def fetch_organizations(api_url, api_key):
    """Fetch organizations for the authenticated user."""
    url = "%s/api/organizations/search?member=true" % api_url
    
    auth_string = base64.encode("%s:" % api_key)
    headers = {
        "Authorization": "Basic %s" % auth_string
    }
    
    response = http.get(url=url, headers=headers)
    
    if response.get("status_code") != 200:
        log.error("Failed to fetch organizations: %d" % response.get("status_code", 0))
        return []
    
    data = json.decode(response.get("body", ""))
    if not data:
        return []
    
    return data.get("organizations", [])

def fetch_all_projects(api_url, api_key, org_key):
    """Fetch all projects from SonarQube Cloud for a specific organization."""
    projects = []
    page = 1
    
    while True:
        url = "%s/api/projects/search?organization=%s&p=%d&ps=%d" % (api_url, org_key, page, DEFAULT_PAGE_SIZE)
        
        auth_string = base64.encode("%s:" % api_key)
        headers = {
            "Authorization": "Basic %s" % auth_string
        }
        
        response = http.get(url=url, headers=headers)
        
        if response.get("status_code") != 200:
            log.error("Failed to fetch projects page %d: %d" % (page, response.get("status_code", 0)))
            break
        
        data = json.decode(response.get("body", ""))
        if not data:
            log.error("Invalid JSON response for projects")
            break
        
        components = data.get("components", [])
        if not components:
            break
        
        projects.extend(components)
        
        # Check if there are more pages
        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if len(projects) >= total:
            break
        
        page += 1
    
    return projects

def process_project(project, api_url, api_key, pb):
    """Process a single project and create instance."""
    
    project_key = project.get("key", "")
    project_name = project.get("name", "")
    
    if not project_key:
        log.warn("Project key not found, skipping")
        return
    
    # Build identifiers
    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.IDENTIFIER_TYPE_UNSPECIFIED,
            value=project_key,
            scanner_type="sonarqube"
        )
    ]
    
    # Build properties
    properties = {}
    
    if project.get("organization"):
        properties["organization"] = pb.InstancePropertyValue(
            value=project.get("organization"),
            type=pb.InstancePropertyType.STRING
        )
    
    if project.get("qualifier"):
        properties["qualifier"] = pb.InstancePropertyValue(
            value=project.get("qualifier"),
            type=pb.InstancePropertyType.STRING
        )
    
    if project.get("visibility"):
        properties["visibility"] = pb.InstancePropertyValue(
            value=project.get("visibility"),
            type=pb.InstancePropertyType.STRING
        )
    
    if project.get("lastAnalysisDate"):
        properties["last_analysis_date"] = pb.InstancePropertyValue(
            value=project.get("lastAnalysisDate"),
            type=pb.InstancePropertyType.STRING
        )
    
    # Create instance
    instance = pb.InstanceData(
        instance_id=project_key,
        name=project_name,
        operating_system="",  # Not applicable for code projects
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=[],
            mac_addresses=[]
        ),
        identifiers=identifiers,
        instance_properties=properties
    )
    
    zafran.collect_instance(instance)
    
    # Fetch and process vulnerabilities for this project
    log.info("Fetching vulnerabilities for project: %s" % project_name)
    process_vulnerabilities(project_key, api_url, api_key, pb)

def process_vulnerabilities(project_key, api_url, api_key, pb):
    """Fetch and process vulnerabilities for a specific project."""
    
    page = 1
    total_vulns = 0
    
    while True:
        # Using hotspots endpoint for security vulnerabilities
        url = "%s/api/hotspots/search?projectKey=%s&p=%d&ps=%d" % (
            api_url, project_key, page, DEFAULT_PAGE_SIZE
        )
        
        auth_string = base64.encode("%s:" % api_key)
        headers = {
            "Authorization": "Basic %s" % auth_string
        }
        
        response = http.get(url=url, headers=headers)
        
        if response.get("status_code") != 200:
            log.error("Failed to fetch vulnerabilities for %s: %d" % (
                project_key, response.get("status_code", 0)
            ))
            break
        
        data = json.decode(response.get("body", ""))
        if not data:
            break
        
        hotspots = data.get("hotspots", [])
        
        for hotspot in hotspots:
            process_hotspot(hotspot, project_key, pb)
            total_vulns += 1
        
        # Check if there are more pages
        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if (page * DEFAULT_PAGE_SIZE) >= total:
            break
        
        page += 1
    
    # Also check for issues of type VULNERABILITY
    fetch_vulnerability_issues(project_key, api_url, api_key, pb)
    
    if total_vulns > 0:
        log.info("Found %d vulnerabilities for project %s" % (total_vulns, project_key))

def fetch_vulnerability_issues(project_key, api_url, api_key, pb):
    """Fetch issues of type VULNERABILITY."""
    
    page = 1
    
    while True:
        url = "%s/api/issues/search?componentKeys=%s&types=VULNERABILITY&p=%d&ps=%d" % (
            api_url, project_key, page, DEFAULT_PAGE_SIZE
        )
        
        auth_string = base64.encode("%s:" % api_key)
        headers = {
            "Authorization": "Basic %s" % auth_string
        }
        
        response = http.get(url=url, headers=headers)
        
        if response.get("status_code") != 200:
            # Issues API might not be available for all projects
            break
        
        data = json.decode(response.get("body", ""))
        if not data:
            break
        
        issues = data.get("issues", [])
        
        for issue in issues:
            process_vulnerability_issue(issue, project_key, pb)
        
        # Check if there are more pages
        paging = data.get("paging", {})
        total = paging.get("total", 0)
        if (page * DEFAULT_PAGE_SIZE) >= total:
            break
        
        page += 1

def process_hotspot(hotspot, project_key, pb):
    """Process a security hotspot as a vulnerability."""
    
    # Extract relevant information
    vulnerability_key = hotspot.get("key", "")
    message = hotspot.get("message", "")
    security_category = hotspot.get("securityCategory", "")
    vulnerability_probability = hotspot.get("vulnerabilityProbability", "")
    
    if not vulnerability_key:
        return
    
    # Map security category to a generic CVE pattern
    cve = "SONAR-%s" % vulnerability_key
    
    # Determine severity/score based on vulnerability probability
    score_map = {
        "HIGH": 8.0,
        "MEDIUM": 5.0,
        "LOW": 3.0
    }
    base_score = score_map.get(vulnerability_probability, 5.0)
    
    # Create CVSS
    cvss_list = [
        pb.CVSS(
            version="3.1",
            base_score=base_score
        )
    ]
    
    # Create vulnerability
    vuln = pb.Vulnerability(
        instance_id=project_key,
        cve=cve,
        description=message,
        in_runtime=False,  # Static analysis findings
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=project_key,
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion="Review and fix the security hotspot: %s" % security_category,
            source="SonarQube Cloud"
        )
    )
    
    zafran.collect_vulnerability(vuln)

def process_vulnerability_issue(issue, project_key, pb):
    """Process a vulnerability issue."""
    
    # Extract relevant information
    issue_key = issue.get("key", "")
    message = issue.get("message", "")
    severity = issue.get("severity", "")
    rule = issue.get("rule", "")
    
    if not issue_key:
        return
    
    # Create a unique identifier
    cve = "SONAR-%s" % issue_key
    
    # Map severity to score
    score_map = {
        "BLOCKER": 9.0,
        "CRITICAL": 8.0,
        "MAJOR": 6.0,
        "MINOR": 3.0,
        "INFO": 1.0
    }
    base_score = score_map.get(severity, 5.0)
    
    # Create CVSS
    cvss_list = [
        pb.CVSS(
            version="3.1",
            base_score=base_score
        )
    ]
    
    # Extract component info from issue
    component = issue.get("component", project_key)
    
    # Create vulnerability
    vuln = pb.Vulnerability(
        instance_id=project_key,
        cve=cve,
        description="%s (Rule: %s)" % (message, rule),
        in_runtime=False,  # Static analysis findings
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=component,
            vendor="",
            version=""
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion="Fix the issue as suggested by SonarQube rule %s" % rule,
            source="SonarQube Cloud"
        )
    )
    
    zafran.collect_vulnerability(vuln)