load('http', http_post='post', http_get='get', 'url_encode')
load('json', 'json')
load('time', 'time')
load('zafran', 'zafran')
load('log', 'log')


def build_query_string(params):
    """
    Build a URL query string from a dictionary of parameters.
    
    Args:
        params: Dictionary of key-value pairs
    
    Returns:
        URL-encoded query string (e.g., "key1=value1&key2=value2")
    """
    if not params:
        return ""
    
    param_parts = []
    for key, value in params.items():
        # Handle list values (like executions_ids: [id1, id2])
        if type(value) == "list":
            for item in value:
                param_parts.append("%s=%s" % (url_encode(str(key)), url_encode(str(item))))
        else:
            param_parts.append("%s=%s" % (url_encode(str(key)), url_encode(str(value))))
    
    return "&".join(param_parts)


def sleep(seconds):
    """
    Custom sleep function using time.now() and time.parse_duration().
    
    Args:
        seconds: Number of seconds to sleep
    """
    # Parse duration string (e.g., "300s" for 300 seconds)
    duration = time.parse_duration("%ds" % seconds)
    # Calculate target wake time
    target_time = time.now() + duration
    
    # Busy-wait until we reach the target time
    while time.now() < target_time:
        pass  # Keep looping until time is up


def http_post_request(api_endpoint_url, body=None, headers=None, client_id=None, client_secret=None, cycode_url=None):
    """ Send a POST request to url with body """
    # Refresh token
    token = get_token(client_id, client_secret, cycode_url)

    headers = headers or {}
    headers["Authorization"] = "Bearer %s" % token

    # JSON-encode body if it's a dictionary
    if body and type(body) == "dict":
        body = json.encode(body)

    response = http_post(url=api_endpoint_url, headers=headers, body=body)

    return response


def http_get_request(api_endpoint_url, headers=None, client_id=None, client_secret=None, cycode_url=None):
    """ Send a GET request to url (GET requests don't have bodies) """
    # Refresh token
    token = get_token(client_id, client_secret, cycode_url)

    headers = headers or {}
    headers["Authorization"] = "Bearer %s" % token

    # GET requests don't have a body parameter
    response = http_get(url=api_endpoint_url, headers=headers)

    return response


def get_token(client_id, client_secret, cycode_url):
    """Obtain authentication token from Cycode API.
    
    Args:
        client_id: The Cycode client ID
        client_secret: The Cycode client secret
        cycode_url: The base URL for the Cycode API
    
    Returns:
        token: The authentication token, or None if failed
    """
    endpoint = "%s/api/v1/auth/api-token" % cycode_url
    
    # Trim whitespace from credentials
    client_id = client_id.strip() if client_id else ""
    client_secret = client_secret.strip() if client_secret else ""
    
    payload = {
        "clientId": client_id,
        "secret": client_secret
    }
    
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Convert payload to JSON string
    body = json.encode(payload)
        
    # Make the POST request
    resp = http_post(endpoint, headers=headers, body=body)
    
    if resp.get("status_code") != 200:
        log.error("Failed to retrieve token. Status code: %d" % resp.get("status_code", 0))
        log.error("Response body: %s" % resp.get("body", ""))
        return None
    
    # Parse the response
    body_json = json.decode(resp.get("body", ""))
    if not body_json:
        log.error("Invalid JSON response for token")
        return None
    
    token = body_json.get('token')
    if not token:
        log.error("Token not found in response")
        return None
    
    log.info("Successfully obtained authentication token")
    return token


def get_thirty_days_ago():
    """
    Get the date 30 days ago in ISO format.
    
    Returns:
        String in format "YYYY-MM-DDT00:00:00Z"
    """
    # Create a duration of -30 days (in hours: 30 * 24 = 720 hours)
    duration_str = "-%dh" % (30 * 24)
    ago_duration = time.parse_duration(duration_str)
    
    # Get the time 30 days ago
    thirty_days_ago = time.now() + ago_duration
    
    # Format as "YYYY-MM-DDT00:00:00Z"
    # str(time) gives us something like "2025-11-16 15:30:00 +0000 UTC"
    # We take first 10 chars for "YYYY-MM-DD" and append "T00:00:00Z"
    thirty_days_ago_str = str(thirty_days_ago)[:10] + "T00:00:00Z"
    
    return thirty_days_ago_str


def get_repo_and_container_image_queries():
    thirty_days_ago_str = get_thirty_days_ago()
    container_image_query = {
    "output_format": "Json",
    "graph_query_entity": {
        "query": {
            "connections": [],
            "exists": True,
            "is_optional": False,
            "resource_type": "detection",
            "edge_type": "",
            "filters": [
                {
                    "mode": "And",
                    "filters": [
                        {
                            "name": "status",
                            "operator": "Eq",
                            "value": "Open",
                            "type": "List"
                        },
                        {
                            "name": "updated_date",
                            "operator": "Gte",
                            "value": thirty_days_ago_str,
                            "type": "DateTime"
                        },
                        {
                            "name": "source_policy_type",
                            "operator": "Eq",
                            "value": "SCA",
                            "type": "String"
                        },
                        {
                            "name": "source_entity_type",
                            "operator": "Eq",
                            "value": "ContainerImageTag",
                            "type": "String"
                        }
                    ]
                }
            ],
            "variables": [],
            "edge_filters": [],
            "edge_columns": [],
            "parent_resource_type": "",
            "sort_by": "_key",
            "sort_order": "Asc",
            "limit": -1
        },
        "output_fields": {
            "columns": [
               {
                    "value": "source_policy_name",
                    "type": "String",
                    "label": "Source Policy Name"
                },
                {
                    "value": "severity",
                    "type": "List",
                    "label": "Severity"
                },
                {
                    "value": "updated_date",
                    "type": "DateTime",
                    "label": "Updated At"
                },
                {
                    "value": "created_date",
                    "type": "DateTime",
                    "label": "Detected At"
                },
                {
                    "value": "correlation_message",
                    "type": "String",
                    "label": "Correlation Message"
                },
                {
                    "value": "detection_timestamp",
                    "type": "DateTime",
                    "label": "Violation Timestamp"
                },
                {
                    "value": "id",
                    "type": "String",
                    "label": "ID"
                },
                {
                    "value": "labels",
                    "type": "Array",
                    "label": "Labels"
                },
                {
                    "value": "remediable",
                    "type": "Boolean",
                    "label": "Remediable"
                },
                {
                    "value": "source_entity_name",
                    "type": "String",
                    "label": "Source Entity Name"
                },
                 {
                    "value": "source_policy_id",
                    "type": "String",
                    "label": "Source Policy ID"
                },
                {
                    "value": "sub_category_v2",
                    "type": "String",
                    "label": "SubCategory"
                },
                {
                    "value": "detection_details.organization_name",
                    "type": "String",
                    "label": "Organization name"
                },
                {
                    "value": "detection_details.repository_name",
                    "type": "String",
                    "label": "Repository name"
                },
                {
                    "value": "detection_details.file_name",
                    "type": "String",
                    "label": "File name"
                },
                {
                    "value": "detection_details.branch_name",
                    "type": "String",
                    "label": "Branch name"
                },
                {
                    "value": "detection_details.package_name",
                    "type": "String",
                    "label": "Package name"
                },
                {
                    "value": "detection_details.package_version",
                    "type": "String",
                    "label": "Package version"
                },
                {
                    "value": "detection_details.vulnerability_id",
                    "type": "String",
                    "label": "Vulnerability ID"
                },
                {
                    "value": "detection_details.cvss_score",
                    "type": "String",
                    "label": "Cvss score"
                },
                {
                    "value": "detection_details.vulnerable_component",
                    "type": "String",
                    "label": "Vulnerable component"
                },
                {
                    "value": "source_policy_type",
                    "type": "String",
                    "label": "Source Policy Type"
                },
                {
                    "value": "source_entity_type",
                    "type": "String",
                    "label": "Source Entity Type"
                },
                {
                    "value": "detection_details.container_image_name",
                    "type": "String",
                    "label": "Container image name"
                },
            ],
            "edge_columns": [],
            "connections": []
        }
    },
    "parameters": {
        "name": "My Open Violations Report"
    }
    }

    repo_query = {
    "output_format": "Json",
    "graph_query_entity": {
        "query": {
            "connections": [],
            "exists": True,
            "is_optional": False,
            "resource_type": "detection",
            "edge_type": "",
            "filters": [
                {
                    "mode": "And",
                    "filters": [
                        {
                            "name": "status",
                            "operator": "Eq",
                            "value": "Open",
                            "type": "List"
                        },
                        {
                            "name": "updated_date",
                            "operator": "Gte",
                            "value": thirty_days_ago_str,
                            "type": "DateTime"
                        },
                        {
                            "name": "source_policy_type",
                            "operator": "Eq",
                            "value": "SCA",
                            "type": "String"
                        },
                        {
                            "name": "source_entity_type",
                            "operator": "Eq",
                            "value": "Repository",
                            "type": "String"
                        },
                    ]
                }
            ],
            "variables": [],
            "edge_filters": [],
            "edge_columns": [],
            "parent_resource_type": "",
            "sort_by": "_key",
            "sort_order": "Asc",
            "limit": -1
        },
        "output_fields": {
            "columns": [
               {
                    "value": "source_policy_name",
                    "type": "String",
                    "label": "Source Policy Name"
                },
                {
                    "value": "severity",
                    "type": "List",
                    "label": "Severity"
                },
                {
                    "value": "updated_date",
                    "type": "DateTime",
                    "label": "Updated At"
                },
                {
                    "value": "created_date",
                    "type": "DateTime",
                    "label": "Detected At"
                },
                {
                    "value": "correlation_message",
                    "type": "String",
                    "label": "Correlation Message"
                },
                {
                    "value": "detection_timestamp",
                    "type": "DateTime",
                    "label": "Violation Timestamp"
                },
                {
                    "value": "id",
                    "type": "String",
                    "label": "ID"
                },
                {
                    "value": "labels",
                    "type": "Array",
                    "label": "Labels"
                },
                {
                    "value": "remediable",
                    "type": "Boolean",
                    "label": "Remediable"
                },
                {
                    "value": "source_entity_name",
                    "type": "String",
                    "label": "Source Entity Name"
                },
                 {
                    "value": "source_policy_id",
                    "type": "String",
                    "label": "Source Policy ID"
                },
                {
                    "value": "sub_category_v2",
                    "type": "String",
                    "label": "SubCategory"
                },
                {
                    "value": "detection_details.organization_name",
                    "type": "String",
                    "label": "Organization name"
                },
                {
                    "value": "detection_details.repository_name",
                    "type": "String",
                    "label": "Repository name"
                },
                {
                    "value": "detection_details.file_name",
                    "type": "String",
                    "label": "File name"
                },
                {
                    "value": "detection_details.branch_name",
                    "type": "String",
                    "label": "Branch name"
                },
                {
                    "value": "detection_details.package_name",
                    "type": "String",
                    "label": "Package name"
                },
                {
                    "value": "detection_details.package_version",
                    "type": "String",
                    "label": "Package version"
                },
                {
                    "value": "detection_details.vulnerability_id",
                    "type": "String",
                    "label": "Vulnerability ID"
                },
                {
                    "value": "detection_details.cvss_score",
                    "type": "String",
                    "label": "Cvss score"
                },
                {
                    "value": "detection_details.vulnerable_component",
                    "type": "String",
                    "label": "Vulnerable component"
                },
                {
                    "value": "source_policy_type",
                    "type": "String",
                    "label": "Source Policy Type"
                },
                {
                    "value": "source_entity_type",
                    "type": "String",
                    "label": "Source Entity Type"
                },
                {
                    "value": "detection_details.container_image_name",
                    "type": "String",
                    "label": "Container image name"
                },
            ],
            "edge_columns": [],
            "connections": []
        }
    },
    "parameters": {
        "name": "My Open Violations Report"
    }
    }

    return repo_query, container_image_query


def get_report_results(report_path, headers, client_id, client_secret, cycode_url):
    download_report_url = "%s/files/api/v1/file/reports/%s" % (cycode_url, report_path)
    response = http_get_request(download_report_url, headers=headers, client_id=client_id, client_secret=client_secret, cycode_url=cycode_url)
    
    if response.get("status_code") != 200:
        log.info("Got error %s, exiting" % response.get("status_code"))
        return

    # Decode JSON string to dict
    body_json = json.decode(response.get("body", ""))
    return body_json


def execute_violations_report(headers, query, client_id, client_secret, cycode_url):
    """
    Starts a standalone report execution for violations.
    Replace the graph_query_entity contents with your Cycode KG query.
    """
    standalone_execution_url = "%s/v4/reports/standalone-execute" % cycode_url
    response = http_post_request(standalone_execution_url, query, headers, client_id, client_secret, cycode_url)

    if response.get("status_code") < 200 or response.get("status_code") >= 300:
        log.info("Got error %s, exiting" % response.get("status_code"))
        return

    # Decode JSON string to dict
    response_json = json.decode(response.get("body", ""))

    if response_json:
        executions = response_json.get("report_executions")
        if executions:
            if "id" in executions[0]:
                execution_id = executions[0]["id"]
                return execution_id
        
    log.info("Did not get executions")
    log.info("Response is: %s" % response)
    return 


def poll_until_complete(headers, execution_id, client_id, client_secret, cycode_url):
    """
    Polls executions until a Completed status appears.
    """
    base_url = "%s/v4/reports/executions" % cycode_url
    
    # Build query parameters
    poll_params = {
        "executions_ids": [execution_id],
        "include_orphan_executions": True
    }
    query_string = build_query_string(poll_params)
    poll_execution_url = "%s?%s" % (base_url, query_string)
    
    while True:
        response = http_get_request(poll_execution_url, headers, client_id, client_secret, cycode_url)
        if response.get("status_code") != 200:
            log.info("Got error %s, trying again" % response.get("status_code"))
            continue

        # Decode JSON string to dict
        log.info("json decoding response body")
        response_json = json.decode(response.get("body", ""))
        for execution in response_json:
            if execution["id"] == execution_id and execution["status"] == "Completed":
                return execution

        log.info("No completed executions yet, waiting 300s...")
        sleep(300)


def create_zafran_instance(pb, instance_name, instance_id):
    """Process a computer asset and create instance."""
    
    if not instance_id:
        log.warn("Instance ID not found")
        return
    
    # Build identifiers list
    identifiers = []
    identifiers.append(pb.InstanceIdentifier(
        key=pb.IdentifierType.IDENTIFIER_TYPE_UNSPECIFIED,
        value=instance_id
    ))
    
    # Create instance 
    instance = pb.InstanceData(
        instance_id=instance_id,
        name=instance_name,
        identifiers=identifiers,
    )
    
    return instance


def create_zafran_vulnerability(pb, instance_id, cve_id, component_name, component_version):
    """Build a single vulnerability object from an item."""

    # Build vulnerability using proto constructors
    vulnerability = pb.Vulnerability(
        instance_id=instance_id,
        cve=cve_id,
        description="",
        in_runtime=False,
        component=pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=component_name,
            version=component_version
        )
    )

    return vulnerability


def get_instance_id_to_vuln_data_and_instance_jsons(pb, all_results):
    # Use a dict as a "set" of created instance IDs and vulnerability keys
    instance_ids_created = {}
    vulnerabilities_created = {}
    all_instances = []
    all_vulnerabilities = []

    for item in all_results:
        cve_id = item["detection_detection_details.vulnerability_id"]
        if not cve_id:
            continue

        source_type = item["detection_source_entity_type"]
        if source_type == "ContainerImageTag":
            instance_id = item["detection_detection_details.container_image_name"]
            image_name = item["detection_detection_details.container_image_name"]
            new_instance = create_zafran_instance(pb, image_name, instance_id)
        elif source_type == "Repository":
            instance_id = item["detection_detection_details.repository_name"]
            instance_name = item["detection_detection_details.repository_name"]
            new_instance = create_zafran_instance(pb, instance_name, instance_id)
        else:
            instance_id = None
            new_instance = {}

        if not instance_id:
            print("item has no instance: %s" % item)
            continue

        package_name = item["detection_detection_details.package_name"]
        if not package_name:
            package_name = item["detection_detection_details.vulnerable_component"]
        package_version = item["detection_detection_details.package_version"]

        # Create a unique key for this vulnerability
        # A vulnerability is unique by: instance_id + cve_id + package_name + package_version
        vuln_key = "%s_%s_%s_%s" % (instance_id, cve_id, package_name or "", package_version or "")

        # Only add vulnerability if not already created
        if vuln_key not in vulnerabilities_created:
            vulnerabilities_created[vuln_key] = True
            
            vulnerability = create_zafran_vulnerability(
                pb,
                instance_id,
                cve_id,
                package_name,
                package_version,
            )
            
            all_vulnerabilities.append(vulnerability)

        # Only add instance json if not already created
        if instance_id not in instance_ids_created:
            instance_ids_created[instance_id] = True
            all_instances.append(new_instance)

    return all_instances, all_vulnerabilities


def main(**kwargs):
    """Main entry point for the Cycode integration.
    
    Required parameters:
    - cycode_url: The base URL of your Cycode instance (e.g., "https://api.cycode.com")
    - client_id: The OAuth2 client ID for API authentication
    - client_secret: The OAuth2 client secret for API authentication
    """

    pb = zafran.proto_file
    # Get parameters
    cycode_url = kwargs.get('api_url', '').rstrip('/')
    client_id = kwargs.get('api_key', '')
    client_secret = kwargs.get('api_secret', '')
    
    # Validate parameters
    if not cycode_url:
        log.error('cycode_url parameter is required')
        return
    
    if not client_id or not client_secret:
        log.error('api_key (client ID) and api_secret (client secret) parameters are required')
        return
    
    # Authenticate and get token
    log.info("Authenticating with Cycode API...")
    token = get_token(client_id, client_secret, cycode_url)
    
    if not token:
        log.error("Failed to obtain authentication token")
        return
    
    log.info("Authentication successful!")

    headers = {
        "Authorization": "Bearer %s" % token,
        "X-Tenant-Id": client_id,
        "Content-Type": "application/json",
        "Accept": "application/json"
    }
    
    # Get queries for API
    repo_query, container_image_query = get_repo_and_container_image_queries()
    log.info("Got repo_query and container_image_query")

    # Execute queries and get execution IDs
    repo_execution_id = execute_violations_report(headers, repo_query, client_id, client_secret, cycode_url)
    # Wait ten seconds between executions
    log.info("Sleeping 10 seconds for repo execution to register")
    sleep(10)
    container_image_execution_id = execute_violations_report(headers, container_image_query, client_id, client_secret, cycode_url)
    # Wait ten seconds between executions
    log.info("Sleeping 10 seconds for container image execution to register")
    sleep(10)

    # Poll executions until complete
    container_image_execution = poll_until_complete(headers, container_image_execution_id, client_id, client_secret, cycode_url)
    log.info("Container image execution complete")
    repo_execution = poll_until_complete(headers, repo_execution_id, client_id, client_secret, cycode_url)
    log.info("Repo execution complete")

    # Get report paths
    container_image_report_path = container_image_execution["storage_details"]["path"]
    repo_report_path = repo_execution["storage_details"]["path"]

    # Get report results
    container_image_results = get_report_results(container_image_report_path, headers, client_id, client_secret, cycode_url)
    repo_results = get_report_results(repo_report_path, headers, client_id, client_secret, cycode_url)

    all_results = container_image_results + repo_results

    log.info("Creating instances and vulnerabilities from results")
    all_instances, all_vulnerabilities = get_instance_id_to_vuln_data_and_instance_jsons(pb, all_results)

    log.info("Created %s instances and %s vulnerabilities" % (len(all_instances), len(all_vulnerabilities)))
    log.info("Collect instances and vulnerabilities")

    for instance in all_instances:
        zafran.collect_instance(instance)

    for vulnerability in all_vulnerabilities:
        zafran.collect_vulnerability(vulnerability)

    log.info("Done!")