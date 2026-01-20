# Example Starlark integration script
# This demonstrates how to collect instances and vulnerabilities using the proto API
#
# Structure:
#   - main: Entry point that orchestrates the integration
#   - get_bearer_token: (Optional) Gets a bearer token from OAuth endpoint
#   - fetch_paginated: Helper to fetch data with pagination support
#   - fetch_instances: Fetches raw instance/asset data from the API
#   - fetch_vulnerabilities: Fetches raw vulnerability data from the API
#   - parse_to_instance: Transforms raw asset data into InstanceData proto
#   - parse_to_finding: Transforms raw vulnerability data into Vulnerability proto
#
# Data Collection:
#   - Use zafran.collect_instance() and zafran.collect_vulnerability() to collect data
#   - Use zafran.flush() to send collected data mid-execution (useful for large datasets)
#   - Any unflushed data is automatically sent when the script completes

load("http", "http")
load("json", "json")
load("log", "log")
load("zafran", "zafran")

def main(**kwargs):
    """
    Main function for the integration.

    Accepts parameters:
    - api_url: Base URL of the API
    - api_key: API authentication key (used directly or for token exchange)
    - api_secret: API secret (optional, for OAuth token exchange)
    - use_oauth: Set to "true" to use OAuth token exchange (optional)
    - page_size: Number of items per page for pagination (optional, default 100)
    """

    # Get parameters with defaults
    api_url = kwargs.get("api_url", "https://api.example.com")
    api_key = kwargs.get("api_key", "")
    api_secret = kwargs.get("api_secret", "")
    use_oauth = kwargs.get("use_oauth", "false")
    page_size = int(kwargs.get("page_size", "100"))

    log.info("Starting integration with API:", api_url)

    # Get proto types from zafran
    pb = zafran.proto_file

    # Step 0: Get bearer token (optional)
    bearer_token = api_key
    if use_oauth == "true":
        log.info("Step 0: Getting bearer token via OAuth...")
        bearer_token = get_bearer_token(api_url, api_key, api_secret)
        if not bearer_token:
            log.error("Failed to get bearer token")
            return None
        log.info("Successfully obtained bearer token")

    # Step 1: Fetch instances from API
    log.info("Step 1: Fetching instances...")
    raw_instances = fetch_instances(api_url, bearer_token, page_size)

    if not raw_instances:
        log.error("No instances found")
        return None

    log.info("Found %d instances" % len(raw_instances))

    # Step 2: Parse and collect instances
    log.info("Step 2: Parsing and collecting instances...")
    for raw_instance in raw_instances:
        instance = parse_to_instance(raw_instance, pb)
        if instance:
            zafran.collect_instance(instance)
            log.info("Collected instance:", instance.name)

    # Step 3: Fetch and collect vulnerabilities for each instance
    # Note: We collect vulns with their instances before flushing to ensure
    # vulnerabilities are associated with their instances
    log.info("Step 3: Fetching vulnerabilities...")
    raw_vulnerabilities = fetch_vulnerabilities(api_url, bearer_token, page_size)

    if not raw_vulnerabilities:
        log.info("No vulnerabilities found")
        return None

    log.info("Found %d vulnerabilities" % len(raw_vulnerabilities))

    # Step 4: Parse and collect vulnerabilities
    log.info("Step 4: Parsing and collecting vulnerabilities...")
    for raw_vuln in raw_vulnerabilities:
        vulnerability = parse_to_finding(raw_vuln, pb)
        if vulnerability:
            zafran.collect_vulnerability(vulnerability)
            log.info("Collected vulnerability:", vulnerability.cve)

    # Step 5: Flush collected data
    # This sends all instances and vulnerabilities to Zafran.
    # For small datasets, you can skip this - data is auto-flushed when the script ends.
    # For large datasets or paginated APIs, call flush() periodically to avoid memory buildup.
    log.info("Step 5: Flushing collected data...")
    zafran.flush()

    log.info("Integration completed successfully")
    return None


def get_bearer_token(api_url, client_id, client_secret):
    """
    (Optional) Get a bearer token from an OAuth endpoint.

    This function exchanges client credentials for an access token.
    Modify the endpoint and payload based on your API's OAuth implementation.

    Args:
        api_url: Base URL of the API
        client_id: OAuth client ID (often the api_key)
        client_secret: OAuth client secret

    Returns:
        Bearer token string, or None if failed
    """
    # Build token endpoint URL
    token_url = api_url.rstrip("/") + "/oauth/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }

    # OAuth client credentials grant payload
    payload = "grant_type=client_credentials&client_id=%s&client_secret=%s" % (client_id, client_secret)

    # Make token request
    # response = http.post(token_url, headers=headers, body=payload)
    #
    # if response["status_code"] != 200:
    #     log.error("Failed to get token:", response["status_code"])
    #     log.error("Response:", response["body"][:500])
    #     return None
    #
    # token_data = json.decode(response["body"])
    # return token_data.get("access_token", "")

    # Mock token for example purposes
    log.info("(Mock) Would request token from:", token_url)
    return "mock-bearer-token-12345"


def fetch_paginated(url, bearer_token, page_size=100, items_key="items", total_key="total"):
    """
    Fetch all data from a paginated API endpoint.

    Supports common pagination patterns:
    - offset/limit based pagination
    - Automatically fetches all pages until no more data

    Args:
        url: API endpoint URL (without pagination params)
        bearer_token: Bearer token for authentication
        page_size: Number of items per page (default 100)
        items_key: Key in response containing the items array (default "items")
        total_key: Key in response containing total count (default "total")

    Returns:
        List of all items across all pages
    """
    headers = {
        "Authorization": "Bearer " + bearer_token,
        "Content-Type": "application/json"
    }

    all_items = []
    offset = 0

    while True:
        # Build paginated URL
        separator = "&" if "?" in url else "?"
        paginated_url = "%s%soffset=%d&limit=%d" % (url, separator, offset, page_size)

        log.info("Fetching page (offset=%d, limit=%d)" % (offset, page_size))

        # Make API request
        response = http.get(paginated_url, headers=headers)

        if response["status_code"] != 200:
            log.error("Failed to fetch page:", response["status_code"])
            log.error("Response:", response["body"][:500])
            break

        data = json.decode(response["body"])

        # Extract items from response
        # Handle both nested ({"items": [...]}) and flat ([...]) responses
        if type(data) == "list":
            items = data
        else:
            items = data.get(items_key, [])

        if not items:
            log.info("No more items to fetch")
            break

        all_items.extend(items)
        log.info("Fetched %d items (total so far: %d)" % (len(items), len(all_items)))

        # Check if we've fetched all items
        if len(items) < page_size:
            log.info("Received fewer items than page_size, done fetching")
            break

        # Check against total count if available
        if type(data) != "list":
            total_count = data.get(total_key, 0)
            if total_count > 0 and len(all_items) >= total_count:
                log.info("Fetched all %d items" % total_count)
                break

        offset += page_size

    return all_items


def fetch_instances(api_url, bearer_token, page_size=100):
    """
    Fetch raw instance/asset data from the API.

    Args:
        api_url: Base URL of the API
        bearer_token: Bearer token for authentication
        page_size: Number of items per page for pagination

    Returns:
        List of raw instance dicts from the API
    """
    # Build request URL
    url = api_url.rstrip("/") + "/assets"

    # Use paginated fetch for real API calls
    # return fetch_paginated(url, bearer_token, page_size, items_key="assets")

    # Mock data for example purposes
    log.info("(Mock) Would fetch instances from:", url)
    return [
        {
            "id": "server-001",
            "name": "web-server-01",
            "os": "Ubuntu 22.04",
            "ips": ["192.168.1.100", "10.0.0.50"],
            "macs": ["00:11:22:33:44:55"],
            "environment": "production",
            "labels": ["critical", "web-tier"]
        },
        {
            "id": "server-002",
            "name": "db-server-01",
            "os": "CentOS 8",
            "ips": ["192.168.1.101"],
            "macs": ["00:11:22:33:44:66"],
            "environment": "staging",
            "labels": ["database"]
        }
    ]


def fetch_vulnerabilities(api_url, bearer_token, page_size=100):
    """
    Fetch raw vulnerability data from the API.

    Args:
        api_url: Base URL of the API
        bearer_token: Bearer token for authentication
        page_size: Number of items per page for pagination

    Returns:
        List of raw vulnerability dicts from the API
    """
    # Build request URL
    url = api_url.rstrip("/") + "/vulnerabilities"

    # Use paginated fetch for real API calls
    # return fetch_paginated(url, bearer_token, page_size, items_key="vulnerabilities")

    # Mock data for example purposes
    log.info("(Mock) Would fetch vulnerabilities from:", url)
    return [
        {
            "id": "vuln-001",
            "cve": "CVE-2023-1234",
            "description": "Critical vulnerability in OpenSSL",
            "asset_id": "server-001",
            "product": "openssl",
            "vendor": "openssl",
            "version": "1.1.1",
            "score": 9.8,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "fix": "Update to OpenSSL 1.1.1k or later"
        },
        {
            "id": "vuln-002",
            "cve": "CVE-2023-5678",
            "description": "SQL injection vulnerability in MySQL",
            "asset_id": "server-002",
            "product": "mysql",
            "vendor": "oracle",
            "version": "8.0.25",
            "score": 7.5,
            "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "fix": "Update to MySQL 8.0.28 or later"
        }
    ]


def parse_to_instance(raw_instance, pb):
    """
    Parse raw asset data into an InstanceData proto message.

    Args:
        raw_instance: Raw instance dict from the API
        pb: Proto types from zafran.proto_file

    Returns:
        InstanceData proto message
    """
    instance_id = raw_instance.get("id", "")
    if not instance_id:
        log.warn("Instance missing ID, skipping")
        return None

    # Extract fields from raw data
    name = raw_instance.get("name", "")
    os = raw_instance.get("os", "")
    ips = raw_instance.get("ips", [])
    macs = raw_instance.get("macs", [])

    # Build identifiers list
    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.LINUX_UUID,
            value=instance_id
        )
    ]

    # Tags can be either key-value pairs or simple labels.
    # For key-value tags, the value must not be empty.
    key_value_tags = []
    labels = []

    # Example: Add environment tag from raw data (key-value tag),
    env = raw_instance.get("environment", "")
    if env:  # Only add key-value tag if value is not empty
        key_value_tags=[pb.InstanceTagKeyValue(key="environment", value=env)]

    # Example: Add labels from raw data
    raw_labels = raw_instance.get("labels", [])
    labels = []
    for label in raw_labels:
        if label:  # Only add if label is not empty
            labels.append(pb.InstanceLabel(label=label))

    # Create and return the InstanceData proto
    instance = pb.InstanceData(
        instance_id=instance_id,
        name=name,
        operating_system=os,
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=ips,
            mac_addresses=macs
        ),
        identifiers=identifiers,
        labels=labels,
        key_value_tags=key_value_tags
    )

    return instance


def parse_to_finding(raw_vuln, pb):
    """
    Parse raw vulnerability data into a Vulnerability proto message.

    Args:
        raw_vuln: Raw vulnerability dict from the API
        pb: Proto types from zafran.proto_file

    Returns:
        Vulnerability proto message
    """
    cve = raw_vuln.get("cve", "")
    if not cve:
        log.warn("Vulnerability missing CVE, skipping")
        return None

    # Extract fields from raw data
    instance_id = raw_vuln.get("asset_id", "")
    description = raw_vuln.get("description", "")
    product = raw_vuln.get("product", "")
    vendor = raw_vuln.get("vendor", "")
    version = raw_vuln.get("version", "")
    score = raw_vuln.get("score")
    vector = raw_vuln.get("vector", "")
    fix = raw_vuln.get("fix", "")

    # Build CVSS list
    cvss_list = []
    if score and vector:
        cvss_list.append(pb.CVSS(
            base_score=float(score),
            vector=vector,
            version="3.1"
        ))

    # Create and return the Vulnerability proto
    vulnerability = pb.Vulnerability(
        instance_id=instance_id,
        cve=cve,
        description=description,
        in_runtime=True,
        component=pb.Component(
            product=product,
            vendor=vendor,
            version=version,
            type=pb.ComponentType.LIBRARY
        ),
        CVSS=cvss_list,
        remediation=pb.Remediation(
            suggestion=fix,
            source="Example Scanner"
        )
    )

    return vulnerability
