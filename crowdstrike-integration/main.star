# Pull assets and vulnerabilities from CrowdStrike into Zafran
#
# Structure:
#   - main: Entry point that orchestrates the integration
#   - get_bearer_token: Gets a bearer token from OAuth2 endpoint
#   - fetch_paginated: Helper to fetch data with scroll pagination
#   - fetch_instances: Fetches raw instance/asset data from the API
#   - fetch_vulnerabilities: Fetches raw vulnerability data from the API
#   - fetch_device_ids: Fetch Device IDs from the API
#   - fetch_device_details: Fetch device details from the API using the device IDs
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
    Main function for the Crowdstrike integration.

    Accepts parameters:
    - api_url: Base URL of the API
    - api_key: OAuth2 Client ID
    - api_secret: OAuth2 Client Secret 
    - page_size: Number of items per page for pagination (optional, default 50)
    """

    # Get parameters with defaults
    api_url = kwargs.get("api_url", "https://api.crowdstrike.com")
    api_key = kwargs.get("api_key", "")
    api_secret = kwargs.get("api_secret", "")
    page_size = int(kwargs.get("page_size", "50"))

    log.info("Starting integration with API:", api_url)

    # Get proto types from zafran
    pb = zafran.proto_file

    # Step 0: Get bearer token
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


    # Step 3: Fetch and collect vulnerabilities
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
    Authenticate with CrowdStrike OAuth2 and return a bearer token.

    Args:
        api_url: CrowdStrike API base URL
        client_id: OAuth2 Client ID
        client_secret: OAuth2 Client Secret

    Returns:
        Bearer token string, or None if failed
    """
    # Build token endpoint URL
    token_url = api_url.rstrip("/") + "/oauth2/token"

    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json"
    }

    # OAuth client credentials grant payload
    payload = "client_id=%s&client_secret=%s" % (client_id, client_secret)

    # Make token request
    response = http.post(token_url, headers=headers, body=payload)
    if response["status_code"] != 201:
        log.error("Failed to get token:", response["status_code"])
        log.error("Response:", response["body"][:500])
        return None
    
    token_data = json.decode(response["body"])
    return token_data.get("access_token", "")


def get_auth_headers(bearer_token):
    """
    Build the authorization headers for API requests.
    """
    return {
        "Authorization": "Bearer " + bearer_token,
        "Content-Type": "application/json"
    }


def fetch_paginated(url, bearer_token, page_size=100, items_key="resources"):
    """
    Fetch all data from a paginated API endpoint using CrowdStrike's
    token-based scroll pagination.

    Args:
        url: API endpoint URL (without pagination params)
        bearer_token: Bearer token for authentication
        page_size: Number of items per page (default 100)
        items_key: Key in response containing the items array (default "resources")

    Returns:
        List of all items across all pages
    """
    headers = get_auth_headers(bearer_token)
    all_items = []
    offset = ""

    while True:
        # Build paginated URL
        separator = "&" if "?" in url else "?"
        paginated_url = url + separator + "limit=%d" % page_size
        if offset:
            paginated_url += "&offset=" + offset

        log.info("Fetching page (offset=%s, limit=%d)" % (offset, page_size))
        # Make API request
        response = http.get(paginated_url, headers=headers)

        if response["status_code"] != 200:
            log.error("Failed to fetch page:", response["status_code"])
            log.error("Response:", response["body"][:500])
            break

        data = json.decode(response["body"])
        items = data.get(items_key, [])
        if not items:
            log.info("No more items to fetch.")
            break

        all_items.extend(items)
        log.info("Fetched %d items (total so far: %d)" % (len(items), len(all_items)))

        # Check if we've fetched all items
        if len(items) < page_size:
            log.info("Received fewer items than page_size, done fetching")
            break

        meta = data.get("meta", {}).get("pagination", {})
        offset = meta.get("offset")
        if not offset:
            break

    return all_items


def fetch_device_ids(api_url, bearer_token, page_size=100):
    """
    Fetch all device IDs from the scroll endpoint.
    """
    scroll_url = api_url.rstrip("/") + "/devices/queries/devices-scroll/v1"
    log.info("Fetch device ids:", scroll_url)
    return fetch_paginated(scroll_url, bearer_token, page_size, items_key="resources")


def fetch_device_details(api_url, bearer_token, device_ids):
    """
    Fetch device objects in batches of 50 given a list of IDs.
    """
    headers = get_auth_headers(bearer_token)
    devices = []
    batch_size = 50

    for i in range(0, len(device_ids), batch_size):
        batch = device_ids[i:i + batch_size]
        ids = "&".join(["ids=" + _id for _id in batch])
        url = api_url + "/devices/entities/devices/v2?" + ids

        response = http.get(url, headers=headers)
        if response["status_code"] != 200:
            log.error("Device details failed:", response["status_code"])
            continue
        
        data = json.decode(response["body"])
        resources = data.get("resources", [])
        devices.extend(resources)
    
    return devices


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
    device_ids = fetch_device_ids(api_url, bearer_token, page_size)
    if not device_ids:
        return []

    log.info("Total device IDs found: %d" % len(device_ids))

    devices = fetch_device_details(api_url, bearer_token, device_ids)
    log.info("Fetched details for %d devices" % len(devices))
    return devices 



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
    headers = get_auth_headers(bearer_token)
    all_vulnerabilites = []
    after = ""

    while True:
        url = api_url.rstrip("/") + "/spotlight/combined/vulnerabilities/v1"
        url += "?filter=status:'open'"
        url += "&facet=host_info"
        url += "&limit=%d" % page_size
        if after:
            url += "&after=" + after

        log.info("Fetching vulnerabilities (after=%s)" % after) 
        response = http.get(url, headers=headers)
        if response["status_code"] != 200:
            log.error("Fetch failed:", response["status_code"])
            log.error("Response:", response["body"][:500])
            break
        
        data = json.decode(response["body"])
        vulnerabilities = data.get("resources", [])
        if not vulnerabilities:
            log.info("No more vulnerabilities to fetch.")
            break

        all_vulnerabilites.extend(vulnerabilities)
        log.info("Vulnerabilities fetched in total %d." % len(all_vulnerabilites))
        if len(vulnerabilities) < page_size:
            break
        
        meta = data.get("meta", {}).get("pagination", {})
        after = meta.get("after")
        if not after:
            break
        
    return all_vulnerabilites


def parse_to_instance(raw_instance, pb):
    """
    Parse a CrowdStrike device into an InstanceData proto.
    """
    instance_id = raw_instance.get("device_id", "")
    if not instance_id:
        log.warn("Instance missing device_id, skipping")
        return None

    # IP addresses
    ip_addresses = []
    if raw_instance.get("local_ip"):
        ip_addresses.append(raw_instance["local_ip"])
    if raw_instance.get("external_ip"):
        ip_addresses.append(raw_instance["external_ip"])

    # MAC addresses
    mac_addresses = []
    if raw_instance.get("mac_address"):
        mac_addresses.append(raw_instance["mac_address"])

    # Operating system
    os_parts = []
    if raw_instance.get("platform_name"):
        os_parts.append(raw_instance["platform_name"])
    if raw_instance.get("os_version"):
        os_parts.append(raw_instance["os_version"])
    os_string = " ".join(os_parts)

    # Key-value tags from CrowdStrike tags (format: "GroupType/Value")
    key_value_tags = []
    for tag in raw_instance.get("tags", []):
        parts = tag.split("/", 1)
        if len(parts) == 2 and parts[1]:
            key_value_tags.append(pb.InstanceTagKeyValue(key=parts[0], value=parts[1]))

    if raw_instance.get("service_provider"):
        key_value_tags.append(pb.InstanceTagKeyValue(key="service_provider", value=raw_instance["service_provider"]))

    # Labels
    labels = []
    if raw_instance.get("product_type_desc"):
        labels.append(pb.InstanceLabel(label=raw_instance["product_type_desc"]))
    if raw_instance.get("platform_name"):
        labels.append(pb.InstanceLabel(label=raw_instance["platform_name"]))

    # Identifiers
    identifiers = [
        pb.InstanceIdentifier(
            key=pb.IdentifierType.CROWDSTRIKE_AID,
            value=instance_id,
        ),
    ]
    if raw_instance.get("serial_number"):
        identifiers.append(pb.InstanceIdentifier(
            key=pb.IdentifierType.SERIAL_NUMBER,
            value=raw_instance["serial_number"],
        ))
    if raw_instance.get("instance_id"):
        identifiers.append(pb.InstanceIdentifier(
            key=pb.IdentifierType.AWS_EC2_INSTANCE_ID,
            value=raw_instance["instance_id"],
        ))

    instance = pb.InstanceData(
        instance_id=instance_id,
        name=raw_instance.get("hostname", instance_id),
        operating_system=os_string,
        instance_type=pb.InstanceType.INSTANCE_TYPE_MACHINE,
        asset_information=pb.AssetInstanceInformation(
            ip_addresses=ip_addresses,
            mac_addresses=mac_addresses,
        ),
        identifiers=identifiers,
        labels=labels,
        key_value_tags=key_value_tags,
    )

    return instance


def parse_to_finding(raw_vuln, pb):
    """
    Parse a CrowdStrike Spotlight vulnerability into a Vulnerability proto.
    """
    instance_id = raw_vuln.get("aid", "")
    if not instance_id:
        log.warn("Vulnerability missing aid, skipping")
        return None

    cve_data = raw_vuln.get("cve", {})
    cve_id = cve_data.get("id", "")
    if not cve_id:
        log.warn("Vulnerability missing cve.id, skipping")
        return None

    # Component from apps
    component = None
    apps = raw_vuln.get("apps", [])
    if apps and len(apps) > 0:
        app = apps[0]
        component = pb.Component(
            type=pb.ComponentType.APPLICATION,
            product=app.get("product_name_version", ""),
            vendor=app.get("vendor_normalized", ""),
        )

    vuln_fields = {
        "instance_id": instance_id,
        "cve": cve_id,
    }

    if component:
        vuln_fields["component"] = component

    vulnerability = pb.Vulnerability(**vuln_fields)
    return vulnerability
