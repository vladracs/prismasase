import os
import csv
import json
import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SDWAN_API_BASE = f"{BASE_API_URL}/sdwan/v3.1/api"


def get_env_variable(name):
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Environment variable {name} is not set")
    return value


def get_token():
    client_id = get_env_variable("CLIENT_ID")
    client_secret = get_env_variable("CLIENT_SECRET")
    tenant_id = get_env_variable("TENANT_ID")

    data_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tenant_id}",
        "grant_type": "client_credentials"
    }

    response = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data_payload
    )
    response.raise_for_status()
    return response.json()["access_token"]


def get_headers(token):
    return {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-PANW-Region': 'de'
    }


def get_service_endpoints(headers):
    url = f"{SDWAN_API_BASE}/serviceendpoints"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json().get("items", [])


def find_endpoint_by_name(endpoints, name):
    for ep in endpoints:
        if ep.get("name") == name:
            return ep.get("id")
    return None


def get_service_endpoint_details(headers, endpoint_id):
    url = f"{SDWAN_API_BASE}/serviceendpoints/{endpoint_id}"
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def read_ips_and_hostnames(ips_path, hostnames_path):
    with open(ips_path, 'r') as f:
        ip_list = [line.strip() for line in f if line.strip()]
    with open(hostnames_path, 'r') as f:
        hostname_list = [line.strip() for line in f if line.strip()]
    return ip_list, hostname_list


def update_service_endpoint(headers, endpoint_id, etag, existing_payload, new_ips, new_hostnames):
    # Merge existing and new values
    existing_peers = existing_payload.get("service_link_peers", {})
    existing_ips = existing_peers.get("ip_addresses", [])
    existing_hostnames = existing_peers.get("hostnames", [])

    updated_ips = list(set(existing_ips + new_ips))
    updated_hostnames = list(set(existing_hostnames + new_hostnames))

    existing_payload["_etag"] = etag
    existing_payload["service_link_peers"] = {
        "ip_addresses": updated_ips,
        "hostnames": updated_hostnames
    }

    url = f"{SDWAN_API_BASE}/serviceendpoints/{endpoint_id}"
    response = requests.put(url, headers=headers, data=json.dumps(existing_payload))
    response.raise_for_status()
    print("Service endpoint updated successfully.")


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description="Update SCM SD-WAN service endpoint with new IPs and hostnames.")
    parser.add_argument('--endpoint_name', required=True, help='Name of the service endpoint to update')
    parser.add_argument('--ips_file', required=True, help='Path to the file containing IP addresses (one per line)')
    parser.add_argument('--hostnames_file', required=True, help='Path to the file containing hostnames (one per line)')
    args = parser.parse_args()


    token = get_token()
    headers = get_headers(token)

    # Initial /profile call
    profile_url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    requests.get(profile_url, headers=headers)

    print("Fetching service endpoints...")
    endpoints = get_service_endpoints(headers)
    endpoint_id = find_endpoint_by_name(endpoints, args.endpoint_name)
    if not endpoint_id:
        print("Service endpoint not found.")
        exit(1)

    print(f"Found endpoint ID: {endpoint_id}")
    details = get_service_endpoint_details(headers, endpoint_id)
    etag = details.get("_etag")
    if not etag:
        print("ETag not found in endpoint details.")
        exit(1)
    
    ip_list, hostname_list = read_ips_and_hostnames(args.ips_file, args.hostnames_file)
    

    existing_payload=details
    update_service_endpoint(headers, endpoint_id, etag, existing_payload, ip_list, hostname_list)
