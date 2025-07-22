#!/usr/bin/env python3

#script will go over all flows for the application PING for a given site in a given period and print all flows where the number of packets sent by client and responded by server dont match.

import os
import json
import requests
import sys
from datetime import datetime
from typing import List, Optional

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
PING_APP_ID = "1750746392700003945" #hardcoded this may change in the future

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
        'x-panw-region': 'de'
    }
def get_profile(token):
    profile_url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    headers = get_headers(token)
    resp = requests.get(profile_url, headers=headers)
    print("profile api status:", resp.status_code)
    #print("profile api response:", resp.text)
    return resp

def get_site_id_by_name(token: str, site_name: str) -> Optional[str]:
    url = f"{BASE_API_URL}/sdwan/v4.12/api/sites"
    headers = get_headers(token)
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    sites = response.json().get("items", [])
    for site in sites:
        if site.get("name", "").lower() == site_name.lower():
            return site["id"]
    return None

def get_sdwan_flows_with_packet_mismatch(
    token: str,
    start_time: str,
    end_time: str,
    site_ids: List[str],
    app_ids: List[str],
    page_size: int,
    debug_level: str = "all",
    dest_page: int = 1,
    summary: bool = False
):
    url = "https://api.sase.paloaltonetworks.com/sdwan/monitor/v3.10/api/monitor/flows" 
    #url = f"{BASE_API_URL}/sdwan/monitor/v3.10/api/monitor/flows"
    headers = get_headers(token)
    payload = {
        "start_time": start_time,
        "end_time": end_time,
        "filter": {
            "site": site_ids
        },
        "debug_level": debug_level,
        "page_size": page_size,
        "dest_page": dest_page,
        "view": {
            "summary": summary
        }
    }
    if app_ids:
        payload["filter"]["app"] = app_ids
    #print(payload)
    #payload={"start_time":"2025-07-22T14:04:30Z","end_time":"2025-07-22T15:04:30.000Z","filter":{"site":["1750842266204012345"],"app":["1750746392700003945"]},"debug_level":"all","page_size":100,"dest_page":1,"view":{"summary":False}}
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    data = response.json()

    items = data.get("flows", {}).get("items", [])
    print(f"[INFO] Total flows returned: {len(items)}")
    mismatch_count = 0

    for flow in items:
        start_ms = flow.get("flow_start_time_ms")
        end_ms = flow.get("flow_end_time_ms")
        start_human = datetime.utcfromtimestamp(start_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') if start_ms else "N/A"
        end_human = datetime.utcfromtimestamp(end_ms / 1000).strftime('%Y-%m-%d %H:%M:%S') if end_ms else "N/A"

        c2s = flow.get("packets_c2s", 0)
        s2c = flow.get("packets_s2c", 0)
        #uncomment to print all PING flows
        #print({                "source_ip": flow.get("source_ip"),"destination_ip": flow.get("destination_ip"),"packets_c2s": c2s, "packets_s2c": s2c,"flow_start_time": start_human, "flow_end_time": end_human })
        if c2s != s2c:
            mismatch_count += 1
            print({
                "source_ip": flow.get("source_ip"),
                "destination_ip": flow.get("destination_ip"),
                "packets_c2s": c2s,
                "packets_s2c": s2c,
                "flow_start_time": start_human,
                "flow_end_time": end_human,
            })

    print(f"\n[INFO] Flows with mismatched packets: {mismatch_count} / {len(items)}")
    return data

if __name__ == '__main__':
    if len(sys.argv) != 5 :
        print("Usage: python3 scm_sdwan_get_ping_drops.py <site_name> <num_flows> <start_time> <end_time>")
        print("Example: python3 scm_sdwan_get_ping_drops.py BRANCH 100 2025-07-21T10:00:00Z 2025-07-22T10:00:00Z")
        sys.exit(1)

    site_name = sys.argv[1]
    flow_count = int(sys.argv[2])
    start_time = sys.argv[3]
    end_time = sys.argv[4]

    token = get_token()
    get_profile(token)
    site_id = get_site_id_by_name(token, site_name)
    print(site_name," ",site_id)
    if not site_id:
        print(f"[ERROR] Site '{site_name}' not found.")
        sys.exit(1)
    start_time = "2025-07-21T10:45:34.000Z"
    end_time = "2025-07-22T12:50:34.000Z"
    print("Flows from ",start_time, " till ",end_time)
    get_sdwan_flows_with_packet_mismatch(token, start_time, end_time, site_ids=[site_id],app_ids=[PING_APP_ID], page_size=flow_count)

