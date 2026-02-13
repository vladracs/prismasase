#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

import os
import requests
import json
import csv
from typing import Dict, Any, List

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

def _must_env(name: str) -> str:
    v = os.getenv(name)
    if not v: raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    data = {
        "client_id": _must_env("PRISMASASE_CLIENT_ID"),
        "client_secret": _must_env("PRISMASASE_CLIENT_SECRET"),
        "scope": f"tsg_id:{_must_env('PRISMASASE_TSG_ID')}",
        "grant_type": "client_credentials",
    }
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_profile(token: str, headers: Dict[str, str]):
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()

def main():
    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de"
    }
    
    get_profile(token, headers)
    print("Fetching Sites, Elements (Tags), and Real-time Status...")

    # 1. Map Site IDs to Names
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    site_map = {s['id']: s['name'] for s in sites_res.json().get('items', [])}

    # 2. Get Device Status/Monitoring Data
    status_res = requests.get(f"{BASE_API_URL}/sdwan/monitor/v1.0/api/monitor/elements", headers=headers)
    status_items = {item['id']: item for item in status_res.json().get('items', [])}

    # 3. Get all Elements (This includes the 'tags' list)
    elements_res = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements", headers=headers)
    elements = elements_res.json().get('items', [])

    csv_data = []
    
    for dev in elements:
        eid = dev.get('id')
        sid = dev.get('site_id')
        stat = status_items.get(eid, {})
        
        # --- Handle Tags ---
        tag_list = dev.get('tags') or []
        tag_str = "; ".join(tag_list)

        # --- Handle Multiple Interface IPs ---
        all_ips = []
        if sid and sid != "0":
            intf_url = f"{BASE_API_URL}/sdwan/v4.21/api/sites/{sid}/elements/{eid}/interfaces"
            intf_res = requests.get(intf_url, headers=headers)
            if intf_res.status_code == 200:
                for i in intf_res.json().get('items', []):
                    ipv4 = i.get('ipv4_config') or {}
                    static = ipv4.get('static_config') or {}
                    if static.get('address'):
                        all_ips.append(f"{i.get('name')}: {static.get('address')}")
                    elif ipv4.get('type') == 'dhcp':
                        all_ips.append(f"{i.get('name')}: DHCP")

        # --- Construct Row with Metadata, Status, and Tags ---
        row = {
            "Site": site_map.get(sid, "Unassigned"),
            "Device Name": dev.get('name'),
            "Tags": tag_str,  # New Column for Grouping
            "Serial Number": dev.get('serial_number'),
            "Software Version": dev.get('software_version'),
            "IP Addresses": ", ".join(all_ips),
            "Uptime": stat.get('uptime_str', "N/A"),
            "Config/Events": stat.get('config_status', "Offline"),
            "Analytics": stat.get('analytics_status', "Offline"),
            "Flows": stat.get('flows_status', "Offline"),
            "Last Disconnect": stat.get('last_disconnect_time', "N/A"),
            "Reboot Reason": stat.get('last_reboot_reason', "N/A"),
            "Logging Service": stat.get('logging_service_status', "Offline")
        }
        csv_data.append(row)
        print(f"Processed: {dev.get('name')} [Tags: {len(tag_list)}]")

    # 4. Write CSV
    if csv_data:
        keys = csv_data[0].keys()
        filename = 'prisma_sdwan_full_audit.csv'
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(csv_data)
        print(f"\nAudit complete: {filename}")

if __name__ == "__main__":
    main()
