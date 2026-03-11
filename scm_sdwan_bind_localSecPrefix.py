#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.


# credentials should be added to a vault:
#pip install keyring
#python3 -c "import keyring; keyring.set_password('prismasase', 'client_id', 'YOUR_SA_ID')"
#python3 -c "import keyring; keyring.set_password('prismasase', 'client_secret', 'YOUR_SECRET')"
#python3 -c "import keyring; keyring.set_password('prismasase', 'tsg_id', 'YOUR_TSG_ID')"
#usage: python3 scm_sdwan_bind_localSecPrefix.py -o "local security prefix list name"

import requests
import sys
import argparse
import keyring
from typing import Dict, List, Optional

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SERVICE_NAME = "prismasase"

# ---------- Auth & Profile ----------

def _get_credential(key: str) -> str:
    val = keyring.get_password(SERVICE_NAME, key)
    if not val:
        print(f"CRITICAL ERROR: '{key}' not found in Keychain for '{SERVICE_NAME}'")
        sys.exit(1)
    return val

def get_token() -> str:
    data = {
        "client_id": _get_credential("client_id"),
        "client_secret": _get_credential("client_secret"),
        "scope": f"tsg_id:{_get_credential('tsg_id')}",
        "grant_type": "client_credentials",
    }
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def init_profile(headers: Dict):
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

# ---------- Data Extraction ----------

def get_prefix_object_id(headers: Dict, object_name: str) -> str:
    """Finds the ID of the Global Security Prefix Object (e.g., VLAN-X)."""
    resp = requests.get(f"{BASE_API_URL}/sdwan/v2.0/api/ngfwsecuritypolicylocalprefixes", headers=headers)
    resp.raise_for_status()
    for item in resp.json().get("items", []):
        if item.get("name") == object_name:
            return item.get("id")
    print(f"ERROR: Prefix Object '{object_name}' not found.")
    sys.exit(1)

def get_all_sites(headers: Dict) -> List[Dict]:
    resp = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    resp.raise_for_status()
    return resp.json().get("items", [])

def get_site_local_subnets(headers: Dict, site_id: str) -> List[str]:
    """Extracts ipv4_prefix list from the site's localprefixset."""
    url = f"{BASE_API_URL}/sdwan/v2.0/api/sites/{site_id}/localprefixset"
    resp = requests.get(url, headers=headers)
    if resp.status_code != 200:
        return []
    
    data = resp.json()
    subnets = []
    # Navigate the nested JSON structure provided in your example
    configured = data.get("configured", {}) or {}
    local_prefix_set = configured.get("local_prefix_set", {}) or {}
    networks = local_prefix_set.get("local_networks", []) or []
    
    for net in networks:
        for p_set in net.get("prefix_set", []):
            if p_set.get("ipv4_prefix"):
                subnets.append(p_set["ipv4_prefix"])
    return list(set(subnets)) # Unique values only

# ---------- Binding Logic ----------

def sync_site_binding(headers: Dict, site_id: str, site_name: str, prefix_obj_id: str):
    # 1. Get the subnets to apply
    subnets = get_site_local_subnets(headers, site_id)
    if not subnets:
        print(f"[-] Site {site_name}: No local subnets found. Skipping.")
        return

    # 2. Check for existing binding to get ID and ETag
    bind_url = f"{BASE_API_URL}/sdwan/v2.1/api/sites/{site_id}/ngfwsecuritypolicylocalprefixes"
    check_resp = requests.get(bind_url, headers=headers)
    check_resp.raise_for_status()
    
    existing_items = check_resp.json().get("items", [])
    existing_obj = next((item for item in existing_items if item.get("prefix_id") == prefix_obj_id), None)

    payload = {
        "prefix_id": prefix_obj_id,
        "ipv4_prefixes": subnets,
        "ipv6_prefixes": [],
        "tags": []
    }

    if existing_obj:
        # UPDATE Path
        bind_id = existing_obj["id"]
        payload.update({
            "id": bind_id,
            "_etag": existing_obj.get("_etag"),
            "_schema": existing_obj.get("_schema", 1)
        })
        resp = requests.put(f"{bind_url}/{bind_id}", headers=headers, json=payload)
        action = "Updated"
    else:
        # CREATE Path
        resp = requests.post(bind_url, headers=headers, json=payload)
        action = "Created"

    if resp.status_code in [200, 201]:
        print(f"[+] Site {site_name}: {action} binding with subnets {subnets}")
    else:
        print(f"[!] Site {site_name}: Failed to {action}. Status: {resp.status_code}")

# ---------- Main ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--object", help="Security Prefix Object Name", required=True)
    args = parser.parse_args()

    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    init_profile(headers)

    prefix_obj_id = get_prefix_object_id(headers, args.object)
    sites = get_all_sites(headers)

    print(f"[*] Starting Sync for {len(sites)} sites to object '{args.object}'...\n")
    for site in sites:
        if site.get("admin_state") != "active":
            continue
        sync_site_binding(headers, site["id"], site["name"], prefix_obj_id)

if __name__ == "__main__":
    main()
