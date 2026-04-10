#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

import os
import json
import argparse
import requests
from typing import Dict, Any, List, Optional

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

def get_profile(headers: Dict[str, str]):
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

def main():
    parser = argparse.ArgumentParser(description="Replace ION by Device Name")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device Name")
    parser.add_argument("-N", "--new_sn", required=True, help="New Serial Number")
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-panw-region": "de" 
    }
    
    get_profile(headers)

    # 1. Map Site Name to ID
    print(f"[*] Locating site: {args.site}...")
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    sites_res.raise_for_status()
    site_obj = next((s for s in sites_res.json().get('items', []) if s['name'] == args.site), None)
    
    if not site_obj:
        print(f"[!] Error: Site '{args.site}' not found."); return
    site_id = site_obj['id']

    # 2. Target the specific Element by Name
    print(f"[*] Searching for device '{args.device}' in site '{args.site}'...")
    elems_res = requests.get(f"{BASE_API_URL}/sdwan/v3.1/api/elements?site_id={site_id}", headers=headers)
    elems_res.raise_for_status()
    target_elem = next((e for e in elems_res.json().get('items', []) if e['name'] == args.device), None)
    
    if not target_elem:
        print(f"[!] Error: Device '{args.device}' not found in site '{args.site}'."); return

    # 3. Get the Shell ID (First Curl Logic)
    print(f"[*] Generating Shell for {target_elem['name']} (ID: {target_elem['id']})...")
    shell_payload = {
        "tenant_id": target_elem.get("tenant_id"),
        "site_id": site_id,
        "element_id": target_elem.get("id"),
        "model_name": target_elem.get("model_name"),
        "software_version": target_elem.get("software_version"),
        "role": target_elem.get("role")
    }
    
    shell_res = requests.post(f"{BASE_API_URL}/sdwan/v2.0/api/sites/{site_id}/elementshells", 
                               headers=headers, json=shell_payload)
    shell_res.raise_for_status()
    shell_data = shell_res.json()
    shell_id = shell_data.get("id")

    # 4. Find the New Machine in Inventory
    # Fixed: Adding extra error handling for the machine lookup
    print(f"[*] Finding New Hardware SN: {args.new_sn}...")
    mac_res = requests.get(f"{BASE_API_URL}/sdwan/v2.5/api/machines", headers=headers)
    mac_res.raise_for_status()
    
    # Check if we actually got content back
    if not mac_res.text.strip():
        print("[!] Error: API returned empty response for machines list."); return
        
    all_machines = mac_res.json().get("items", [])
    # Search manually in the list to be safer than relying on server-side filtering
    machine_obj = next((m for m in all_machines if m.get('sl_no') == args.new_sn or m.get('id') == args.new_sn), None)
    
    if not machine_obj:
        print(f"[!] Error: Serial {args.new_sn} not found in inventory."); return

    # 5. Final Allocation (Second Curl Logic)
    print(f"[*] Swapping hardware: Allocating {args.new_sn} to {args.device}...")
    allocate_url = f"{BASE_API_URL}/sdwan/v2.0/api/machines/{machine_obj['id']}/allocate_to_shell"
    
    allocate_payload = machine_obj.copy()
    allocate_payload["element_shell_id"] = shell_id
    allocate_payload["software_version"] = target_elem.get("software_version")

    final_res = requests.post(allocate_url, headers=headers, json=allocate_payload)
    
    if final_res.status_code in [200, 201]:
        print(f"\n[SUCCESS] Replacement Complete!")
        print(f"Device '{args.device}' is now bound to Serial '{args.new_sn}'.")
    else:
        print(f"\n[FAILED] Error {final_res.status_code}: {final_res.text}")

if __name__ == "__main__":
    main()
