#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vladimir F de Sousa - vfrancad@gmail.com
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
    parser = argparse.ArgumentParser(description="Allocate Unclaimed ION to Shell")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device (Element Shell) Name")
    parser.add_argument("-N", "--new_sn", required=True, help="Serial Number to Allocate")
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "accept": "application/json",
        "x-panw-region": "de" 
    }
    
    get_profile(headers)

    # 1. Resolve Site ID
    print(f"[*] Locating site: {args.site}...")
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    site_obj = next((s for s in sites_res.json().get('items', []) if s['name'] == args.site), None)
    if not site_obj:
        print(f"[!] Error: Site '{args.site}' not found."); return
    site_id = site_obj['id']

    # 2. Resolve Element Shell (Claimed Device entry)
    print(f"[*] Searching for Shell '{args.device}' in site '{args.site}'...")
    elems_res = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements?site_id={site_id}", headers=headers)
    target_elem = next((e for e in elems_res.json().get('items', []) if e['name'] == args.device), None)
    
    if not target_elem:
        print(f"[!] Error: Shell/Device '{args.device}' not found in site."); return
    
    element_shell_id = target_elem['id']

    # 3. Find Machine and Verify "Online" Status
    print(f"[*] Verifying status for Serial {args.new_sn}...")
    # Using v2.5 as per your example
    mac_res = requests.get(f"{BASE_API_URL}/sdwan/v2.5/api/machines", headers=headers)
    all_machines = mac_res.json().get("items", [])
    
    machine = next((m for m in all_machines if m.get('sl_no') == args.new_sn), None)
    
    if not machine:
        print(f"[!] Error: Serial {args.new_sn} not found in inventory."); return
    
    # Logic check: Must be connected and not retired
    if not machine.get('connected'):
        print(f"[!] Warning: Device {args.new_sn} is OFFLINE. Allocation will likely fail.")
    if machine.get('machine_state') == 'retired':
        print(f"[!] Error: Device {args.new_sn} is in 'retired' state and cannot be claimed.")
        return

    # 4. Allocate to Shell
    print(f"[*] Allocating {args.new_sn} to Shell {args.device} ({element_shell_id})...")
    allocate_url = f"{BASE_API_URL}/sdwan/v2.0/api/machines/{machine['id']}/allocate_to_shell"
    
    # As per your curl example: simplified payload
    payload = {"element_shell_id": element_shell_id}

    final_res = requests.post(allocate_url, headers=headers, json=payload)
    
    if final_res.status_code in [200, 201]:
        print(f"\n[SUCCESS] Allocation Complete!")
        print(json.dumps(final_res.json(), indent=2))
    else:
        print(f"\n[FAILED] Error {final_res.status_code}: {final_res.text}")

if __name__ == "__main__":
    main()
