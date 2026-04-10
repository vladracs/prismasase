import os
import json
import argparse
import requests
from typing import Dict, Any, List, Optional
import json
import argparse
import requests
import keyring  # <--- New Import
from typing import Dict, Any, List, Optional

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SERVICE_NAME = "prismasase" # Consistency is key

def _get_credential(key: str) -> str:
    """Fetches credential from macOS Keychain."""
    val = keyring.get_password(SERVICE_NAME, key)
    if not val:
        raise ValueError(f"Credential '{key}' not found in Keychain for service '{SERVICE_NAME}'")
    return val

def get_token() -> str:
    # Fetching from Keychain instead of Environment Variables
    client_id = _get_credential("client_id")
    client_secret = _get_credential("client_secret")
    tsg_id = _get_credential("tsg_id")

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tsg_id}",
        "grant_type": "client_credentials",
    }
    
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_profile(headers: Dict[str, str]):
    # Mandatory session initialization
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

def main():
    parser = argparse.ArgumentParser(description="Prisma SD-WAN Remote Device Reboot")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device (Element) Name to reboot")
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

    # 2. Map Device Name to Element ID
    print(f"[*] Locating device '{args.device}' in site '{args.site}'...")
    elems_res = requests.get(f"{BASE_API_URL}/sdwan/v3.1/api/elements?site_id={site_id}", headers=headers)
    elems_res.raise_for_status()
    target_elem = next((e for e in elems_res.json().get('items', []) if e['name'] == args.device), None)
    
    if not target_elem:
        print(f"[!] Error: Device '{args.device}' not found."); return
    
    element_id = target_elem['id']

    # 3. Trigger Reboot Operation
    print(f"[*] Triggering reboot for {args.device} (ID: {element_id})...")
    ops_url = f"{BASE_API_URL}/sdwan/v2.0/api/elements/{element_id}/operations"
    
    # Payload as per your curl requirement
    payload = {
        "action": "reboot",
        "parameters": []
    }

    resp = requests.post(ops_url, headers=headers, json=payload)
    
    if resp.status_code in [200, 201, 204]:
        print(f"\n[SUCCESS] Reboot command sent to {args.device}.")
    else:
        print(f"\n[FAILED] Status {resp.status_code}: {resp.text}")

if __name__ == "__main__":
    main()