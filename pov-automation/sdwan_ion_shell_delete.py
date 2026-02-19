import os
import json
import argparse
import requests
import keyring
import sys
from typing import Dict, Any, List, Optional

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SERVICE_NAME = "prismasase"

# ---------- Helpers ----------
def _get_credential(key: str) -> str:
    val = keyring.get_password(SERVICE_NAME, key)
    if not val:
        print(f"CRITICAL: Credential '{key}' not found in Keychain.")
        sys.exit(1)
    return val

def get_token() -> str:
    client_id = _get_credential("client_id")
    client_secret = _get_credential("client_secret")
    tsg_id = _get_credential("tsg_id")

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tsg_id}",
        "grant_type": "client_credentials",
    }
    
    try:
        r = requests.post(AUTH_URL, data=data, timeout=30)
        r.raise_for_status()
        return r.json()["access_token"]
    except Exception as e:
        print(f"Auth Failed: {e}")
        sys.exit(1)

def get_profile(headers: Dict[str, str]):
    try:
        requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
        print("[*] Profile Initialized")
    except Exception as e:
        print(f"Profile Init Failed: {e}")
        sys.exit(1)

def find_item(items: List[Dict], name: str, label: str) -> Dict:
    """Finds the full object by name (case-insensitive)."""
    target = name.strip().lower()
    for item in items:
        if (item.get('name') or '').lower() == target: return item
        if (item.get('display_name') or '').lower() == target: return item
    
    print(f"[!] Error: Could not find {label} named '{name}'")
    sys.exit(1)

# ---------- Main Logic ----------
def main():
    parser = argparse.ArgumentParser(description="Delete a Prisma SD-WAN Device Shell")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device Shell Name to delete")
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de" # Adjust region as needed
    }

    # 1. Init Profile
    get_profile(headers)

    # 2. Get Site ID
    print(f"[*] Locating Site '{args.site}'...")
    sites_resp = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    sites_resp.raise_for_status()
    site_obj = find_item(sites_resp.json().get('items', []), args.site, "Site")
    site_id = site_obj['id']

    # 3. Get Device Shell ID
    # Note: Elementshells are specific to the site context
    print(f"[*] Locating Device Shell '{args.device}' in Site '{args.site}'...")
    shell_url = f"{BASE_API_URL}/sdwan/v2.0/api/sites/{site_id}/elementshells"
    shell_resp = requests.get(shell_url, headers=headers)
    shell_resp.raise_for_status()
    
    shell_obj = find_item(shell_resp.json().get('items', []), args.device, "Device Shell")
    shell_id = shell_obj['id']

    # 4. Perform DELETE
    print(f"[*] Deleting Device Shell '{args.device}' (ID: {shell_id})...")
    delete_url = f"{shell_url}/{shell_id}"
    
    # Per your curl, send empty JSON body with DELETE
    resp = requests.delete(delete_url, headers=headers, json={})

    if resp.status_code in [200, 204]:
        print(f"\n[SUCCESS] Device shell '{args.device}' deleted.")
    elif resp.status_code == 202:
        print(f"\n[ACCEPTED] Delete request accepted (processing).")
    else:
        print(f"\n[FAILED] Status Code: {resp.status_code}")
        print(f"Response: {resp.text}")

if __name__ == "__main__":
    main()