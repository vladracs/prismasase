#Use: 
# python3 -c "import keyring; keyring.set_password('prismasase', 'client_id', 'YOUR_SA_ID')"
# python3 -c "import keyring; keyring.set_password('prismasase', 'client_secret', 'YOUR_SECRET')"
# python3 -c "import keyring; keyring.set_password('prismasase', 'tsg_id', 'YOUR_TSG_ID')"

import os
import requests
import json
import csv
import sys
import keyring
from datetime import datetime
from typing import Dict, List, Any

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SERVICE_NAME = "prismasase"

def _get_credential(key: str) -> str:
    val = keyring.get_password(SERVICE_NAME, key)
    if not val:
        print(f"CRITICAL ERROR: Credential '{key}' not found in Keychain.")
        sys.exit(1)
    return val

def get_token() -> str:
    data = {
        "client_id": _get_credential("client_id"),
        "client_secret": _get_credential("client_secret"),
        "scope": f"tsg_id:{_get_credential('tsg_id')}",
        "grant_type": "client_credentials"
    }
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_profile(headers: Dict[str, str]):
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

# ---------- New API Call for Audit Logs ----------
def fetch_audit_logs(headers: Dict[str, str]) -> List[Dict]:
    """Fetches audit logs using the exact structure from the curl base."""
    url = f"{BASE_API_URL}/sdwan/v2.1/api/auditlog/query"
    
    # Matching the --data-raw from your curl
    payload = {
        "limit": "100",
        "sort_params": {"response_ts": "desc"},
        "dest_page": 1
    }

    # Your curl specifically uses the token in a cookie as well
    token = headers['Authorization'].split(' ')[1]
    cookies = {"SASE.OAuth.AccessToken": token}

    try:
        res = requests.post(url, headers=headers, cookies=cookies, json=payload, timeout=30)
        if res.status_code == 200:
            return res.json().get('items', [])
        else:
            print(f"[!] Audit API Error {res.status_code}: {res.text[:200]}")
            return []
    except Exception as e:
        print(f"[!] Audit request failed: {e}")
        return []

def main():
    token = get_token()
    # Keeping original header structure
    headers = {
        "Authorization": f"Bearer {token}", 
        "Content-Type": "application/json"
    }
    
    # Required profile initialization
    get_profile(headers)

    # 1. Fetch Audit Data
    print("[*] Fetching Audit Logs...")
    audit_raw = fetch_audit_logs(headers)
    
    # 2. Process for CSV
    all_data = []
    for item in audit_raw:
        all_data.append({
            "Time": item.get('response_ts'),
            "User": item.get('user_email'),
            "Method": item.get('request_method'),
            "Resource": item.get('request_uri'),
            "Status": item.get('response_code'),
            "App": item.get('app_name'),
            "IP": item.get('ip_address')
        })

    # 3. CSV Export
    if all_data:
        filename = f"Audit_Log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_data[0].keys())
            writer.writeheader()
            writer.writerows(all_data)
        print(f"\n[SUCCESS] Extracted {len(all_data)} logs to: {filename}")
    else:
        print("\n[!] No audit logs found.")

if __name__ == "__main__":
    main()
