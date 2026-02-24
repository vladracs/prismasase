import os
import requests
import json
import csv
import argparse
import sys
import keyring
from datetime import datetime, timedelta, timezone
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

def fetch_events_final(headers: Dict[str, str], event_type: str) -> List[Dict]:
    """Uses exact list structures to satisfy API validation."""
    url = f"{BASE_API_URL}/sdwan/v3.7/api/events/query"
    
    end_dt = datetime.now(timezone.utc)
    start_dt = end_dt - timedelta(hours=24)

    payload = {
        "start_time": start_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "end_time": end_dt.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "query": {
            # FIX: Use the variable passed into the function here
            "type": [event_type], 
            "site": [],
            "category": [],
            "code": [],
            "correlation_id": []
        },
        "severity": [],
        "priority": [],
        "limit": {
            "count": 50, 
            "sort_on": "time", 
            "sort_order": "descending"
        },
        "view": {"summary": False},
        "acknowledged": None,
        "suppressed": None
    }

    try:
        res = requests.post(url, headers=headers, json=payload)
        if res.status_code == 200:
            return res.json().get('items', [])
        else:
            print(f"\n[!] API Error {res.status_code} for {event_type}")
            print(f"    Response: {res.text}")
    except Exception as e:
        print(f"    [!] Request failed: {e}")
    return []

def main():
    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "x-panw-region": "de"}
    get_profile(headers)

    # 1. Map Names
    print("[*] Resolving Site and Device names...")
    sites = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers).json().get('items', [])
    site_map = {s['id']: s['name'] for s in sites}
    elements = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements", headers=headers).json().get('items', [])
    elem_map = {e['id']: e['name'] for e in elements}

    # 2. Grab Data
    print("[*] Fetching Events (Last 24h)...")
    alarms = fetch_events_final(headers, "alarm")
    alerts = fetch_events_final(headers, "alert")
    incidents = fetch_events_final(headers, "incident") # Added this call
    
    all_raw = (alarms or []) + (alerts or []) + (incidents or [])
    print(f"    -> Found {len(all_raw)} total events.")

    all_data = []
    for item in all_raw:
        sid = item.get('site_id')
        eid = item.get('element_id')
        info = item.get('info') or {}
        
        # Build description
        details = []
        if item.get('code'): details.append(item['code'])
        if info.get('reason'): details.append(f"Reason: {info['reason']}")
        if info.get('process_name'): details.append(f"Process: {info['process_name']}")
        
        all_data.append({
            "Time": item.get('time'),
            "Type": item.get('type', 'N/A').upper(),
            "Severity": item.get('severity', 'N/A').upper(),
            "Site": site_map.get(sid, sid),
            "Device": elem_map.get(eid, "N/A"),
            "Description": " | ".join(details),
            "Status": "Standing" if item.get('standing') else "Cleared",
            "Correlation ID": item.get('correlation_id', 'N/A') 
        })
    # 3. CSV Export
    if all_data:
        all_data.sort(key=lambda x: x['Time'], reverse=True)
        filename = f"POV_Event_Log_{datetime.now().strftime('%H%M%S')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=all_data[0].keys())
            writer.writeheader()
            writer.writerows(all_data)
        print(f"\n[SUCCESS] Report generated: {filename}")
    else:
        print("\n[!] No events found. If you see data in the UI, check your TSG ID.")

if __name__ == "__main__":
    main()