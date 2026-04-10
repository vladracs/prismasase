import os
import requests
import json
import csv
import argparse
import time
import sys
import keyring
from datetime import datetime, timedelta
from typing import Dict, Any, List

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SERVICE_NAME = "prismasase" 

# ---------- Helpers ----------

def _get_credential(key: str) -> str:
    val = keyring.get_password(SERVICE_NAME, key)
    if not val:
        print(f"CRITICAL ERROR: Credential '{key}' not found in Keychain for service '{SERVICE_NAME}'")
        sys.exit(1)
    return val

def debug_request(response, label):
    """Prints debug info if request fails."""
    if not (200 <= response.status_code < 300):
        print(f"DEBUG [{label}]: Request FAILED (Status {response.status_code})")
        print(f"DEBUG [{label}]: Raw Response: {response.text[:500]}...") 
        return False
    return True

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
        if not debug_request(r, "Auth Token"): sys.exit(1)
        return r.json()["access_token"]
    except Exception as e:
        print(f"CRITICAL ERROR getting token: {e}")
        sys.exit(1)

def get_profile(headers: Dict[str, str]):
    """Initializes the session profile."""
    try:
        requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
        print("[*] Profile Initialized")
    except Exception as e:
        print(f"CRITICAL: Failed to initialize profile: {e}")
        sys.exit(1)

def fmt_time(ts):
    """Converts Prisma SD-WAN timestamps (seconds or microseconds) to string."""
    if not ts or ts == 0: return "N/A"
    ts_str = str(ts)
    if len(ts_str) > 11: ts = ts / 1_000_000.0
    try:
        return datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "Invalid TS"

def calc_uptime(boot_time):
    if not boot_time or boot_time == 0: return "N/A"
    if len(str(boot_time)) > 11: boot_time = boot_time / 1_000_000.0
    start = datetime.fromtimestamp(boot_time)
    delta = datetime.now() - start
    return str(delta).split('.')[0]

def fetch_site_status(token, site_id):
    """
    Fetches status for ALL elements at a SPECIFIC Site ID using the query payload.
    """
    url = f"{BASE_API_URL}/sdwan/v2.6/api/elements/status/query"
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    
    # EXACT PAYLOAD PATTERN YOU PROVIDED
    payload = {
        "query_params": {
            "site_id": {"eq": site_id}
        },
        "limit": 100,
        "getDeleted": False
    }
    
    try:
        resp = requests.post(url, headers=headers, json=payload)
        if resp.status_code == 200:
            return resp.json().get('items', [])
        else:
            print(f"Warning: Failed to fetch status for site {site_id}: {resp.status_code}")
            return []
    except Exception as e:
        print(f"Error fetching site status {site_id}: {e}")
        return []

# ---------- Main Execution ----------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-T", "--tags", help="Filter by SITE tags (comma-separated).", type=str)
    args = parser.parse_args()
    
    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de"
    }
    
    # 1. Initialize Profile
    get_profile(headers)
    
    # 2. Get Sites
    print("Fetching Sites...")
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    if not debug_request(sites_res, "Get Sites"): sys.exit(1)
    
    sites_data = sites_res.json().get('items', [])
    site_map = {s['id']: s['name'] for s in sites_data}
    site_tags_map = {s['id']: (s.get('tags') or []) for s in sites_data}

    # 3. Get Elements Inventory
    print("Fetching Elements...")
    elements_res = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements", headers=headers)
    if not debug_request(elements_res, "Get Elements"): sys.exit(1)
    elements = elements_res.json().get('items', [])

    # 4. Filter Elements & Build Unique Site List
    target_tags = sorted([t.strip() for t in args.tags.split(',')]) if args.tags else []
    
    # We only want to fetch status for sites that actually have relevant devices
    relevant_site_ids = set()
    filtered_elements = []

    for dev in elements:
        sid = dev.get('site_id')
        if not sid: continue
        
        site_tags = site_tags_map.get(sid, [])
        if args.tags and sorted(site_tags) != target_tags:
            continue
            
        relevant_site_ids.add(sid)
        filtered_elements.append(dev)

    print(f"Found {len(filtered_elements)} devices across {len(relevant_site_ids)} sites.")

    # 5. Fetch Status Per Site (Aggregating)
    status_cache = {}
    print("Fetching Status for relevant sites...")
    
    for i, sid in enumerate(relevant_site_ids):
        print(f"  [{i+1}/{len(relevant_site_ids)}] Querying Site ID: {sid}...")
        items = fetch_site_status(token, sid)
        for item in items:
            # Map element_id (or id) to the status item
            # The API returns "id" as the status record ID, but "element_id" inside the object
            # usually links back to the device. Let's cache both just in case.
            status_cache[item.get('id')] = item 
            if item.get('element_id'):
                status_cache[item.get('element_id')] = item

    # 6. Generate CSV
    csv_data = []
    print("\nMapping data...")

    for dev in filtered_elements:
        eid = dev.get('id')
        sid = dev.get('site_id')
        site_tags = site_tags_map.get(sid, [])
        
        # Try finding status by Element ID first
        stat = status_cache.get(eid, {})
        
        tag_str = "; ".join(site_tags)

        # Helpers
        def conn_state(field):
            val = stat.get(field)
            return "Connected" if val is True else "Disconnected" if val is False else "N/A"

        app_sig = stat.get('application_sig_file_info') or {}
        switch = stat.get('switch_state', {})

        row = {
            "Site Name": site_map.get(sid, "Unassigned"),
            "Device Name": dev.get('name'),
            "Site Tags": tag_str,
            "Serial Number": dev.get('serial_number'),
            "Software Version": dev.get('software_version'),
            "Model": dev.get('model_name'),
            "Device Mode": stat.get('device_mode', "N/A"),
            
            "Uptime Duration": calc_uptime(stat.get('last_rebooted_time')),
            "Last Reboot Date": fmt_time(stat.get('last_rebooted_time')),
            "Reboot Reason": stat.get('last_rebooted_info', "N/A").strip(),
            "Last Disconnect": fmt_time(stat.get('last_disconnected_time')),
            
            "Config Status": conn_state('config_and_events_connected'),
            "Config IP": stat.get('config_and_events_from', "N/A"),
            "Config Connect Time": fmt_time(stat.get('config_and_events_connected_on_utc')),

            "Analytics Status": conn_state('analytics_live_connected'),
            "Flows Status": conn_state('flows_live_connected'),
            "Logs Status": conn_state('logs_live_connected'),
            
            "App Sig Version": app_sig.get('active_application_sig_file', "N/A"),
            "App Sig Date": fmt_time(int(app_sig.get('application_sig_file_last_update', 0) or 0)),
            
            "PoE State": stat.get('poe_state', "N/A"),
            "STP Enabled": switch.get('mstp_enabled', "N/A"),
        }
        
        csv_data.append(row)
        print(f"Processed: {dev.get('name')}")

    if csv_data:
        filename = 'prisma_sdwan_full_audit.csv'
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
            writer.writeheader()
            writer.writerows(csv_data)
        print(f"\nSUCCESS: Audit complete. Saved to: {filename}")
    else:
        print("\nNo devices found matching criteria.")

if __name__ == "__main__":
    main()