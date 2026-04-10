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
        "grant_type": "client_credentials",
    }
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_profile(headers: Dict[str, str]):
    requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

def get_sys_metrics(headers: Dict[str, str], site_id: str, element_id: str, debug=False):
    url = f"{BASE_API_URL}/sdwan/monitor/v2.3/api/monitor/sys_metrics"
    
    # Using the window from your successful curl
    payload = {
        "start_time": "2026-02-22T09:52:00.000Z",
        "end_time": "2026-02-23T09:47:00.000Z",
        "filter": {
            "site": [site_id],
            "element": [element_id]
        },
        "interval": "5min",
        "metrics": [
            {"name": "CPUUsage", "statistics": ["max", "average"], "unit": "percentage"},
            {"name": "MemoryUsage", "statistics": ["max", "average"], "unit": "percentage"},
            {"name": "DiskUsage", "statistics": ["max"], "unit": "percentage"},
            {"name": "DeviceCpuTemperature", "statistics": ["max"], "unit": "celsius"}
        ],
        "view": {"summary": True} 
    }

    print(f"\n--- REQUESTING METRICS FOR ELEMENT: {element_id} ---")
    try:
        res = requests.post(url, headers=headers, json=payload)
        
        # --- THIS PRINTS THE RAW API RESPONSE ---
        print(f"STATUS CODE: {res.status_code}")
        #print("RAW RESPONSE BODY:")
        #print(res.text) 
        print("---------------------------------------------------\n")
        
        if res.status_code == 200:
            return res.json().get('metrics', [])
            
    except Exception as e:
        print(f"    [!] Metric Request Exception: {e}")
    return []

def parse_summary_v2(metrics_list: List[Dict], metric_name: str, stat_type: str):
    """
    Robust parser for: metrics[] -> series[] -> data[] -> datapoints[]
    Handles cases where 'name' might be missing or nested differently.
    """
    if not metrics_list:
        return "N/A"

    for m in metrics_list:
        # Check if the name matches OR if there's only one metric and we're desperate
        api_metric_name = m.get('name')
        
        # If we requested one metric and the API didn't label it, we proceed anyway
        if api_metric_name == metric_name or api_metric_name is None:
            series = m.get('series', [])
            for s in series:
                # 1. Try Summary Object (Most efficient)
                summary = s.get('summary', {})
                if summary and stat_type in summary:
                    return round(summary[stat_type], 2)
                
                # 2. Dig into Data -> Datapoints
                data_list = s.get('data', [])
                for d in data_list:
                    # Match the statistic (max/average)
                    if d.get('statistics') == stat_type:
                        dps = d.get('datapoints', [])
                        # Extract non-null values
                        valid_vals = [dp['value'] for dp in dps if dp.get('value') is not None]
                        if valid_vals:
                            # Return the latest one
                            return round(valid_vals[-1], 2)
                            
    return "N/A"

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-T", "--tags", help="Filter by Site Tags (comma separated)", type=str)
    parser.add_argument("--debug", action="store_true", help="Print raw metric JSON for the first device")
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de" 
    }

    get_profile(headers)

    print("[*] Fetching Sites and Elements...")
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    sites = sites_res.json().get('items', [])
    
    # Use string keys for ID map to prevent matching issues
    site_map = {str(s['id']): s['name'] for s in sites}
    site_tags_map = {str(s['id']): (s.get('tags') or []) for s in sites}

    elements_res = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements", headers=headers)
    elements = elements_res.json().get('items', [])

    target_tags = [t.strip() for t in args.tags.split(',')] if args.tags else []
    csv_data = []

    has_debugged = False

    print(f"[*] Processing telemetry for {len(elements)} elements...")

    for dev in elements:
        sid = str(dev.get('site_id'))
        eid = str(dev.get('id'))
        
        # Filter logic
        site_tags = site_tags_map.get(sid, [])
        if target_tags and not any(tag in site_tags for tag in target_tags):
            continue

        print(f"  [>] Collecting: {dev['name']} ({site_map.get(sid, 'Unassigned')})")
        
        # Call API
        do_debug = args.debug and not has_debugged
        metrics_raw = get_sys_metrics(headers, sid, eid, debug=do_debug)
        if do_debug: has_debugged = True

        # Build Row
        row = {
            "Site": site_map.get(sid, "Unassigned"),
            "Device": dev['name'],
            "CPU Avg (%)": parse_summary_v2(metrics_raw, "CPUUsage", "average"),
            "CPU Max (%)": parse_summary_v2(metrics_raw, "CPUUsage", "max"),
            "Mem Avg (%)": parse_summary_v2(metrics_raw, "MemoryUsage", "average"),
            "Mem Max (%)": parse_summary_v2(metrics_raw, "MemoryUsage", "max"),
            "Disk Max (%)": parse_summary_v2(metrics_raw, "DiskUsage", "max"),
            "CPU Temp Max (C)": parse_summary_v2(metrics_raw, "DeviceCpuTemperature", "max")
        }
        csv_data.append(row)
        # ADD THIS LINE TO PRINT TO TERMINAL:
        #print(f"    -> CPU: {row['CPU Max (%)']}% | Mem: {row['Mem Max (%)']}% | Temp: {row['CPU Temp Max (C)']}C")
    # Export
    if csv_data:
        filename = "sdwan_pov_telemetry_report.csv"
        keys = csv_data[0].keys()
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(csv_data)
        print(f"\n[SUCCESS] POV Report generated: {filename}")
    else:
        print("\n[!] No devices matching those criteria were found.")

if __name__ == "__main__":
    main()