import os
import requests
import json
import csv
import argparse
import sys
import keyring
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List

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

def get_interface_bandwidth(headers: Dict[str, str], site_id: str, element_id: str, interface_id: str) -> str:
    """Fetches the latest bandwidth utilization for a specific interface."""
    url = f"{BASE_API_URL}/sdwan/monitor/v2.3/api/monitor/sys_metrics"
    
    # Using a 24h window (or 1h for faster response)
    now = datetime.now(timezone.utc)
    end_time = now - timedelta(minutes=5)
    start_time = end_time - timedelta(hours=24)

    payload = {
        "start_time": start_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "end_time": end_time.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "filter": {
            "site": [site_id],
            "element": [element_id],
            "interface": [interface_id]
        },
        "interval": "5min",
        "metrics": [{"name": "InterfaceBandwidthUsage", "statistics": ["average"], "unit": "Mbps"}],
        "view": {"individual": "interface", "summary": True}
    }

    try:
        res = requests.post(url, headers=headers, json=payload)
        if res.status_code == 200:
            metrics = res.json().get('metrics', [])
            for m in metrics:
                # Same robust parsing as telemetry script
                for series in m.get('series', []):
                    # Check summary first
                    summary = series.get('summary', {})
                    if summary and 'average' in summary:
                        return f"{round(summary['average'], 2)} Mbps"
                    
                    # Fallback to last datapoint
                    for data_group in series.get('data', []):
                        dps = data_group.get('datapoints', [])
                        valid_vals = [dp['value'] for dp in dps if dp.get('value') is not None]
                        if valid_vals:
                            return f"{round(valid_vals[-1], 2)} Mbps"
    except:
        pass
    return "0.00 Mbps"

# ---------- Main Logic ----------

def main():
    parser = argparse.ArgumentParser(description="Interface Audit (IP, MAC & Utilization)")
    parser.add_argument("-T", "--tags", help="Filter by Site Tags", type=str)
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de" 
    }

    get_profile(headers)

    # 1. Get Sites
    print("[*] Fetching Sites...")
    sites = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers).json().get('items', [])
    target_tags = [t.strip() for t in args.tags.split(',')] if args.tags else []
    
    csv_data = []

    for site in sites:
        site_id = site['id']
        site_name = site['name']
        if target_tags and not any(tag in (site.get('tags') or []) for tag in target_tags):
            continue

        print(f"[*] Site: {site_name}")

        # 2. Get Elements
        elements = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements?site_id={site_id}", headers=headers).json().get('items', [])

        for dev in elements:
            element_id = dev['id']
            print(f"  [+] Device: {dev['name']}")

            # 3. Get Interfaces
            intf_url = f"{BASE_API_URL}/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"
            intfs = requests.get(intf_url, headers=headers).json().get('items', [])

            for i in intfs:
                intf_id = i['id']
                
                # 4. Get Status (MAC/IP)
                status_url = f"{BASE_API_URL}/sdwan/v3.9/api/sites/{site_id}/elements/{element_id}/interfaces/{intf_id}/status"
                try:
                    s_res = requests.get(status_url, headers=headers)
                    if s_res.status_code == 200:
                        stat = s_res.json()
                        op_state = stat.get('operational_state', 'down')
                        
                        # 5. Get Utilization ONLY if interface is UP
                        utilization = "0.00 Mbps"
                        if op_state == "up":
                            utilization = get_interface_bandwidth(headers, site_id, element_id, intf_id)

                        ip_val = stat.get('ipv4_addresses')
                        ip_str = ", ".join(ip_val) if isinstance(ip_val, list) else "N/A"

                        csv_data.append({
                            "Site": site_name,
                            "Device": dev['name'],
                            "Interface": i['name'],
                            "State": op_state,
                            "MAC Address": stat.get('mac_address', "N/A"),
                            "IPv4 Address": ip_str,
                            "Utilization (Avg 24h)": utilization,
                            "Used For": i.get('used_for'),
                            "VRF": stat.get('vrf', {}).get('vrf_context_name', "Global")
                        })
                        print(f"      - {i['name']}: {op_state} ({utilization})")
                except Exception as e:
                    print(f"    [!] Error on {i['name']}: {e}")

    # 6. Write CSV
    if csv_data:
        filename = 'interface_bandwidth_audit.csv'
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
            writer.writeheader()
            writer.writerows(csv_data)
        print(f"\n[SUCCESS] Report generated: {filename}")

if __name__ == "__main__":
    main()