import requests
import json
import csv
import argparse
from datetime import datetime, timezone, timedelta
import keyring
import sys
from typing import Dict, List, Any

# ---------- Constants ----------
SERVICE_NAME = "prismasase"
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_URL = "https://api.sase.paloaltonetworks.com"

def get_token():
    try:
        client_id = keyring.get_password(SERVICE_NAME, "client_id")
        client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
        tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")
        data = {"client_id": client_id, "client_secret": client_secret, "scope": f"tsg_id:{tsg_id}", "grant_type": "client_credentials"}
        r = requests.post(AUTH_URL, data=data)
        r.raise_for_status()
        return r.json()["access_token"]
    except Exception as e:
        print(f"Auth Error: {e}")
        sys.exit(1)

def get_profile(headers: Dict[str, str]):
    requests.get(f"{BASE_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

def get_site_id_by_name(headers, name):
    url = f"{BASE_URL}/sdwan/v4.11/api/sites"
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    for site in r.json().get('items', []):
        if site.get('name') == name:
            return site.get('id')
    print(f"ERROR: Could not find site named '{name}'")
    sys.exit(1)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-S", "--site", help="Site Name", required=True)
    args = parser.parse_args()

    token = get_token()
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json", "x-panw-region": "de"}
    get_profile(headers)

    print(f"[*] Looking up ID for site: {args.site}...")
    site_id = str(get_site_id_by_name(headers, args.site))

    # 1. Map Topology
    print("[*] Mapping Topology...")
    topo_url = f"{BASE_URL}/sdwan/v3.6/api/topology"
    topo_res = requests.post(topo_url, headers=headers, json={"type": "basenet", "nodes": [site_id]})
    topo_res.raise_for_status()
    
    path_map = {}
    for link in topo_res.json().get('links', []):
        # --- FILTER: Only VPN/Fabric types, ignore underlay stubs ---
        if link.get('type') not in ['vpn', 'servicelink', 'public-anynet', 'private-anynet']:
            continue
            
        pid = link.get('path_id')
        if pid:
            # Reconstruct names based on your preferred output
            src_wan = link.get('source_wan_network') or "WAN"
            dst_circuit = link.get('target_circuit_name') or link.get('target_wan_network') or "Remote"
            remote_site = link.get('target_site_name') if str(link.get('source_node_id')) == site_id else link.get('source_site_name')
            
            path_map[pid] = {
                "display_name": f"Circuit to {src_wan} -> Circuit to {dst_circuit}",
                "remote_context": f"@{remote_site}",
                "status": link.get('status', 'unknown')
            }

    # 2. Fetch LQM Metrics
    print("[*] Fetching Metrics...")
    now = datetime.now(timezone.utc)
    start_time = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    lqm_payload = {
        "start_time": start_time,
        "interval": "5min",
        "filter": {"site": [site_id], "path": list(path_map.keys())},
        "metrics": [
            {"name": "LqmLatencyPointMetric", "unit": "milliseconds"},
            {"name": "LqmMosPointMetric", "unit": "count"},
            {"name": "LqmPktLossPointMetric", "unit": "percentage"},
            {"name": "LqmJitterPointMetric", "unit": "milliseconds"}
        ]
    }
    lqm_res = requests.post(f"{BASE_URL}/sdwan/monitor/v2.0/api/monitor/lqm_point_metrics", headers=headers, json=lqm_payload)
    lqm_res.raise_for_status()

    # 3. Process Data
    results = {}
    for metric in lqm_res.json().get('metrics', []):
        m_name = metric['name']
        for site_data in metric.get('sites', []):
            for p in site_data.get('paths', []):
                pid = p['path_id']
                if pid not in path_map: continue
                
                meta = path_map[pid]
                if meta['status'].lower() != "up": continue

                if pid not in results:
                    results[pid] = {
                        "Name": meta['display_name'],
                        "Remote Site": meta['remote_context'],
                        "Connectivity": meta['status'],
                        "Packet Loss (%)": "0.0%",
                        "Jitter (ms)": "0.0",
                        "Latency (ms)": "0.0",
                        "Link MOS": "4.4"
                    }
                
                data = p['data']
                if m_name == "LqmLatencyPointMetric":
                    results[pid]["Latency (ms)"] = round(data.get('rtt_latency', 0), 1)
                elif m_name == "LqmJitterPointMetric":
                    # Use the average of available directions to ensure we don't get 0
                    results[pid]["Jitter (ms)"] = round((data.get('downlink_jitter_avg', 0) + data.get('uplink_jitter_avg', 0)) / 2, 2)
                elif m_name == "LqmPktLossPointMetric":
                    results[pid]["Packet Loss (%)"] = f"{round((data.get('downlink_pkt_loss_avg', 0) + data.get('uplink_pkt_loss_avg', 0)) / 2, 2)}%"
                elif m_name == "LqmMosPointMetric":
                    results[pid]["Link MOS"] = round(data.get('downlink_mos_avg', 0), 1)

    # 4. Export
    if results:
        filename = f"path_health_{args.site.replace(' ', '_')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(results[next(iter(results))].keys()))
            writer.writeheader()
            for row in results.values():
                # Final check: only output if we have real data (Latency > 0)
                if row["Latency (ms)"] != 0:
                    writer.writerow(row)
        print(f"\n[SUCCESS] Report generated: {filename}")
    else:
        print(f"\n[!] No active 'up' paths found.")

if __name__ == "__main__":
    main()