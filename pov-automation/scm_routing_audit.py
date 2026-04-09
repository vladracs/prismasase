import requests
import json
import csv
import argparse
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

    # 1. Resolve specific Site ID
    print(f"[*] Resolving Site: {args.site}...")
    site_id = get_site_id_by_name(headers, args.site)
    
    # 2. Get ONLY Elements bound to this specific site
    # Using the site-nested elements endpoint for strict filtering
    elem_url = f"{BASE_URL}/sdwan/v4.11/api/sites/{site_id}/elements"
    elements = requests.get(elem_url, headers=headers).json().get('items', [])
    
    csv_data = []

    for dev in elements:
        eid = dev['id']
        dev_name = dev['name']
        print(f"  [+] Auditing Site Device: {dev_name}")

        # 3. BGP Peers
        bgp_url = f"{BASE_URL}/sdwan/v3.0/api/sites/{site_id}/elements/{eid}/bgppeers"
        peers = requests.get(bgp_url, headers=headers).json().get('items', [])

        for peer in peers:
            pid = peer['id']
            # Prefixes Received
            r_url = f"{BASE_URL}/sdwan/v2.1/api/sites/{site_id}/elements/{eid}/bgppeers/{pid}/reachableprefixes"
            r_prefixes = requests.get(r_url, headers=headers).json().get('reachable_prefixes', {})
            
            # Prefixes Advertised
            a_url = f"{BASE_URL}/sdwan/v2.1/api/sites/{site_id}/elements/{eid}/bgppeers/{pid}/advertisedprefixes"
            a_prefixes = requests.get(a_url, headers=headers).json().get('advertised_prefixes', {})

            csv_data.append({
                "Site": args.site,
                "Device": dev_name,
                "Route Type": "BGP PEER",
                "Neighbor/Prefix": peer.get('peer_ip', 'N/A'),
                "Status/NextHop": peer.get('state', 'N/A'),
                "Rx Prefixes": len(r_prefixes),
                "Tx Prefixes": len(a_prefixes)
            })

        # 4. Static Routes
        static_url = f"{BASE_URL}/sdwan/v2.3/api/sites/{site_id}/elements/{eid}/staticroutes"
        statics = requests.get(static_url, headers=headers).json().get('items', [])

        for route in statics:
            csv_data.append({
                "Site": args.site,
                "Device": dev_name,
                "Route Type": "STATIC",
                "Neighbor/Prefix": route.get('destination_prefix', 'N/A'),
                "Status/NextHop": route.get('nexthop_ip', 'N/A'),
                "Rx Prefixes": "N/A",
                "Tx Prefixes": "N/A"
            })

    # 5. Output
    if csv_data:
        filename = f"routing_{args.site.replace(' ', '_')}.csv"
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=csv_data[0].keys())
            writer.writeheader()
            writer.writerows(csv_data)
        print(f"\n[SUCCESS] Routing report for {args.site} generated: {filename}")
    else:
        print(f"\n[!] No BGP or Static routing data found on the device(s) at {args.site}.")

if __name__ == "__main__":
    main()
