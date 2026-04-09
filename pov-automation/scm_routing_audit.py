import prisma_sase
import keyring
import sys
import ipaddress
import argparse
import json

# --- Configuration ---
SERVICE_NAME = "prismasase"
OUTPUT_FILE = "bgp_prefixes_export.json"

def is_private(network_str):
    """Returns True if the network is RFC 1918 (Private)."""
    try:
        return ipaddress.ip_network(network_str).is_private
    except ValueError:
        return False

def summarize_prefixes(prefix_list):
    """Collapses adjacent networks into larger aggregates (CIDR summarization)."""
    if not prefix_list:
        return []
    try:
        nets = [ipaddress.ip_network(p) for p in prefix_list]
        return [str(net) for net in ipaddress.collapse_addresses(nets)]
    except ValueError as e:
        return prefix_list

def get_bgp_prefixes(site_name, aggregate=False):
    # 1. Fetch Credentials
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"Error: Credentials not found for '{SERVICE_NAME}' in keyring.")
        sys.exit(1)

    # 2. Initialize and Authenticate
    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 3. Resolve Site
    sites_resp = sdk.get.sites()
    site = next((s for s in sites_resp.cgx_content.get("items", []) if s['name'] == site_name), None)
    if not site:
        print(f"❌ Site '{site_name}' not found.")
        return

    site_id = site['id']
    export_data = {"site_name": site_name, "site_id": site_id, "aggregated": aggregate, "elements": []}

    # 4. Fetch Elements
    elements_resp = sdk.get.elements()
    site_elements = [e for e in elements_resp.cgx_content.get("items", []) if e.get("site_id") == site_id]

    for element in site_elements:
        element_id = element['id']
        element_record = {"element_name": element['name'], "element_id": element_id, "peers": []}
        
        sep = "=" * 60
        print(f"\n{sep}\nELEMENT: {element['name']}\n{sep}")

        # --- UPDATED: Map Peer IDs to Names, VRFs, AND Configured IP ---
        peer_map = {}
        config_resp = sdk.get.bgppeers(site_id=site_id, element_id=element_id)
        if config_resp.cgx_status:
            for p_conf in config_resp.cgx_content.get("items", []):
                peer_map[p_conf['id']] = {
                    "name": p_conf.get("name", "Unnamed Peer"),
                    "vrf": p_conf.get("vrf_context_name", "Global"),
                    "conf_ip": p_conf.get("peer_ip", "N/A") # Grab IP from config
                }

        # 5. Fetch BGP Status
        status_resp = sdk.get.bgppeers_status(site_id=site_id, element_id=element_id)
        if status_resp.cgx_status:
            for peer_stat in status_resp.cgx_content.get("items", []):
                peer_id = peer_stat.get("id")
                state = peer_stat.get("state", "Unknown")
                
                # Pull metadata from our config map
                info = peer_map.get(peer_id, {"name": "Unknown", "vrf": "N/A", "conf_ip": "N/A"})
                
                # Fallback: If status API has 'peer_addr' (common for dynamic peers), use it
                display_ip = info['conf_ip']
                if display_ip == "N/A":
                    display_ip = peer_stat.get("peer_ip") or peer_stat.get("peer_addr") or "N/A"

                print(f"\n▶ Peer: {info['name']} ({display_ip}) | VRF: {info['vrf']} | State: {state}")

                if state.lower() != "established":
                    continue

                # 6. Fetch Reachable Prefixes
                prefix_resp = sdk.get.bgppeers_reachableprefixes(site_id, element_id, peer_id)
                if prefix_resp.cgx_status:
                    ipv4_data = prefix_resp.cgx_content.get("reachable_ipv4_prefixes", [])
                    raw_pvt = [p['network'] for p in ipv4_data if p.get('network') and is_private(p['network'])]
                    raw_pub = [p['network'] for p in ipv4_data if p.get('network') and not is_private(p['network'])]

                    final_pvt = summarize_prefixes(raw_pvt) if aggregate else raw_pvt
                    final_pub = summarize_prefixes(raw_pub) if aggregate else raw_pub

                    element_record["peers"].append({
                        "peer_name": info['name'],
                        "peer_ip": display_ip,
                        "vrf": info['vrf'],
                        "prefixes_private": final_pvt,
                        "prefixes_public": final_pub
                    })

                    if final_pvt:
                        print(f"  [Private RFC1918] ({len(final_pvt)}): {', '.join(final_pvt)}")
                    if final_pub:
                        print(f"  [Public Prefixes] ({len(final_pub)}): {', '.join(final_pub)}")
        
        export_data["elements"].append(element_record)

    # 7. Write to JSON file
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(export_data, f, indent=4)
    print(f"\n{'-'*60}\n✅ Export complete! Results saved to: {OUTPUT_FILE}\n{'-'*60}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Prisma SASE BGP Route Fetcher")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-A", "--aggregate", action="store_true", help="Aggregate prefixes")
    args = parser.parse_args()
    get_bgp_prefixes(args.site, args.aggregate)
