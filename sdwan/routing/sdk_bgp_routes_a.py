import prisma_sase
import keyring
import sys
import ipaddress
import argparse
import json

# --- Configuration ---
SERVICE_NAME = "tenant2"
OUTPUT_FILE = "bgp_prefixes_export.json"

def is_private(network_str):
    """Returns True if the network is RFC 1918 (Private)."""
    try:
        return ipaddress.ip_network(network_str).is_private
    except ValueError:
        return False

def summarize_prefixes(prefix_list):
    """
    Collapses adjacent networks into larger aggregates.
    This uses standard CIDR math (no 'loose' aggregation).
    """
    if not prefix_list:
        return []
    try:
        # Cast to set to remove exact duplicates first
        nets = [ipaddress.ip_network(p) for p in set(prefix_list) if p]
        # collapse_addresses returns an iterator of the most concise CIDR representation
        return [str(net) for net in ipaddress.collapse_addresses(nets)]
    except ValueError as e:
        print(f"⚠️ Error during summarization: {e}")
        return list(set(prefix_list))

def update_enterprise_prefixes(sdk, new_prefixes):
    """Fetches existing prefixes, merges with new ones, and pushes update."""
    print(f"\n--- Updating Enterprise Global Prefixes ---")
    
    current_resp = sdk.get.enterpriseprefixset()
    if not current_resp.cgx_status:
        print("❌ Failed to fetch current Enterprise Prefix Set.")
        return

    data = current_resp.cgx_content
    existing_v4 = data.get("ipv4_enterprise_prefixes", []) or []
    etag = data.get("_etag")

    # Combine existing with new, then summarize the whole batch
    combined_v4 = summarize_prefixes(existing_v4 + new_prefixes)
    
    payload = {
        "ipv4_enterprise_prefixes": combined_v4,
        "ipv6_enterprise_prefixes": data.get("ipv6_enterprise_prefixes", []) or [],
        "_etag": etag
    }

    update_resp = sdk.put.enterpriseprefixset(data=payload)
    if update_resp.cgx_status:
        print(f"✅ Successfully updated Enterprise Prefixes.")
        print(f"📊 Before: {len(existing_v4)} | After: {len(combined_v4)} prefixes.")
    else:
        print(f"❌ Update failed: {json.dumps(update_resp.cgx_content, indent=2)}")

def run_bgp_sync(site_name, aggregate=False, update_global=False):
    # 1. Auth
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"Error: Credentials not found for '{SERVICE_NAME}'.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Resolve Site
    sites_resp = sdk.get.sites()
    site = next((s for s in sites_resp.cgx_content.get("items", []) if s['name'] == site_name), None)
    if not site:
        print(f"❌ Site '{site_name}' not found.")
        return

    site_id = site['id']
    all_found_prefixes = []
    export_data = {"site_name": site_name, "elements": []}

    # 3. Fetch Elements for Site
    elements_resp = sdk.get.elements()
    site_elements = [e for e in elements_resp.cgx_content.get("items", []) if e.get("site_id") == site_id]

    for element in site_elements:
        el_id = element['id']
        el_record = {"element_name": element['name'], "peers": []}
        print(f"\nInspecting Element: {element['name']}")

        # Map Peer Config (for names/VRFs)
        peer_map = {}
        conf_resp = sdk.get.bgppeers(site_id=site_id, element_id=el_id)
        if conf_resp.cgx_status:
            for p in conf_resp.cgx_content.get("items", []):
                peer_map[p['id']] = {"name": p.get("name"), "vrf": p.get("vrf_context_name")}

        # Get Runtime Status
        stat_resp = sdk.get.bgppeers_status(site_id=site_id, element_id=el_id)
        if not stat_resp.cgx_status: continue

        for peer_stat in stat_resp.cgx_content.get("items", []):
            p_id = peer_stat.get("id")
            if peer_stat.get("state") != "Established": continue

            info = peer_map.get(p_id, {"name": "Unknown", "vrf": "Global"})
            
            # Fetch Routes
            pref_resp = sdk.get.bgppeers_reachableprefixes(site_id, el_id, p_id)
            if pref_resp.cgx_status:
                raw_routes = [r['network'] for r in pref_resp.cgx_content.get("reachable_ipv4_prefixes", []) if r.get('network')]
                
                # We filter out private IPs if you only want Public in the Global list, 
                # OR keep all. Here we collect everything for the summary.
                all_found_prefixes.extend(raw_routes)

                # Local per-peer summary for the JSON log
                summ_routes = summarize_prefixes(raw_routes) if aggregate else raw_routes
                el_record["peers"].append({
                    "peer_name": info['name'],
                    "vrf": info['vrf'],
                    "count": len(summ_routes),
                    "prefixes": summ_routes
                })
                print(f"  └─ Peer {info['name']}: Found {len(raw_routes)} routes.")

        export_data["elements"].append(el_record)

    # 4. Save Log
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(export_data, f, indent=4)

    # 5. Update Global Prefix Set
    if update_global and all_found_prefixes:
        # Usually, you only want to push PUBLIC prefixes to the Enterprise Set 
        # to assist with Traffic Steering/Path selection for internet traffic.
        # If you want everything, remove the 'not is_private' filter.
        public_only = [p for p in all_found_prefixes if not is_private(p)]
        update_enterprise_prefixes(sdk, public_only)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-S", "--site", required=True)
    parser.add_argument("-A", "--aggregate", action="store_true", help="Aggregate in JSON output")
    parser.add_argument("-U", "--update", action="store_true", help="Update Enterprise Prefix Set")
    args = parser.parse_args()
    
    run_bgp_sync(args.site, args.aggregate, args.update)