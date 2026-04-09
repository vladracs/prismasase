import prisma_sase
import keyring
import sys
import ipaddress

# --- Configuration ---
SERVICE_NAME = "prismasase"

def is_private(network_str):
    """Returns True if the network is RFC 1918 (Private)."""
    try:
        return ipaddress.ip_network(network_str).is_private
    except ValueError:
        return False

def get_bgp_prefixes(site_name):
    # 1. Fetch Credentials from Keyring
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"Error: Credentials not found for '{SERVICE_NAME}' in keyring.")
        sys.exit(1)

    # 2. Initialize and Authenticate
    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    login_success = sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    if not login_success:
        print("SDK Login failed.")
        return

    # 3. Resolve Site Name to ID
    sites_resp = sdk.get.sites()
    site = next((s for s in sites_resp.cgx_content.get("items", []) if s['name'] == site_name), None)

    if not site:
        print(f"❌ Site '{site_name}' not found.")
        return

    site_id = site['id']
    print(f"--- Site: {site_name} (ID: {site_id}) ---")

    # 4. Fetch Elements (IONs) for the Site
    elements_resp = sdk.get.elements()
    site_elements = [e for e in elements_resp.cgx_content.get("items", []) if e.get("site_id") == site_id]

    # 5. Process each Element
    for element in site_elements:
        element_id = element['id']
        sep = "=" * 60
        print(f"\n{sep}\nELEMENT: {element['name']} ({element_id})\n{sep}")

        # Fetch Peer Configs to map IDs to Names and VRFs
        peer_map = {}
        config_resp = sdk.get.bgppeers(site_id=site_id, element_id=element_id)
        if config_resp.cgx_status:
            for p_conf in config_resp.cgx_content.get("items", []):
                peer_map[p_conf['id']] = {
                    "name": p_conf.get("name", "Unnamed Peer"),
                    "vrf": p_conf.get("vrf_context_name", "Global/Default")
                }

        # Fetch real-time BGP status
        status_resp = sdk.get.bgppeers_status(site_id=site_id, element_id=element_id)
        if not status_resp.cgx_status:
            print("  - Could not fetch BGP status for this element.")
            continue

        peers = status_resp.cgx_content.get("items", [])
        for peer in peers:
            bgppeer_id = peer.get("id")
            state = peer.get("state", "Unknown")
            peer_ip = peer.get("peer_ip", "N/A")
            
            # Lookup name and VRF from our config map
            info = peer_map.get(bgppeer_id, {"name": "Unknown", "vrf": "N/A"})

            print(f"\n▶ Peer: {info['name']} ({peer_ip})")
            print(f"  VRF: {info['vrf']} | State: {state}")

            if state.lower() != "established":
                continue

            # 6. Fetch actual Reachable Prefixes
            prefix_resp = sdk.get.bgppeers_reachableprefixes(
                site_id=site_id, 
                element_id=element_id, 
                bgppeer_id=bgppeer_id
            )

            if prefix_resp.cgx_status:
                ipv4_data = prefix_resp.cgx_content.get("reachable_ipv4_prefixes", [])
                
                private_ips = []
                public_ips = []

                for item in ipv4_data:
                    net = item.get("network")
                    if not net: continue
                    
                    if is_private(net):
                        private_ips.append(net)
                    else:
                        public_ips.append(net)

                # Output categorized results
                if private_ips:
                    print(f"  [Private RFC1918] ({len(private_ips)}):")
                    print(f"    {', '.join(private_ips)}")
                
                if public_ips:
                    print(f"  [Public Prefixes] ({len(public_ips)}):")
                    print(f"    {', '.join(public_ips)}")
                
                if not private_ips and not public_ips:
                    print("  - No prefixes received.")
            else:
                print(f"    - Error fetching prefixes.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 sdk_bgp_routes.py \"SITE_NAME\"")
        sys.exit(1)
    
    get_bgp_prefixes(sys.argv[1])
