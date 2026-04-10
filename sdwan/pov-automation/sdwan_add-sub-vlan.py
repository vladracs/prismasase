import os
import json
import argparse
import requests
import keyring
import sys
from typing import Dict, Any, List, Optional

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
        r.raise_for_status()
        return r.json()["access_token"]
    except Exception as e:
        print(f"Auth Failed: {e}")
        sys.exit(1)

def get_profile(headers: Dict[str, str]):
    try:
        requests.get(f"{BASE_API_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
        print("[*] Profile Initialized")
    except Exception as e:
        print(f"Profile Init Failed: {e}")
        sys.exit(1)

def find_item(items: List[Dict], name: str, label: str) -> Dict:
    """Finds the full object by name (case-insensitive)."""
    target = name.strip().lower()
    for item in items:
        # Check name, display_name, model_name
        if (item.get('name') or '').lower() == target: return item
        if (item.get('display_name') or '').lower() == target: return item
        if (item.get('model_name') or '').lower() == target: return item
    
    print(f"[!] Error: Could not find {label} named '{name}'")
    sys.exit(1)

# ---------- Main Logic ----------
def main():
    parser = argparse.ArgumentParser(description="Create Sub-interface using Parent Config")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device Name")
    parser.add_argument("-I", "--interface", required=True, help="Parent Interface Name (e.g. '1', 'Ethernet 1')")
    parser.add_argument("--vlan", required=True, help="VLAN ID (e.g. 110)")
    parser.add_argument("--ip", required=True, help="IP/CIDR (e.g. 192.168.110.1/24)")
    parser.add_argument("--desc", help="Description", default=None)
    args = parser.parse_args()

    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "americas" # Adjust region if needed (e.g., 'de')
    }

    # 1. Init Profile
    get_profile(headers)

    # 2. Get Site ID
    print(f"[*] Locating Site '{args.site}'...")
    sites_resp = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    sites_resp.raise_for_status()
    site_obj = find_item(sites_resp.json().get('items', []), args.site, "Site")
    site_id = site_obj['id']

    # 3. Get Device ID
    print(f"[*] Locating Device '{args.device}'...")
    elems_resp = requests.get(f"{BASE_API_URL}/sdwan/v3.2/api/elements?site_id={site_id}", headers=headers)
    elems_resp.raise_for_status()
    dev_obj = find_item(elems_resp.json().get('items', []), args.device, "Device")
    element_id = dev_obj['id']

    # 4. Get Parent Interface & Extract Info
    print(f"[*] Fetching interfaces for '{args.device}'...")
    intf_url = f"{BASE_API_URL}/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"
    intf_resp = requests.get(intf_url, headers=headers)
    intf_resp.raise_for_status()
    
    # Find the specific parent object
    parent_obj = find_item(intf_resp.json().get('items', []), args.interface, "Interface")
    
    parent_id = parent_obj['id']
    vrf_id = parent_obj.get('vrf_context_id')
    
    print(f"    -> Found Parent: {parent_obj['name']}")
    print(f"    -> Parent ID:    {parent_id}")
    print(f"    -> Parent VRF:   {vrf_id}")

    if not vrf_id:
        print("[!] Warning: Parent interface has no VRF ID. Sub-interface creation might fail if VRF is required.")

    # 5. Build Payload
    description = args.desc if args.desc else f"subinterface vlan {args.vlan}"
    
    payload = {
        "parent": parent_id,
        "type": "subinterface",
        "used_for": "lan",
        "power_usage_threshold": 0,
        "mtu": 0,  # 0 usually means inherit
        "name": "", # Name is auto-generated typically for sub-interfaces or optional
        "description": description,
        "attached_lan_networks": None,
        "site_wan_interface_ids": None,
        "mac_address": None,
        "ipv4_config": {
            "dhcp_config": None,
            "type": "static",
            "routes": None,
            "dns_v4_config": {
                "name_servers": []
            },
            "static_config": {
                "address": args.ip
            }
        },
        "ipv6_config": None,
        "dhcp_relay": None,
        "ethernet_port": {
            "full_duplex": False,
            "speed": 0
        },
        "admin_up": True, # Note: boolean true in Python, 'true' string in your snippet? API usually wants boolean.
        "nat_address": None,
        "nat_port": None,
        "nat_address_v6": None,
        "nat_port_v6": 0,
        "bound_interfaces": None,
        "sub_interface": {
            "vlan_id": args.vlan,
            "native_vlan": False
        },
        "pppoe_config": None,
        "network_context_id": None,
        "bypass_pair": None,
        "peer_bypasspair_wan_port_type": "none",
        "port_channel_config": None,
        "service_link_config": None,
        "sgi_apply_static_tag": None,
        "scope": "global", # or "local", usually matches parent or global
        "tags": None,
        "nat_zone_id": None,
        "devicemgmt_policysetstack_id": None,
        "nat_pools": None,
        "directed_broadcast": False,
        "ipfixcollectorcontext_id": None,
        "ipfixfiltercontext_id": None,
        "secondary_ip_configs": None,
        "static_arp_configs": None,
        "cellular_config": None,
        "multicast_config": None,
        "poe_enabled": False,
        "lldp_enabled": None,
        "switch_port_config": None,
        "authentication_config": None,
        "vlan_config": None,
        "interface_profile_id": None,
        "vrf_context_id": vrf_id, # Inherited from parent
        "fec_mode": None,
        "loopback_config": None
    }

    # 6. Push Configuration
    print(f"[*] Pushing new sub-interface (VLAN {args.vlan}) to {args.device}...")
    
    try:
        post_resp = requests.post(intf_url, headers=headers, json=payload)
        
        if post_resp.status_code in [200, 201]:
            new_item = post_resp.json()
            print(f"\n[SUCCESS] Created Sub-interface!")
            print(f"          ID: {new_item.get('id')}")
            print(f"          Name: {new_item.get('name')}")
        else:
            print(f"\n[FAILED] Status Code: {post_resp.status_code}")
            print(f"Response: {post_resp.text}")
            
    except Exception as e:
        print(f"[!] Request Exception: {e}")

if __name__ == "__main__":
    main()