#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

import os
import json
import argparse
import requests
from typing import Dict, Any, List, Optional

# ---------- Constants ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

def _must_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    data = {
        "client_id": _must_env("PRISMASASE_CLIENT_ID"),
        "client_secret": _must_env("PRISMASASE_CLIENT_SECRET"),
        "scope": f"tsg_id:{_must_env('PRISMASASE_TSG_ID')}",
        "grant_type": "client_credentials",
    }
    r = requests.post(AUTH_URL, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_headers(token: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de", # adjust if your tenant region differs
    }

def get_profile(token: str, headers: Dict[str, str]) -> Dict[str, Any]:
    # Mandatory first API call for Prisma SD-WAN
    url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    print("profile api status: 200")
    return r.json()

def find_id_by_name(items: List[Dict[str, Any]], target_name: str) -> Optional[str]:
    for item in items:
        # Check both 'name' and 'display_name' common in SD-WAN API
        if item.get("name") == target_name or item.get("display_name") == target_name:
            return str(item.get("id"))
    return None

def main():
    parser = argparse.ArgumentParser(description="Add Prisma SD-WAN Sub-interface")
    parser.add_argument("-S", "--site", required=True, help="Site Name")
    parser.add_argument("-D", "--device", required=True, help="Device (Element) Name")
    parser.add_argument("-I", "--interface", required=True, help="Parent Interface Name")
    parser.add_argument("-P", "--parameters", required=True, help="Path to parameters.txt")
    args = parser.parse_args()

    # 1. Auth & Profile (Mandatory)
    token = get_token()
    headers = get_headers(token)
    get_profile(token, headers)

    # 2. Resolve Site ID
    sites_res = requests.get(f"{BASE_API_URL}/sdwan/v4.11/api/sites", headers=headers)
    site_id = find_id_by_name(sites_res.json().get("items", []), args.site)
    if not site_id:
        print(f"Error: Site '{args.site}' not found.")
        return

    # 3. Resolve Element ID
    elems_res = requests.get(f"{BASE_API_URL}/sdwan/v3.1/api/elements", headers=headers)
    # Filter elements belonging to this site
    site_elements = [e for e in elems_res.json().get("items", []) if str(e.get("site_id")) == site_id]
    element_id = find_id_by_name(site_elements, args.device)
    if not element_id:
        print(f"Error: Device '{args.device}' not found in site.")
        return

    # 4. Resolve Parent Interface ID
    intf_url = f"{BASE_API_URL}/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"
    intfs_res = requests.get(intf_url, headers=headers)
    parent_id = find_id_by_name(intfs_res.json().get("items", []), args.interface)
    if not parent_id:
        print(f"Error: Parent interface '{args.interface}' not found.")
        return

    # 5. Load Payload and Post
    with open(args.parameters, 'r') as f:
        payload = json.load(f)
    #example payload json file
    payload = {
  "parent": "1741294034078022545",
  "type": "subinterface",
  "used_for": "lan",
  "power_usage_threshold": 0,
  "mtu": 0,
  "name": "",
  "description": "transfer vlan 110",
  "attached_lan_networks": null,
  "site_wan_interface_ids": null,
  "mac_address": null,
  "ipv4_config": {
    "dhcp_config": null,
    "type": "static",
    "routes": null,
    "dns_v4_config": {
      "name_servers": []
    },
    "static_config": {
      "address": "192.168.110.1/24"
    }
  },
  "ipv6_config": null,
  "dhcp_relay": null,
  "ethernet_port": {
    "full_duplex": false,
    "speed": 0
  },
  "admin_up": "true",
  "nat_address": null,
  "nat_port": null,
  "nat_address_v6": null,
  "nat_port_v6": 0,
  "bound_interfaces": null,
  "sub_interface": {
    "vlan_id": "110",
    "native_vlan": false
  },
  "pppoe_config": null,
  "network_context_id": null,
  "bypass_pair": null,
  "peer_bypasspair_wan_port_type": "none",
  "port_channel_config": null,
  "service_link_config": null,
  "sgi_apply_static_tag": null,
  "scope": "global",
  "tags": null,
  "nat_zone_id": null,
  "devicemgmt_policysetstack_id": null,
  "nat_pools": null,
  "directed_broadcast": false,
  "ipfixcollectorcontext_id": null,
  "ipfixfiltercontext_id": null,
  "secondary_ip_configs": null,
  "static_arp_configs": null,
  "cellular_config": null,
  "multicast_config": null,
  "poe_enabled": false,
  "lldp_enabled": null,
  "switch_port_config": null,
  "authentication_config": null,
  "vlan_config": null,
  "interface_profile_id": null,
  "vrf_context_id": "1737015242377022245",
  "fec_mode": null,
  "loopback_config": null
}
    payload["parent"] = parent_id
    
    print(f"Adding sub-interface to {args.device}...")
    resp = requests.post(intf_url, headers=headers, json=payload)
    
    if resp.status_code in [200, 201]:
        print("Success!")
        print(json.dumps(resp.json(), indent=2))
    else:
        print(f"Failed: {resp.status_code} - {resp.text}")

if __name__ == "__main__":
    main()
