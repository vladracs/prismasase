import requests
import json
import argparse
import keyring
import sys
import os
import dns.resolver
from typing import Dict, List, Any

# ---------- Constants ----------
SERVICE_NAME = "prismasase"
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_URL = "https://api.sase.paloaltonetworks.com"

# Configuration
TARGET_LIST_NAME = "API-GENERATED"  # Change this to MIST-IP or any other name
DOMAIN_FILE = "domains.txt"
DNS_SERVERS = ["8.8.8.8", "208.67.222.222"]

def get_token():
    try:
        client_id = keyring.get_password(SERVICE_NAME, "client_id")
        client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
        tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")
        data = {
            "client_id": client_id, 
            "client_secret": client_secret, 
            "scope": f"tsg_id:{tsg_id}", 
            "grant_type": "client_credentials"
        }
        r = requests.post(AUTH_URL, data=data)
        r.raise_for_status()
        return r.json()["access_token"]
    except Exception as e:
        print(f"Auth Error: {e}")
        sys.exit(1)

def get_profile(headers: Dict[str, str]):
    requests.get(f"{BASE_URL}/sdwan/v2.1/api/profile", headers=headers).raise_for_status()
    print("[*] Profile Initialized")

def resolve_domains_to_prefixes():
    if not os.path.exists(DOMAIN_FILE):
        print(f"[!] Error: {DOMAIN_FILE} not found.")
        sys.exit(1)

    resolved_set = set()
    resolver = dns.resolver.Resolver()
    resolver.nameservers = DNS_SERVERS
    
    with open(DOMAIN_FILE, 'r') as f:
        domains = [line.strip() for line in f if line.strip()]

    print(f"[*] Resolving {len(domains)} domains using DNS {DNS_SERVERS}...")
    for domain in domains:
        try:
            answers = resolver.resolve(domain, 'A')
            for data in answers:
                resolved_set.add(f"{data.to_text()}/32")
            print(f"  [+] {domain} resolved.")
        except Exception as e:
            print(f"  [!] {domain} failed: {e}")

    return list(resolved_set)

def get_prefix_list_by_name(headers, name):
    """Searches for the prefix list by name and returns the full object."""
    url = f"{BASE_URL}/sdwan/v2.1/api/networkpolicyglobalprefixes"
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    
    items = r.json().get("items", [])
    for item in items:
        if item.get("name") == name:
            return item
    
    print(f"ERROR: Prefix list named '{name}' not found.")
    sys.exit(1)

def update_global_prefix_list(headers, new_prefixes):
    # 1. Dynamically find the list by name
    print(f"[*] Searching for global prefix list: {TARGET_LIST_NAME}...")
    current_obj = get_prefix_list_by_name(headers, TARGET_LIST_NAME)
    
    list_id = current_obj.get("id")
    current_prefixes = set(current_obj.get("ipv4_prefixes") or [])
    
    # 2. Check if update is needed
    if set(new_prefixes) == current_prefixes:
        print(f"[+] '{TARGET_LIST_NAME}' is already in sync. No update needed.")
        return

    # 3. Build PUT Payload
    url = f"{BASE_URL}/sdwan/v2.1/api/networkpolicyglobalprefixes/{list_id}"
    payload = {
        "id": list_id,
        "name": current_obj.get("name"),
        "description": current_obj.get("description"),
        "tags": current_obj.get("tags") or [],
        "ipv4_prefixes": new_prefixes,
        "ipv6_prefixes": current_obj.get("ipv6_prefixes") or [],
        "_etag": current_obj.get("_etag"),
        "_schema": current_obj.get("_schema")
    }

    print(f"[*] Updating '{TARGET_LIST_NAME}' ({list_id}) with {len(new_prefixes)} IPs...")
    put_r = requests.put(url, headers=headers, json=payload)
    
    if put_r.status_code == 200:
        print(f"[SUCCESS] Updated. New ETAG: {put_r.json().get('_etag')}")
    else:
        print(f"[!] Update failed: {put_r.status_code} - {put_r.text}")

def main():
    token = get_token()
    headers = {
        "Authorization": f"Bearer {token}", 
        "Content-Type": "application/json", 
        "x-panw-region": "de"
    }
    
    get_profile(headers)

    # Resolve IPs
    resolved_ips = resolve_domains_to_prefixes()
    
    if not resolved_ips:
        print("[!] No IPs resolved. Aborting update.")
        return

    # Sync
    update_global_prefix_list(headers, resolved_ips)

if __name__ == "__main__":
    main()
