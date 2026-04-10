import prisma_sase
import keyring
import sys
import ipaddress
import json

# --- Configuration ---
SERVICE_NAME = "tenant2" 
INPUT_FILE = "bgp_prefixes_export-nokia.json"

def summarize_prefixes(prefix_list):
    """Collapses adjacent subnets and removes duplicates."""
    if not prefix_list:
        return []
    try:
        nets = [ipaddress.ip_network(p) for p in set(prefix_list) if p]
        return [str(net) for net in ipaddress.collapse_addresses(nets)]
    except ValueError as e:
        print(f"⚠️ Formatting error in prefix list: {e}")
        return list(set(prefix_list))

def append_to_target_tenant():
    # 1. Load Data from JSON
    try:
        with open(INPUT_FILE, 'r') as f:
            source_data = json.load(f)
    except FileNotFoundError:
        print(f"❌ Error: {INPUT_FILE} not found.")
        return

    # 2. Extract prefixes (Excluding 0.0.0.0/0)
    new_prefixes_from_json = []
    for element in source_data.get("elements", []):
        for peer in element.get("peers", []):
            for p in peer.get("prefixes_private", []) + peer.get("prefixes_public", []):
                if p != "0.0.0.0/0":
                    new_prefixes_from_json.append(p)

    if not new_prefixes_from_json:
        print("❌ No valid prefixes found in JSON.")
        return

    # 3. Auth to Target Tenant
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Credentials for '{SERVICE_NAME}' missing in keyring.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 4. GET Current State
    print(f"🔗 Fetching current Enterprise Prefix Set from {SERVICE_NAME}...")
    current_resp = sdk.get.enterpriseprefixset()
    if not current_resp.cgx_status:
        print("❌ Failed to fetch current state.")
        return

    data = current_resp.cgx_content
    existing_v4 = data.get("ipv4_enterprise_prefixes", []) or []
    etag = data.get("_etag")

    # 5. MERGE and SUMMARIZE
    combined_list = summarize_prefixes(existing_v4 + new_prefixes_from_json)
    
    # Calculate stats for the user
    current_count = len(existing_v4)
    final_count = len(combined_list)
    net_increase = final_count - current_count
    # --- DEBUG SECTION ---
    print("\n--- [DEBUG] First 20 summarized prefixes ---")
    for net in combined_list[:20]:
        print(f"  {net}")
    
    print("\n--- [DEBUG] Last 20 summarized prefixes ---")
    for net in combined_list[-20:]:
        print(f"  {net}")
    # ---------------------
    print(f"\n" + "="*40)
    print(f"📈 PRE-UPDATE REPORT")
    print(f"="*40)
    print(f"Current entries in Cloud:   {current_count}")
    print(f"New summarized total:       {final_count}")
    print(f"Net increase to list:       +{net_increase} entries")
    
    if final_count > 3000:
        print(f"⚠️  WARNING: Final size ({final_count}) exceeds recommended 3000 limit!")
    print(f"="*40 + "\n")

    # 6. USER INPUT STEP
    confirm = input(f"❓ Do you want to push these {final_count} prefixes to {SERVICE_NAME}? (yes/no): ").strip().lower()
    
    if confirm != 'yes':
        print("🛑 Update aborted by user.")
        return

    # 7. PUT Update
    print(f"🚀 Uploading to {SERVICE_NAME}...")
    payload = {
        "ipv4_enterprise_prefixes": combined_list,
        "ipv6_enterprise_prefixes": data.get("ipv6_enterprise_prefixes", []) or [],
        "_etag": etag
    }

    update_resp = sdk.put.enterpriseprefixset(data=payload)
    if update_resp.cgx_status:
        print(f"✅ Successfully updated Enterprise Prefixes.")
    else:
        print(f"❌ Update failed: {json.dumps(update_resp.cgx_content, indent=2)}")

if __name__ == "__main__":
    append_to_target_tenant()