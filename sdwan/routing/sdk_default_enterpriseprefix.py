import prisma_sase
import keyring
import sys
import json

# --- Configuration ---
# Ensure you have credentials stored for 'tenant2'
SERVICE_NAME = "tenant2"

def reset_to_default_prefixes():
    # 1. Auth to Target Tenant
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Error: Credentials for '{SERVICE_NAME}' not found in keyring.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Get current state to retrieve the mandatory _etag
    print(f"🔗 Fetching current state from {SERVICE_NAME}...")
    current_resp = sdk.get.enterpriseprefixset()
    if not current_resp.cgx_status:
        print("❌ Failed to fetch current Enterprise Prefix Set.")
        return

    data = current_resp.cgx_content
    etag = data.get("_etag")

    # 3. Define your "Default" clean lists
    default_ipv4 = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ]
    default_ipv6 = [
        "fc00::/7"
    ]

    # 4. Prepare Payload
    payload = {
        "ipv4_enterprise_prefixes": default_ipv4,
        "ipv6_enterprise_prefixes": default_ipv6,
        "_etag": etag
    }

    # 5. PUT Update (This replaces the current lists entirely)
    print(f"🧹 Cleaning up Enterprise Prefix Set...")
    update_resp = sdk.put.enterpriseprefixset(data=payload)
    
    if update_resp.cgx_status:
        print(f"✅ Successfully reset Enterprise Prefixes to default.")
        print(f"IPv4: {', '.join(default_ipv4)}")
        print(f"IPv6: {', '.join(default_ipv6)}")
    else:
        print(f"❌ Cleanup failed: {json.dumps(update_resp.cgx_content, indent=2)}")

if __name__ == "__main__":
    reset_to_default_prefixes()
