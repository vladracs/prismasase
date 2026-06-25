#!/usr/bin/env python3
# ============================================================================
# DISCLAIMER
# ----------------------------------------------------------------------------
# I am currently employed by Palo Alto Networks; however, the scripts, examples,
# and documentation in this repository are provided solely in my personal
# capacity for educational purposes. They are not official, are not supported,
# and do not represent the views of Palo Alto Networks.
#
# NO WARRANTY / NO LIABILITY. The materials are provided AS IS without
# warranties of any kind. You assume all risks from use. I and my employer
# disclaim any liability for damages arising from use of this code.
#
# NO SUPPORT. Please do not contact Palo Alto Networks support regarding this
# repository. Issues and questions should be filed in GitHub on a best-effort
# basis only.
#
# COMPLIANCE. By using these materials, you agree to:
#   - adhere to all applicable contracts, licenses, and API terms (including
#     those of Palo Alto Networks and third parties);
#   - avoid exposing secrets/keys and confidential information;
#   - comply with export, privacy, and security laws/policies.
#
# TRADEMARKS. Palo Alto Networks(R), Prisma(R) SASE, and Prisma(R) SD-WAN are
# trademarks of Palo Alto Networks. Other names may be trademarks of their
# respective owners. No affiliation or endorsement is implied.
# ============================================================================
"""
import prisma_sase
import keyring
import sys
import json

SERVICE_NAME = "prismasase"

def audit_site_extended_tags():
    print("🟢 [1/5] Script started. Loading credentials from keyring...")
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Credentials missing. ID: {bool(client_id)}, Secret: {bool(client_secret)}, TSG: {bool(tsg_id)}")
        sys.exit(1)
    print("🟢 [2/5] Credentials found. Initializing SDK...")

    try:
        sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
        print("🟢 [3/5] SDK Initialized. Attempting login (this may take a few seconds)...")
        sdk.interactive.login_secret(client_id, client_secret, tsg_id)
    except Exception as e:
        print(f"❌ Login failed with exception: {e}")
        sys.exit(1)

    print("🟢 [4/5] Login successful! Fetching sites...")
    
    try:
        sites_resp = sdk.get.sites()
    except Exception as e:
        print(f"❌ API call to fetch sites crashed: {e}")
        sys.exit(1)

    if not sites_resp.cgx_status:
        print(f"❌ API returned an error status: {sites_resp.cgx_content}")
        sys.exit(1)

    sites = sites_resp.cgx_content.get("items", [])
    print(f"🟢 [5/5] Success! Found {len(sites)} sites.\n")
    print("-" * 60)

    for site in sites:
        site_id = site.get('id')
        site_name = site.get('name', 'Unknown Site')
        extended_tags = site.get('extended_tags', [])

        print(f"🏢 Site: {site_name} (ID: {site_id})")
        
        if not extended_tags:
            print("  ℹ️  No extended tags configured.")
        else:
            for tag in extended_tags:
                key = tag.get('key', 'Unknown Key')
                raw_value = tag.get('value', '')
                print(f"  🏷️  Tag Key: {key}")
                
                try:
                    parsed_value = json.loads(raw_value)
                    pretty_value = json.dumps(parsed_value, indent=4)
                    print("  📄 Tag Value (Parsed JSON):")
                    for line in pretty_value.splitlines():
                        print(f"      {line}")
                except (json.JSONDecodeError, TypeError):
                    print(f"  📄 Tag Value (Raw): {raw_value}")
        print("-" * 60)

if __name__ == "__main__":
    audit_site_extended_tags()
