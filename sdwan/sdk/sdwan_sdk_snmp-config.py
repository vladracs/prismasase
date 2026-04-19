#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
"""
--- QUICK START GUIDE ---

1. INSTALL LIBRARIES:
   Mac/Windows: pip install prisma-sase keyring

2. SETUP SECURE CREDENTIALS (Keyring):
   Open your terminal/command prompt, type 'python' and run:
   ---------------------------------------------------------
   import keyring
   keyring.set_password("prismasase", "client_id", "YOUR_ID")
   keyring.set_password("prismasase", "client_secret", "YOUR_SECRET")
   keyring.set_password("prismasase", "tsg_id", "YOUR_TSG_ID")
   ---------------------------------------------------------

3. RUN THE SCRIPT:
   python your_script_name.py
"""

import prisma_sase
import keyring
import sys
import json

# --- Configuration ---
SERVICE_NAME = "prismasase"

def update_snmp_on_all_elements():
    # 1. Auth to Tenant
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Credentials for '{SERVICE_NAME}' missing in keyring.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Get all Elements
    print(f"📡 Fetching all elements for {SERVICE_NAME}...")
    elem_resp = sdk.get.elements()
    if not elem_resp.cgx_status:
        print("❌ Failed to fetch elements.")
        return

    elements = elem_resp.cgx_content.get("items", [])
    print(f"Found {len(elements)} elements. Starting SNMP update scan...\n")

    for x in elements:
        eid = x.get('id')
        sid = x.get('site_id')
        name = x.get('name', 'Unknown')

        if not sid or sid == "1": # Skip unassigned elements if necessary
            print(f"⏩ Skipping {name} ({eid}) - No site assigned.")
            continue

        # 3. Get SNMP Agents for this element
        snmp_resp = sdk.get.snmpagents(site_id=sid, element_id=eid)
        
        if not snmp_resp.cgx_status:
            print(f"⚠️  Could not fetch SNMP for {name}")
            continue

        agents = snmp_resp.cgx_content.get("items", [])
        
        if not agents:
            print(f"ℹ️  No SNMP agent configured on {name}. Skipping.")
            continue

        for agent in agents:
            aid = agent.get('id')
            print(f"🔄 Updating SNMP Agent '{agent.get('description')}' on {name}...")

            # 4. Define the Update Payload
            # We preserve the ETag and ID, but update the v3_config
            payload = agent.copy()
            
            payload["v3_config"] = {
                "enabled": True,
                "users_access": [
                    {
                        "user_name": "b1labsnmpuser",
                        "engine_id": None,
                        "security_level": "auth",
                        "auth_type": "sha",
                        "auth_phrase": None, # Set phrase if needed, or leave null per your curl
                        "enc_type": "aes",
                        "enc_phrase": None
                    },
                    {
                        "user_name": "test_user",
                        "engine_id": None,
                        "security_level": "auth",
                        "auth_type": "sha",
                        "auth_phrase": "Palo123456",
                        "enc_type": "aes",
                        "enc_phrase": "Palo123456"
                    }
                ]
            }

            # 5. Push the Update
            update_resp = sdk.put.snmpagents(
                site_id=sid, 
                element_id=eid, 
                snmpagent_id=aid, 
                data=payload
            )

            if update_resp.cgx_status:
                print(f"  ✅ Successfully updated agent on {name}")
            else:
                print(f"  ❌ Failed update on {name}: {update_resp.cgx_content}")

    print("\n✨ Finished processing all elements.")

if __name__ == "__main__":
    update_snmp_on_all_elements()
