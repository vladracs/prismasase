#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import prisma_sase
import keyring
import sys
import json
import argparse

# --- Configuration ---
SERVICE_NAME = "prismasase"

def create_incident_policy(policy_name, description):
    # 1. Auth to Tenant (Keeping your preferred keyring method)
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Credentials for '{SERVICE_NAME}' missing in keyring.")
        sys.exit(1)

    # Initialize SDK
    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Define the Incident Policy Payload
    # Based on your provided raw data structure
    policy_payload = {
        "name": policy_name,
        "description": description,
        "tags": None,
        "severity_priority_mapping": [
            {"severity": "critical", "priority": "p2"},
            {"severity": "major", "priority": "p3"},
            {"severity": "minor", "priority": "p4"}
        ],
        "policyrule_order": None,
        "active_policyset": False,
        "clone_from": None
    }

    print(f"🚀 Attempting to create Incident Policy Set: {policy_name}...")

    # 3. Post to the eventcorrelationpolicysets endpoint
    # The SDK maps the URL path directly to the method name
    resp = sdk.post.eventcorrelationpolicysets(data=policy_payload)

    # 4. Handle Response
    if resp.cgx_status:
        policy_id = resp.cgx_content.get("id")
        print(f"✅ Successfully created Incident Policy Set '{policy_name}'")
        print(f"🆔 Policy ID: {policy_id}")
    else:
        print(f"❌ Failed to create Incident Policy Set.")
        # Provide detailed error feedback from the API
        print(f"Error Details: {json.dumps(resp.cgx_content, indent=2)}")

if __name__ == "__main__":
    # --- Argument Parsing ---
    parser = argparse.ArgumentParser(description="Create a new Incident Policy Set in Prisma SD-WAN.")
    
    parser.add_argument("-n", "--name", required=True, help="The name of the Incident Policy Set")
    parser.add_argument("-d", "--desc", default="Created via Python SDK", help="Optional description")

    args = parser.parse_args()

    # Execute
    create_incident_policy(policy_name=args.name, description=args.desc)
