#sample sdk with env credentials
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import prisma_sase
import os
import sys
import json
import argparse

def create_incident_policy(policy_name, description):
    # 1. Auth to Tenant (Switching to Environment Variables for simplicity)
    client_id = os.environ.get("PRISMA_CLIENT_ID")
    client_secret = os.environ.get("PRISMA_CLIENT_SECRET")
    tsg_id = os.environ.get("PRISMA_TSG_ID")

    if not all([client_id, client_secret, tsg_id]):
        print("❌ Missing auth variables. Please export PRISMA_CLIENT_ID, PRISMA_CLIENT_SECRET, and PRISMA_TSG_ID.")
        sys.exit(1)

    # Initialize SDK
    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Define the Payload
    policy_payload = {
        "name": policy_name,
        "description": description,
        "severity_priority_mapping": [
            {"severity": "critical", "priority": "p2"},
            {"severity": "major", "priority": "p3"},
            {"severity": "minor", "priority": "p4"}
        ]
    }

    print(f"🚀 Attempting to create: {policy_name}...")

    # 3. Post to the endpoint
    resp = sdk.post.eventcorrelationpolicysets(data=policy_payload)

    # 4. Handle Response
    if resp.cgx_status:
        print(f"✅ Created: {policy_name} | ID: {resp.cgx_content.get('id')}")
    else:
        print(f"❌ Error: {json.dumps(resp.cgx_content, indent=2)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-n", "--name", required=True)
    parser.add_argument("-d", "--desc", default="Created via AI Agent")
    args = parser.parse_args()

    create_incident_policy(policy_name=args.name, description=args.desc)
