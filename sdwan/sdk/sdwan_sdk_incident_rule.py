#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
"""

import prisma_sase
import keyring
import sys
import json
import argparse

SERVICE_NAME = "prismasase"

def get_policy_set_id(sdk, name):
    """Queries the API to find the ID of a policy set by its name."""
    resp = sdk.get.eventcorrelationpolicysets()
    if not resp.cgx_status:
        print(f"❌ Failed to fetch policy sets: {resp.cgx_content}")
        return None

    # Search items for the matching name
    items = resp.cgx_content.get("items", [])
    for item in items:
        if item.get("name") == name:
            return item.get("id")
    
    return None

def add_rule_to_policy(target_policy_name, rule_name):
    # 1. Auth
    client_id = keyring.get_password(SERVICE_NAME, "client_id")
    client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
    tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

    if not all([client_id, client_secret, tsg_id]):
        print(f"❌ Credentials missing.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(client_id, client_secret, tsg_id)

    # 2. Find the ID of the Policy Set
    print(f"🔍 Searching for Policy Set ID for: '{target_policy_name}'...")
    policy_id = get_policy_set_id(sdk, target_policy_name)

    if not policy_id:
        print(f"❌ Could not find a Policy Set named '{target_policy_name}'.")
        sys.exit(1)
    
    print(f"✅ Found ID: {policy_id}")

    # 3. Define the Rule Payload
    rule_payload = {
        "name": rule_name,
        "tags": None,
        "description": "Suppression rule added via SDK",
        "dampening_duration": 5,
        "start_time": None,
        "end_time": None,
        "escalation_rules": None,
        "event_codes": ["CARRIER_PERFORMANCE_DEGRADED"],
        "suppress": "yes"
    }

    # ... (rest of the script remains the same)

    # 4. Post the rule to the specific Policy Set ID
    print(f"🚀 Adding rule '{rule_name}' to Policy Set...")
    
    # Passing the ID as a positional argument is the standard way 
    # the SDK handles /resource/{id}/sub-resource
    resp = sdk.post.eventcorrelationpolicyrules(
        policy_id, # Position 1: Parent ID
        rule_payload # Position 2: The Data
    )

    # If the SDK version is being stubborn about positional args, 
    # we can use the 'sid' keyword which is the SDK's generic internal alias for "Parent ID"
    if not resp.cgx_status and "NoneType" in str(resp.cgx_content):
        resp = sdk.post.eventcorrelationpolicyrules(
            sid=policy_id, 
            data=rule_payload
        )

    # 5. Handle Response
    # ...

    # 5. Handle Response
    if resp.cgx_status:
        rule_id = resp.cgx_content.get("id")
        print(f"✅ Successfully added rule!")
        print(f"🆔 Rule ID: {rule_id}")
    else:
        print(f"❌ Failed to add rule.")
        print(f"Error Details: {json.dumps(resp.cgx_content, indent=2)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Add a suppression rule to an existing Incident Policy.")
    parser.add_argument("-p", "--policy", required=True, help="Name of the existing Policy Set")
    parser.add_argument("-r", "--rule", default="SUPRESS RULE", help="Name of the new rule")

    args = parser.parse_args()
    add_rule_to_policy(target_policy_name=args.policy, rule_name=args.rule)
