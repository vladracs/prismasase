#!/usr/bin/env python3
"""
Push Prisma SD-WAN security policies using the prisma_sase SDK (API class).
"""

import os
import yaml
from prisma_sase import API

# Authenticate
sdk = API()
sdk.interactive.login_secret(
    client_id=os.getenv("PRISMASDWAN_CLIENT_ID"),
    client_secret=os.getenv("PRISMASDWAN_CLIENT_SECRET"),
    tsg_id=os.getenv("PRISMASDWAN_TSG_ID")
)

# Load YAML file
with open("pulled_security_policy.yaml", "r") as f:
    policies = yaml.safe_load(f)

# Push each policy
for policy in policies:
    name = policy.get("name", "Unnamed")
    print(f"🚀 Pushing policy: {name}")
    response = sdk.post.policysets_security(policy)
    print(f"✅ Response: {response.status_code}")
