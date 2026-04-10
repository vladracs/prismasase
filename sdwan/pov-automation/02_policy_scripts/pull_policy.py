#!/usr/bin/env python3
"""
Pull Prisma SD-WAN security policies using the prisma_sase SDK (API class).
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

# Get security policies
response = sdk.get.policysets_security()
policies = response.sdk_content.get("items", [])

# Remove metadata keys
def strip_metadata(obj):
    if isinstance(obj, dict):
        return {k: strip_metadata(v) for k, v in obj.items() if not k.startswith("_")}
    elif isinstance(obj, list):
        return [strip_metadata(item) for item in obj]
    else:
        return obj

cleaned = strip_metadata(policies)

# Write to YAML
with open("pulled_security_policy.yaml", "w") as f:
    yaml.dump(cleaned, f, sort_keys=False)

print("✅ Pulled security policies and saved to pulled_security_policy.yaml")
