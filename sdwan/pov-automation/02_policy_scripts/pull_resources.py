#!/usr/bin/env python3
"""
Pull Prisma SD-WAN resources (sites and elements) using the prisma_sase SDK (API class).
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

# Fetch resources
sites = sdk.get.sites().sdk_content.get("items", [])
elements = sdk.get.elements().sdk_content.get("items", [])

# Remove metadata
def strip_metadata(obj):
    if isinstance(obj, dict):
        return {k: strip_metadata(v) for k, v in obj.items() if not k.startswith("_")}
    elif isinstance(obj, list):
        return [strip_metadata(item) for item in obj]
    else:
        return obj

resources = {
    "sites": strip_metadata(sites),
    "elements": strip_metadata(elements)
}

# Save to YAML
with open("pulled_resources.yaml", "w") as f:
    yaml.dump(resources, f, sort_keys=False)

print("✅ Pulled resources and saved to pulled_resources.yaml")
