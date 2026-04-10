#!/usr/bin/env python3
"""
Push Prisma SD-WAN sites and elements using the prisma_sase SDK (API class).
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

# Load YAML
with open("pulled_resources.yaml", "r") as f:
    resources = yaml.safe_load(f)

# Push sites
for site in resources.get("sites", []):
    name = site.get("name", "Unnamed")
    print(f"🏗️  Creating site: {name}")
    response = sdk.post.sites(site)
    print(f"✅ Site response: {response.status_code}")

# Push elements
for element in resources.get("elements", []):
    name = element.get("name", "Unnamed")
    print(f"🔌 Creating element: {name}")
    response = sdk.post.elements(element)
    print(f"✅ Element response: {response.status_code}")
