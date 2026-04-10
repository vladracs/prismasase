#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 <Your Name>
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import prisma_sase
from prisma_sase import API
import http.client
import json
import requests
import os

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

def get_env_variable(name):
    """Retrieve environment variable or raise an error if not found."""
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Environment variable {name} is not set")
    return value

# Read credentials from environment variables
CLIENT_ID = get_env_variable("CLIENT_ID")
CLIENT_SECRET = get_env_variable("CLIENT_SECRET")
TENANT_ID = get_env_variable("TENANT_ID")

# Validate that environment variables are set
if not all([CLIENT_ID, TENANT_ID, CLIENT_SECRET]):
    raise ValueError("Missing one or more required environment variables: PRISMA_CLIENT_ID, PRISMA_TENANT_ID, PRISMA_CLIENT_SECRET")

# Initialize the SDK
sdk = prisma_sase.API()

# Authenticate using OAuth2
sdk.interactive.login_secret(
    client_id=CLIENT_ID,
    tsg_id=TENANT_ID,
    client_secret=CLIENT_SECRET
)

# Fetch and print all sites as an example
response = sdk.get.sites()
# Check if response is valid JSON
if response.status_code == 200:
    data = response.json()  # Convert response to JSON format
    if "items" in data:
        for site in data["items"]:
            print(f"Site Name: {site.get('name')}, ID: {site.get('id')}, Type: {site.get('type')}")
    else:
        print("No sites found.")
else:
    print(f"Error: {response.status_code}, {response.text}")  # Print error details if request fails

response = sdk.get.securityzones()
if response.status_code == 200:
    data = response.json()  # Convert response to JSON format
    if "items" in data:
        for zone in data["items"]:
            print(f"Security Zone Name: {zone.get('name')}, ID: {zone.get('id')}")
    else:
        print("No security zones found.")
else:
    print(f"Error: {response.status_code}, {response.text}")

site_id=your_site_id
response = sdk.get.sitesecurityzones(site_id)
if response.status_code == 200:
    data = response.json()  # Convert response to JSON format
    # Check if 'items' exists and is non-empty
    if "items" in data and data["items"]:
        for zone in data["items"]:
            print(f"Security Zone Name: {zone.get('name')}, ID: {zone.get('id')}, Type: {zone.get('type')}")
    else:
        print("No security zones found at Site Level.")
else:
    print(f"Error: {response.status_code}, {response.text}")  # Print error details if request fails

# Define your element ID
element_id = your_element_id  # Replace with the actual element ID

# Fetch the security zones for the specific element
response = sdk.get.elementsecurityzones(site_id,element_id)

# Check if response is successful (HTTP 200)
if response.status_code == 200:
    data = response.json()  # Convert response to JSON format
    if "items" in data and data["items"]:
        for zone in data["items"]:
            print(f"Security Zone Name: {zone.get('name')}, ID: {zone.get('id')}, Type: {zone.get('type')}")
    else:
        print("No security zones found at Device level.")
else:
    print(f"Error: {response.status_code}, {response.text}")

print("Creating Association at Device Level")
zone_id = 'your_zone_id'  # Replace with actual security zone ID

# Define the data dictionary to create the association
data = {
    "interface_ids": ["interface1", "interface2"],  # Example interface IDs
    "lannetwork_ids": ["lan_network_1", "lan_network_2"],  # Example LAN network IDs
    "site_id": site_id,
    "waninterface_ids": ["wan_interface_1", "wan_interface_2"],  # Example WAN interface IDs
    "wanoverlay_ids": ["wan_overlay_1", "wan_overlay_2"],  # Example WAN overlay IDs
    "zone_id": zone_id  # Security zone ID to associate
} 
# a sample ,taken from Chrome dev explorer 
data = {"zone_id":"x","lannetwork_ids":[],"interface_ids":["y"],"wanoverlay_ids":[],"waninterface_ids":[]}
# Create the association between element and security zone
response = sdk.post.elementsecurityzones(site_id, element_id, data)

# Check if the response is successful (HTTP 200)
if response.status_code == 200:
    print("Association created successfully!")
    print(response.json())  # Print the response content if needed
else:
    print(f"Error: {response.status_code}, {response.text}")  # Print error details if request fails
