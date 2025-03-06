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
    client_secret=CLIENT_SECRET)

# Get all sites in the tenant
response_sites = sdk.get.sites()
if response_sites.status_code != 200:
    print("Failed to fetch sites:", response_sites.text)
    exit(1)

sites = response_sites.json().get("items", [])
if not sites:
    print("No sites found.")
    exit(0)

interface_status_list = []

# Iterate through all sites
for site in sites:
    site_id = site["id"]
    print(f"Processing Site: {site['name']} (ID: {site_id})")

    # Get all elements (devices) in the site
    response_elements = sdk.get.elements()
    if response_elements.status_code != 200:
        print(f"Failed to fetch devices for Site {site_id}: {response_elements.text}")
        continue  # Skip to the next site

    elements = response_elements.json().get("items", [])
    if not elements:
        print(f"No elements found.")
        exit(0) #Exit because we cant process elements without them.

    # Iterate through elements and fetch interface status
    for element in elements:
        if element.get("site_id") == site_id:
            element_id = element["id"]
            element_name = element["name"]
            #Get all Interfaces for the device
            print(f"  - Gathering all Interfaces for Device: {element_name} (ID: {element_id})")
            response_interfaces = sdk.get.interfaces(site_id, element_id)
            if response_interfaces.status_code != 200:
                print(f"Failed to fetch Interface for device {element_id}: {response_interfaces.text}")
                continue  # Skip to the next element
            
            interfaces = response_interfaces.json().get("items", []) # Assuming "items" for consistency
            if not interfaces:
                print(f"No Interfaces found for Element {element_id}.") 
                continue  # Skip to the next element

            # Iterate through interfaces
            for interface in interfaces:
                interface_id = interface["id"]
                interface_name = interface.get("name", "N/A") # Safer way to get "name"

                print(f"    - Processing Element Interface: {interface_name} (ID: {interface_id})")

                # Get interface status
                response_interface_status = sdk.get.interfaces_status(site_id, element_id, interface_id)
                if response_interface_status.status_code != 200:
                    print(f"      - Failed to fetch status for interface {interface_id}: {response_interface_status.text}")
                    continue  # Skip to the next interface

                interface_status = response_interface_status.json() 

                # Extract and print operational and admin states
                operational_state = interface_status.get("operational_state", "N/A")
                print(f"      - Interface Operational State: {operational_state}")


            # Get all WAN interfaces for the given element_id
            wan_interfaces_resp = sdk.get.waninterfaces(site_id)

            # Ensure the response is in JSON format
            wan_interfaces_data = wan_interfaces_resp.json() if hasattr(wan_interfaces_resp, "json") else wan_interfaces_resp

            # Check if response is valid and contains items
            if isinstance(wan_interfaces_data, dict) and wan_interfaces_data.get("_status_code") == "200" and wan_interfaces_data.get("count", 0) > 0:
                wan_interfaces = wan_interfaces_data.get("items", [])
                
                for wan_interface in wan_interfaces:
                    wan_id = wan_interface.get("id")
                    wan_name = wan_interface.get("name")
                    
                    # Get the operational status of the WAN interface
                    status_resp = sdk.get.waninterfaces_status(site_id, wan_id)
                    status_data = status_resp.json() if hasattr(status_resp, "json") else status_resp
                    
                    if isinstance(status_data, dict) and status_data.get("_status_code") == "200":
                        op_status = status_data.get("operational_status", "Unknown")
                        print(f"WAN Interface: {wan_name}, ID: {wan_id}, Status: {op_status}")
                    else:
                        print(f"Failed to get status for WAN Interface {wan_name} (ID: {wan_id})")
            else:
                print("No WAN interfaces found or failed to retrieve WAN interfaces.")

        
        

