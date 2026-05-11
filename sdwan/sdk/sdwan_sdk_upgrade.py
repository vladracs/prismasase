#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import prisma_sase, keyring
from prisma_sase import jd
# --- Configuration ---
SERVICE_NAME = "prismasase"
sdk = prisma_sase.API()
# Replace with your actual credentials or environment variables
client_id = keyring.get_password(SERVICE_NAME, "client_id")
client_secret = keyring.get_password(SERVICE_NAME, "client_secret")
tsg_id = keyring.get_password(SERVICE_NAME, "tsg_id")

if not all([client_id, client_secret, tsg_id]):
    print(f"❌ Credentials for '{SERVICE_NAME}' missing in keyring.")
    sys.exit(1)

# Initialize SDK
sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
sdk.interactive.login_secret(client_id, client_secret, tsg_id)
element_id = "1773934978552002945"
target_image_id = "1773674147762003945"

# --- STEP 1: Fetch the current state to get the fresh ETag and Schema ---
print(f"Fetching current software state for element {element_id}...")
current_state_res = sdk.get.software_state(element_id=element_id)

if not current_state_res.cgx_status:
    print("Failed to fetch current state. Check your element ID.")
    exit()

# Extract the metadata from the existing object
current_content = current_state_res.cgx_content
remote_etag = current_content.get("_etag")
remote_schema = current_content.get("_schema")

print(f"Current ETag found: {remote_etag}")

# --- STEP 2: Prepare the payload using the fresh metadata ---
data = {
    "_etag": remote_etag,
    "_schema": remote_schema,
    "image_id": target_image_id,
    "scheduled_upgrade": None,
    "scheduled_download": None,
    "download_interval": None,
    "upgrade_interval": None,
    "interface_ids": None
}

# --- STEP 3: Trigger the Upgrade ---
print("Triggering upgrade...")
response = sdk.put.software_state(element_id=element_id, data=data)

if response.cgx_status:
    print("SUCCESS: Upgrade triggered successfully.")
    jd(response.cgx_content)
else:
    print("FAILED: API still rejecting the request.")
    jd(response.cgx_content)
