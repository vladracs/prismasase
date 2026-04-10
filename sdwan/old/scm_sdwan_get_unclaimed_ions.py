#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 <Your Name>
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import os
import csv
import json
import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"
SDWAN_API_BASE = f"{BASE_API_URL}/sdwan/v3.1/api"


def get_env_variable(name):
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Environment variable {name} is not set")
    return value


def get_token():
    client_id = get_env_variable("CLIENT_ID")
    client_secret = get_env_variable("CLIENT_SECRET")
    tenant_id = get_env_variable("TENANT_ID")

    data_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tenant_id}",
        "grant_type": "client_credentials"
    }

    response = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data_payload
    )
    response.raise_for_status()
    return response.json()["access_token"]


def get_headers(token):
    return {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-PANW-Region': 'de'
    }

 if __name__ == '__main__':
    
    token = get_token()
    headers = get_headers(token)

    # Initial /profile call
    profile_url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    requests.get(profile_url, headers=headers)

    print("Fetching ion-devices...")
    
    # API endpoint for listing unclaimed ION devices
    url = "https://api.sase.paloaltonetworks.com/sdwan/v2.5/api/machines/query"
    payload = {"dest_page":1,"limit":25,"getDeleted":False,"retrieved_fields_mask":False,"retrieved_fields":[],"query_params":{"machine_state":{"neq":"claimed"}},"sort_params":{"model_name":"asc"}}
    # Make the POST request
    
    response = requests.post(url, headers=headers,params=None,json=payload)

    # Check for success
    if response.status_code == 200:
        elements = response.json().get("items", [])
        print(f" Device_ID           {'Model_Name':20} {'Image_Version':15} {'Serial_Number':36}        {'State'}")
        print("-" * 120)
        for elem in elements:
            device_id = elem.get("id")
            model = elem.get("model_name", "N/A")
            version = elem.get("image_version", "N/A")
            serial = elem.get("sl_no", "N/A")
            role = elem.get("machine_state", "N/A")
            print(f"{device_id} {model:20} {version:15} {serial:36}        {role}")
    else:
        print(f"Failed to fetch ION devices. Status code: {response.status_code}")
        print(response.text)
 
