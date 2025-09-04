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
    
    # API endpoint for listing ION devices
    url = "https://api.sase.paloaltonetworks.com/sdwan/v3.2/api/elements"

    # Make the GET request
    response = requests.get(url, headers=headers)

    # Check for success
    if response.status_code == 200:
        elements = response.json().get("items", [])
        print(f"{'Device Name':30} {'Model Name':20} {'SW Version':15} {'Serial Number':36} {'Role'}")
        print("-" * 120)
        for elem in elements:
            name = elem.get("name", "N/A")
            model = elem.get("model_name", "N/A")
            version = elem.get("software_version", "N/A")
            serial = elem.get("serial_number", "N/A")
            role = elem.get("role", "N/A")
            print(f"{name:30} {model:20} {version:15} {serial:36} {role}")
    else:
        print(f"Failed to fetch ION devices. Status code: {response.status_code}")
        print(response.text)
  
 
