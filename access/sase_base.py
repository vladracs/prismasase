#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 Vladimir França de Sousa
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

# ---------- time parsing ----------
from datetime import datetime, timedelta, timezone
import requests
import os
import json
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Iterable, Tuple
import requests

###

# ---------- Auth / headers ----------
AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

def _must_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    data = {
        "client_id": _must_env("PRISMASASE_CLIENT_ID"),
        "client_secret": _must_env("PRISMASASE_CLIENT_SECRET"),
        "scope": f"tsg_id:{_must_env('PRISMASASE_TSG_ID')}",
        "grant_type": "client_credentials",
    }
    
    r = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]

def get_headers(token: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

if __name__ == "__main__":
   
    token = get_token()
   
    headers=get_headers(token)
    # optional quick sanity: same base profile call (comment out if you want it super-minimal)
    

    # API endpoint for Device Metrics
    url = 'https://api.sase.paloaltonetworks.com/sse/config/v1/service-connections'
 
    # The headers from your curl command
    headers = {
        'accept': '*/*',
        "Authorization": f"Bearer {token}",
        }

    try:
        # Perform the GET request
        response = requests.get(url, headers=headers)

        # Check if the request was successful
        response.raise_for_status()
    #
        # Parse JSON response
        data = response.json()
        print(data)

    except requests.exceptions.HTTPError as err:
        print(f"HTTP error occurred: {err}")
    except Exception as err:
        print(f"An error occurred: {err}")
