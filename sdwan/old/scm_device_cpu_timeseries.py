#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir Franca
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

# ---------- time parsing ----------
from datetime import datetime, timedelta, timezone
import argparse
import csv
import sys
import requests
import os
import sys
import csv
import time
import json
import math
import argparse
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Any, Optional, Iterable, Tuple
import urllib.parse
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
        "Content-Type": "application/json",
        "x-panw-region": "de",  # adjust if your tenant region differs
    }
def get_profile(token: str) -> Dict[str, Any]:
    prof = api_get("/sdwan/v2.1/api/profile", token)
    print("profile api status: 200")
    return prof
# ---------- tiny HTTP ----------
def api_get(ep: str, token: str, params: Optional[Dict[str, Any]] = None) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.get(url, headers=get_headers(token), params=params, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def api_post(ep: str, token: str, payload: Dict[str, Any]) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.post(url, headers=get_headers(token), json=payload, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text
    def get_headers(token):
        return {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-PANW-Region': 'de'
        }
if __name__ == "__main__":
   
    token = get_token()
    #print(token)
    headers=get_headers(token)
    # optional quick sanity: same base profile call (comment out if you want it super-minimal)
    get_profile(token)

    # API endpoint for listing unclaimed ION devices
    url = "https://api.sase.paloaltonetworks.com/sdwan/monitor/v2.3/api/monitor/sys_metrics"
    payload = {"start_time":"2025-11-26T18:58:00.000Z","end_time":"2025-11-27T18:53:00.000Z","filter":{"site":["1752745283015002645"],"element":["1752745283454022245"]},"interval":"5min","metrics":[{"name":"CPUUsage","statistics":["max"],"unit":"percentage"}]}
    
    response = requests.post(url, headers=headers,params=None,json=payload)

    # Check for success
    if response.status_code == 200:
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"Failed to fetch ION CPU. Status code: {response.status_code}")
  
 
