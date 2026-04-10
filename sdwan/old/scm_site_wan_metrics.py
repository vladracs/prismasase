#Author: Vladimir Franca de Sousa vfrancad@gmail.com
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir França de Sousa
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
    Start_Time="2025-12-18T04:53:00.000Z"
    End_Time="2025-12-18T08:48:00.000Z"
    Site="1759404972133007345"
    
    token = get_token()
    #print(token)
    headers=get_headers(token)
    # optional quick sanity: same base profile call (comment out if you want it super-minimal)
    get_profile(token)
    
    #API get all Site Ports:
    print("Site Ports:")
    url = "https://api.sase.paloaltonetworks.com/sdwan/v4.21/api/interfaces/query"
    payload = {"query_params":{"site_id":{"eq":Site}},"dest_page":1,"limit":200,"getDeleted":False,"retrieved_fields_mask":False,"retrieved_fields":[]}
    response = requests.post(url, headers=headers, json=payload)

    # Check for success
    if response.status_code == 200:
        data = response.json()          # <-- FIX
        items = data.get("items", [])   # <-- FIX

        for item in items:
            element_id = item.get("element_id")
            name = item.get("name")
            admin_up = item.get("admin_up")
            site_wan_interface_ids = item.get("site_wan_interface_ids")

            print(
                f"element_id={element_id}, "
                f"port={name}, "
                f"admin_up={admin_up}, "
                f"site_wan_interface_ids={site_wan_interface_ids}"
            )
    else:
        print(f"Failed to fetch Site Ports. Status code: {response.status_code}")

    print("Path Status:")
    # API to get all Path status
    url = "https://api.sase.paloaltonetworks.com/sdwan/v3.6/api/topology"
    payload = {
        "type": "anynet",
        "site_id": Site,
        "servicelinks": True,
        "stub_links": True
    }

    response = requests.post(url, headers=headers, json=payload)

    # Check for success
    if response.status_code == 200:
        data = response.json()
        links = data.get("links", [])

        for link in links:
            path_id = link.get("path_id")
            link_type = link.get("type")
            target_site_name = link.get("target_site_name")
            admin_up = link.get("admin_up")
            status = link.get("status")

            print(
                f"path_id={path_id}, "
                f"type={link_type}, "
                f"target_site_name={target_site_name}, "
                f"admin_up={admin_up}, "
                f"status={status}"
            )
    else:
        print(f"Failed to fetch Topology. Status code: {response.status_code}")

    #GET ALL WAN CIRCUITS METRICS:
        # ---------- collect WAN interface IDs from Site Ports output ----------
    # (Uses the `items` list you already populated above from interfaces/query)
    wan_ids = []
    for item in items:
        ids = item.get("site_wan_interface_ids") or []
        if isinstance(ids, list):
            wan_ids.extend(ids)

    # de-duplicate while preserving order
    seen = set()
    wan_ids = [x for x in wan_ids if not (x in seen or seen.add(x))]

    print("WAN Circuit Metrics")
    url = "https://api.sase.paloaltonetworks.com/sdwan/monitor/v2.6/api/monitor/metrics"

    for WanInterface_Id in wan_ids:
        print(f"\n--- wan_interface_id={WanInterface_Id} ---")

        # Healthscore
        payload = {
            "start_time": Start_Time,
            "end_time": End_Time,
            "interval": "5min",
            "metrics": [{"name": "Healthscore", "statistics": ["max"], "unit": "gauge"}],
            "filter": {"site": [Site], "waninterface": [WanInterface_Id]},
        }
        response = requests.post(url, headers=headers, params=None, json=payload)

        if response.status_code == 200:
            print("Healthscore:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Failed to fetch Healthscore. Status code: {response.status_code}")
            print(response.text)

        # BandwidthUsage
        payload = {
            "start_time": Start_Time,
            "end_time": End_Time,
            "interval": "5min",
            "metrics": [{"name": "BandwidthUsage", "statistics": ["average"], "unit": "Mbps"}],
            "view": {"individual": "direction", "summary": False},
            "filter": {"site": [Site], "waninterface": [WanInterface_Id]},
        }
        response = requests.post(url, headers=headers, params=None, json=payload)

        if response.status_code == 200:
            print("BandwidthUsage:")
            print(json.dumps(response.json(), indent=2))
        else:
            print(f"Failed to fetch BandwidthUsage. Status code: {response.status_code}")
            print(response.text)

    if not wan_ids:
        print("No wan_interface_ids found in site ports output (site_wan_interface_ids was empty).")

