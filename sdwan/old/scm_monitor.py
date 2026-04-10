#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
import os
import json
import argparse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

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
        data=data_payload,
        timeout=30,
    )
    response.raise_for_status()
    return response.json()["access_token"]

def get_headers(token):
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de",
    }

def get_profile(token):
    profile_url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    resp = requests.get(profile_url, headers=get_headers(token), timeout=30)
    print("profile api status:", resp.status_code)
    return resp  # you weren’t using the body here; keeping as Response

# ---------- time helpers ----------

def _to_iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")

def _parse_user_time(s: str) -> datetime:
    """
    Accepts:
      - '2025-09-10T00:00:00Z'
      - '2025-09-10 00:00:00'
      - '2025-09-10'
      - 'now'
    """
    s = s.strip()
    if s.lower() == "now":
        return datetime.now(timezone.utc)
    # normalize Z
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # try a few common formats
    fmts = (
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
    )
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Unrecognized time format: {s}")

def resolve_window(args) -> Tuple[str, str]:
    """
    Builds start/end ISO 8601 Z based on:
      --start, --end (ISO-ish) and/or --last (hours)
    Defaults to last 24h if nothing provided.
    """
    now = datetime.now(timezone.utc)

    if args.last is not None:
        end_dt = now
        start_dt = end_dt - timedelta(hours=args.last)
    else:
        start_dt = _parse_user_time(args.start) if args.start else None
        end_dt = _parse_user_time(args.end) if args.end else None

        if start_dt and not end_dt:
            end_dt = now
        elif end_dt and not start_dt:
            start_dt = end_dt - timedelta(hours=24)
        elif not start_dt and not end_dt:
            # default last 24h
            end_dt = now
            start_dt = end_dt - timedelta(hours=24)

    if start_dt >= end_dt:
        raise ValueError("start_time must be before end_time")

    return _to_iso_utc(start_dt), _to_iso_utc(end_dt)

# ---------- API calls (now parameterized) ----------

def call_alarms(token, start_time_iso: str, end_time_iso: str):
    url = f"{BASE_API_URL}/sdwan/v3.6/api/events/query"
    payload = {
        "limit": {"count": 50, "sort_on": "time", "sort_order": "descending"},
        "dest_page": 0,
        "view": {"summary": False},
        "priority": [],
        "severity": [],
        "element_cluster_roles": [],
        "query": {"site": [], "category": [], "code": [], "correlation_id": [], "type": ["alarm"]},
        "start_time": start_time_iso,
        "end_time": end_time_iso,
    }
    resp = requests.post(url, headers=get_headers(token), data=json.dumps(payload), timeout=60)
    print("alarms api status:", resp.status_code)
    return resp

def call_appdefs(token):
    url = f"{BASE_API_URL}/sdwan/v2.6/api/appdefs"
    resp = requests.get(url, headers=get_headers(token), timeout=60)
    print("appdefs api status:", resp.status_code)
    if not resp.ok:
        return []
    return resp.json().get("items", [])

def call_aiops_health(token, start_time_iso: str, end_time_iso: str):
    aiops_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/aiops/health"
    aiops_payload = {
    "end_time": "2025-06-02T00:00:00Z",
    "filter": { "site_health": ["all"] },
    "interval": "5min",
    "start_time": "2025-06-01T00:00:00Z",
    "view": "summary"
    }
    #print("GET aiops_url = ",aiops_url)
    headers = get_headers(token)
    #print("X-PANW-Region: ",headers["X-PANW-Region"])
    resp = requests.post(aiops_url, headers=headers, data=json.dumps(aiops_payload))
    print("aiops api status:", resp.status_code)
    #print("aiops api response:", resp.text)
    return resp

def call_applicationsummary(token, start_time_iso: str, end_time_iso: str):
    url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/applicationsummary/query"
    payload =  {
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "interval": "5min",
        "metrics": ["ApplicationHealthscore"],
        "filter": {
            "app": ["1682474676454001596"],   # TODO: parameterize if needed
            "site": ["1741378371338024045"]  # TODO: parameterize if needed
        }
    }
    resp = requests.post(url, headers=get_headers(token), data=json.dumps(payload), timeout=60)
    print("applicationsummary api status:", resp.status_code)
    # print("applicationsummary api response:", resp.text)
    return resp

def call_aggregatebandwidth(token, start_time_iso: str, end_time_iso: str):
    url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/aggregatebandwidth/query"
    payload = {
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "interval": "1month",                 # keep as-is; change if you want finer granularity
        "metrics": ["AggBandwidthUsage"],
        "view": "duration"
    }
    resp = requests.post(url, headers=get_headers(token), data=json.dumps(payload), timeout=60)
    print("aggregatebandwidth api status:", resp.status_code)
    return resp

def get_all_interfaces_status(token):
    sites_url = f"{BASE_API_URL}/sdwan/v4.11/api/sites"
    resp = requests.get(sites_url, headers=get_headers(token), timeout=60)
    if resp.status_code != 200:
        print(f"Failed to fetch sites. Status code: {resp.status_code}")
        print(resp.text)
        return

    data = resp.json()
    sites = data.get("items", data if isinstance(data, list) else [])
    print(f"Found {len(sites)} sites\n")

    for site in sites:
        site_id = site.get("id")
        site_name = site.get("name")
        if not site_id:
            continue

        wan_url = f"{BASE_API_URL}/sdwan/v2.8/api/sites/{site_id}/waninterfaces"
        wresp = requests.get(wan_url, headers=get_headers(token), timeout=60)
        if wresp.status_code != 200:
            print(f"  Failed to get WAN interfaces for site {site_name} ({site_id})")
            continue

        wan_interfaces = wresp.json().get("items", [])
        print(f"Site: {site_name} ({site_id}) - {len(wan_interfaces)} WAN interfaces")

        for wi in wan_interfaces:
            wi_id = wi.get("id")
            if not wi_id:
                continue

            status_url = f"{BASE_API_URL}/sdwan/v2.1/api/sites/{site_id}/waninterfaces/{wi_id}/status"
            sresp = requests.get(status_url, headers=get_headers(token), timeout=60)
            if sresp.status_code != 200:
                print(f"    Failed to get status for interface {wi_id}")
                continue

            status_json = sresp.json()
            operational_status = status_json.get("operational_state", "N/A")
            print(f"    WAN Interface {wi_id}: Operational Status: {operational_status}")
        print()

# ---------- main ----------

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="SASE SD-WAN API examples with time window")
    parser.add_argument("--start", help="Start time (ISO 8601). E.g. 2025-09-10T00:00:00Z", default=None)
    parser.add_argument("--end", help="End time (ISO 8601). E.g. 2025-09-11T00:00:00Z", default=None)
    parser.add_argument("--last", type=int, help="Last N hours (overrides --start/--end)", default=None)
    args = parser.parse_args()

    # resolve time window
    start_iso, end_iso = resolve_window(args)
    print(f"Using window: {start_iso} → {end_iso}")

    # auth/profile
    _tenant_id = get_env_variable("TENANT_ID")
    token = get_token()
    get_profile(token)

    # calls (now parameterized with the window)
    call_alarms(token, start_iso, end_iso)
    call_appdefs(token)
    call_aiops_health(token, start_iso, end_iso)
    call_applicationsummary(token, start_iso, end_iso)
    call_aggregatebandwidth(token, start_iso, end_iso)
    get_all_interfaces_status(token)
