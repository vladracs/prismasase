
#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
# Topology printer
#
# Env:
#   export CLIENT_ID="..."
#   export CLIENT_SECRET="..."
#   export TENANT_ID="..."   # (aka tsg_id)
#
# Usage examples:
#   python scm_sdwan_metrics.py --site "My Branch 01"
#   python scm_sdwan_metrics.py --site "My Branch 01" --start "2025-09-30T04:29:00Z" --end "2025-09-30T07:20:00Z"
#
# Notes:
# - Keeps profile call mandatory (prints profile/user).
# - Keeps auth method identical to your existing scripts.
# - Keeps region header 'de'. Adjust via --region if needed.
#
# Output: pretty-printed JSON from the metrics API.
#
import os
import sys
import json
import argparse
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

# Endpoints
PROFILE_EP = "/sdwan/v2.1/api/profile"
SITES_EP = "/sdwan/v4.11/api/sites"
METRICS_EP = "/sdwan/monitor/v2.6/api/monitor/metrics"

# ---------- Auth / headers ----------
def _must_env(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    data = {
        "client_id": _must_env("CLIENT_ID"),
        "client_secret": _must_env("CLIENT_SECRET"),
        "scope": f"tsg_id:{_must_env('TENANT_ID')}",
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

def headers(token: str, region: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": region,
    }

# ---------- tiny HTTP ----------
def api_get(ep: str, token: str, region: str, params: Optional[Dict[str, Any]] = None) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.get(url, headers=headers(token, region), params=params, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def api_post(ep: str, token: str, region: str, payload: Dict[str, Any]) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.post(url, headers=headers(token, region), data=json.dumps(payload), timeout=120)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

# ---------- helpers ----------
def iso_now_z() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def iso_hours_ago_z(h: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=h)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def get_profile(token: str, region: str) -> Dict[str, Any]:
    prof = api_get(PROFILE_EP, token, region)
    # tiny print as requested: mandatory profile call
    user = prof.get("email") or prof.get("user") or "unknown-user"
    tenant = prof.get("tsg_id") or prof.get("tenant_id") or prof.get("customer_id") or "unknown-tenant"
    print(f"Profile: {user} @ {tenant}")
    return prof

def load_sites(token: str, region: str) -> List[Dict[str, Any]]:
    data = api_get(SITES_EP, token, region)
    if isinstance(data, dict) and isinstance(data.get("items"), list):
        return data["items"]
    if isinstance(data, list):
        return data
    return []

def resolve_site_id_by_name(token: str, region: str, site_name: str) -> str:
    sites = load_sites(token, region)
    norm = site_name.strip().lower()
    exact = [s for s in sites if (s.get("name") or "").strip().lower() == norm]
    if len(exact) == 1:
        return str(exact[0].get("id") or exact[0].get("site_id"))
    # fallback: contains match
    contains = [s for s in sites if norm in (s.get("name") or "").strip().lower()]
    if len(contains) == 1:
        return str(contains[0].get("id") or contains[0].get("site_id"))
    # ambiguous or not found
    if not contains and not exact:
        raise SystemExit(f'Site "{site_name}" not found.')
    opts = [f'{s.get("name","?")} ({s.get("id") or s.get("site_id")})' for s in (exact or contains)]
    raise SystemExit("Multiple sites matched:\n  - " + "\n  - ".join(opts))

def build_metrics_payload(site_id: str,
                          start_time: Optional[str],
                          end_time: Optional[str],
                          interval: str,
                          metric_name: str,
                          statistic: str,
                          unit: str,
                          view_individual: str,
                          view_summary: bool) -> Dict[str, Any]:
    if not end_time:
        end_time = iso_now_z()
    if not start_time:
        # default lookback 3h if not provided
        start_time = iso_hours_ago_z(3)
    payload = {
        "start_time": start_time,
        "end_time": end_time,
        "interval": interval,
        "metrics": [{
            "name": metric_name,
            "statistics": [statistic],
            "unit": unit
        }],
        "view": {"individual": view_individual, "summary": view_summary},
        "filter": {"site": [site_id]}
    }
    return payload

def main():
    p = argparse.ArgumentParser(description="Fetch SD-WAN monitor metrics for a site by name")
    p.add_argument("--site", required=True, help="Site name to match (exact match preferred; falls back to contains)")
    p.add_argument("--start", help="ISO8601 start (e.g., 2025-09-30T04:29:00Z). Default: now-3h")
    p.add_argument("--end", help="ISO8601 end   (e.g., 2025-09-30T07:20:00Z). Default: now")
    p.add_argument("--interval", default="5min", help="Metrics interval (default: 5min)")
    p.add_argument("--metric", default="BandwidthUsage", help="Metric name (default: BandwidthUsage)")
    p.add_argument("--stat", default="average", help="Statistic (default: average)")
    p.add_argument("--unit", default="Mbps", help="Unit (default: Mbps)")
    p.add_argument("--view-individual", default="direction", help="View individual dimension (default: direction)")
    p.add_argument("--summary", action="store_true", help="Request summary=true (default: false)")
    p.add_argument("--region", default="de", help="x-panw-region header value (default: de)")
    args = p.parse_args()

    # Auth
    _ = _must_env("TENANT_ID")
    token = get_token()

    # Mandatory profile call
    _ = get_profile(token, args.region)

    # Resolve site id from name
    site_id = resolve_site_id_by_name(token, args.region, args.site)

    # Build payload and POST
    payload = build_metrics_payload(
        site_id=site_id,
        start_time=args.start,
        end_time=args.end,
        interval=args.interval,
        metric_name=args.metric,
        statistic=args.stat,
        unit=args.unit,
        view_individual=args.view_individual,
        view_summary=args.summary,
    )
    resp = api_post(METRICS_EP, token, args.region, payload)

    print(json.dumps(resp, indent=2))

if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"HTTP error: {e}", file=sys.stderr)
        sys.exit(2)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
