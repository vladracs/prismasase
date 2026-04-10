#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

from datetime import datetime, timedelta, timezone
import os
import json
import requests
from typing import Dict, Any, Optional, List

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
    # NOTE: keep header keys consistent; PANW typically accepts x-panw-region / X-PANW-Region
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de",  # adjust if your tenant region differs
    }


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


def api_post(ep: str, token: str, payload: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.post(url, headers=get_headers(token), params=params, json=payload, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text


def get_profile(token: str) -> Dict[str, Any]:
    prof = api_get("/sdwan/v2.1/api/profile", token)
    print("profile api status: 200")
    return prof


# ---------- payload builder (new, minimal change) ----------
def build_metrics_payload(
    start_time: str,
    end_time: str,
    metrics: List[Dict[str, Any]],
    *,
    interval: str = "5min",
    view: Optional[Dict[str, Any]] = None,
    site: Optional[str] = None,
    waninterface: Optional[str] = None,
    path: Optional[str] = None,
    direction: Optional[str] = None,
    extra_filter: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Keeps payload creation consistent & clean without changing your logic.
    """
    payload: Dict[str, Any] = {
        "start_time": start_time,
        "end_time": end_time,
        "interval": interval,
        "metrics": metrics,
        "view": view or {},
        "filter": {},
    }

    if site:
        payload["filter"]["site"] = [site]
    if waninterface:
        payload["filter"]["waninterface"] = [waninterface]
    if path:
        payload["filter"]["path"] = [path]
    if direction:
        payload["filter"]["direction"] = direction
    if extra_filter:
        payload["filter"].update(extra_filter)

    return payload


def post_and_print(url: str, headers: Dict[str, str], payload: Dict[str, Any], label: str) -> None:
    """
    Small helper so you don't repeat status checks everywhere.
    """
    response = requests.post(url, headers=headers, json=payload)
    if response.status_code == 200:
        print(f"{label}:")
        print(json.dumps(response.json(), indent=2))
    else:
        print(f"Failed to fetch {label}. Status code: {response.status_code}")
        print(response.text)


if __name__ == "__main__":
    Start_Time = "2025-12-18T04:53:00.000Z"
    End_Time = "2025-12-18T08:48:00.000Z"
    #for LQM metrics start time should not be older than 7 days
    Site = "1759404972133007345" #Azure US East

    token = get_token()
    headers = get_headers(token)

    # optional quick sanity: same base profile call (comment out if you want it super-minimal)
    get_profile(token)

    # ---------- API get all Site Ports ----------
    print("Site Ports:")
    url_interfaces = "https://api.sase.paloaltonetworks.com/sdwan/v4.21/api/interfaces/query"
    payload = {
        "query_params": {"site_id": {"eq": Site}},
        "dest_page": 1,
        "limit": 200,
        "getDeleted": False,
        "retrieved_fields_mask": False,
        "retrieved_fields": [],
    }
    response = requests.post(url_interfaces, headers=headers, json=payload)

    items = []
    if response.status_code == 200:
        data = response.json()
        items = data.get("items", [])

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
        print(response.text)

    # ---------- Path Status ----------
    print("Path Status:")
    url_topology = "https://api.sase.paloaltonetworks.com/sdwan/v3.6/api/topology"
    payload = {
        "type": "anynet",
        "site_id": Site,
        "servicelinks": True,
        "stub_links": True,
    }

    response = requests.post(url_topology, headers=headers, json=payload)

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
        print(response.text)

    # ---------- collect WAN interface IDs from Site Ports output ----------
    wan_ids: List[str] = []
    for item in items:
        ids = item.get("site_wan_interface_ids") or []
        if isinstance(ids, list):
            wan_ids.extend(ids)

    # de-duplicate while preserving order
    seen = set()
    wan_ids = [x for x in wan_ids if not (x in seen or seen.add(x))]

    if not wan_ids:
        print("No wan_interface_ids found in site ports output (site_wan_interface_ids was empty).")
        raise SystemExit(0)

    # ---------- GET ALL WAN CIRCUITS METRICS ----------
    print("WAN Circuit Metrics")
    url_metrics = "https://api.sase.paloaltonetworks.com/sdwan/monitor/v2.6/api/monitor/metrics"

    for WanInterface_Id in wan_ids:
        print(f"\n--- wan_interface_id={WanInterface_Id} ---")

        # Healthscore
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[{"name": "Healthscore", "statistics": ["max"], "unit": "gauge"}],
            site=Site,
            waninterface=WanInterface_Id,
        )
        post_and_print(url_metrics, headers, payload, "Healthscore")

        # BandwidthUsage
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[{"name": "BandwidthUsage", "statistics": ["average"], "unit": "Mbps"}],
            view={"individual": "direction", "summary": False},
            site=Site,
            waninterface=WanInterface_Id,
        )
        post_and_print(url_metrics, headers, payload, "BandwidthUsage")

        # ---- LQM metrics (path-based) ----
        # In your case, Path_Id equals the wan-id:
        Path_Id = WanInterface_Id

        # LQM Latency + Threshold
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[
                {"name": "LqmLatency", "statistics": ["average"], "unit": "milliseconds"},
                {"name": "LqmLatencyThreshold", "statistics": ["average"], "unit": "milliseconds"},
            ],
            site=Site,
            path=Path_Id,
        )
        post_and_print(url_metrics, headers, payload, "LqmLatency (+Threshold)")

        # LQM PacketLoss + Jitter (Ingress)
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[
                {"name": "LqmPacketLoss", "statistics": ["average"], "unit": "Percentage"},
                {"name": "LqmPacketLossThreshold", "statistics": ["average"], "unit": "Percentage"},
                {"name": "LqmJitter", "statistics": ["average"], "unit": "milliseconds"},
                {"name": "LqmJitterThreshold", "statistics": ["average"], "unit": "milliseconds"},
            ],
            site=Site,
            path=Path_Id,
            direction="Ingress",
        )
        post_and_print(url_metrics, headers, payload, "LqmPacketLoss/Jitter (Ingress)")

        # LQM PacketLoss + Jitter (Egress)
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[
                {"name": "LqmPacketLoss", "statistics": ["average"], "unit": "Percentage"},
                {"name": "LqmPacketLossThreshold", "statistics": ["average"], "unit": "Percentage"},
                {"name": "LqmJitter", "statistics": ["average"], "unit": "milliseconds"},
                {"name": "LqmJitterThreshold", "statistics": ["average"], "unit": "milliseconds"},
            ],
            site=Site,
            path=Path_Id,
            direction="Egress",
        )
        post_and_print(url_metrics, headers, payload, "LqmPacketLoss/Jitter (Egress)")

        # LQM MOS (Ingress)
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[{"name": "LqmMos", "statistics": ["average"], "unit": "count"}],
            site=Site,
            path=Path_Id,
            direction="Ingress",
        )
        post_and_print(url_metrics, headers, payload, "LqmMos (Ingress)")

        # LQM MOS (Egress)
        payload = build_metrics_payload(
            Start_Time,
            End_Time,
            metrics=[{"name": "LqmMos", "statistics": ["average"], "unit": "count"}],
            site=Site,
            path=Path_Id,
            direction="Egress",
        )
        post_and_print(url_metrics, headers, payload, "LqmMos (Egress)")
