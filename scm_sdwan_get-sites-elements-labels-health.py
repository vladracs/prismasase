#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.

import os
import json
import requests
from typing import Any, Dict, List, Tuple, Optional
import argparse
from datetime import datetime, timedelta, timezone

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

SITES_EP = "/sdwan/v4.11/api/sites"
ELEMENTS_TENANT_EP = "/sdwan/v3.1/api/elements"
INTERFACES_EP = "/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"
SITE_WAN_IFACES_EP = "/sdwan/v2.8/api/sites/{site_id}/waninterfaces"
WAN_LABELS_EP = "/sdwan/v2.6/api/waninterfacelabels"
AIOPS_HEALTH_EP = "/sdwan/monitor/v2.0/api/monitor/aiops/health"

_ELEMENTS_CACHE: Optional[List[Dict[str, Any]]] = None
_WAN_LABELS_CACHE: Optional[Dict[str, Dict[str, str]]] = None
_SITE_WAN_IFACES_CACHE: Dict[str, List[Dict[str, Any]]] = {}

# ---------- Auth / headers ----------

def get_env_variable(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    client_id = get_env_variable("CLIENT_ID")
    client_secret = get_env_variable("CLIENT_SECRET")
    tenant_id = get_env_variable("TENANT_ID")
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tenant_id}",
        "grant_type": "client_credentials",
    }
    r = requests.post(AUTH_URL, headers={"Content-Type": "application/x-www-form-urlencoded"}, data=data, timeout=30)
    r.raise_for_status()
    return r.json()["access_token"]

def get_headers(token: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de",  # change if your tenant uses a different region
    }

def get_profile(token: str) -> Dict[str, Any]:
    url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    r = requests.get(url, headers=get_headers(token), timeout=30)
    print("profile api status:", r.status_code)
    r.raise_for_status()
    return r.json()

# ---------- tiny HTTP ----------

def api_get(endpoint: str, token: str, params: Optional[Dict[str, Any]] = None) -> Any:
    url = endpoint if endpoint.startswith("http") else f"{BASE_API_URL}{endpoint}"
    r = requests.get(url, headers=get_headers(token), params=params, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def api_post(endpoint: str, token: str, payload: Dict[str, Any]) -> Any:
    url = endpoint if endpoint.startswith("http") else f"{BASE_API_URL}{endpoint}"
    r = requests.post(url, headers=get_headers(token), data=json.dumps(payload), timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def fetch_all_pages(endpoint: str, token: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    q = dict(params or {})
    next_keys = ("next", "next_page", "nextPageToken", "page.next", "next_token")
    while True:
        data = api_get(endpoint, token, params=q)
        if isinstance(data, list):
            out.extend(data)
        elif isinstance(data, dict):
            if isinstance(data.get("items"), list):
                out.extend(data["items"])
            elif data and not out:
                out.append(data)
        nxt = None
        if isinstance(data, dict):
            for k in next_keys:
                if data.get(k):
                    nxt = data[k]
                    break
        if not nxt:
            break
        for ck in ("cursor", "page", "page_token", "next"):
            q[ck] = nxt
    return out

# ---------- time ----------

def iso_utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def iso_utc_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat().replace("+00:00", "Z")

# ---------- helpers ----------

def normalize_id_name(o: Dict[str, Any]) -> None:
    if "id" not in o:
        if "site_id" in o:
            o["id"] = o["site_id"]
        elif "element_id" in o:
            o["id"] = o["element_id"]
    if "name" not in o and "display_name" in o:
        o["name"] = o["display_name"]

def _flatten_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _flatten_dicts(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _flatten_dicts(it)

# ---------- inventory ----------

def get_all_sites(token: str) -> List[Dict[str, Any]]:
    sites = fetch_all_pages(SITES_EP, token)
    for s in sites:
        normalize_id_name(s)
    return sites

def _get_all_elements_cached(token: str) -> List[Dict[str, Any]]:
    global _ELEMENTS_CACHE
    if _ELEMENTS_CACHE is None:
        _ELEMENTS_CACHE = fetch_all_pages(ELEMENTS_TENANT_EP, token)
        for e in _ELEMENTS_CACHE:
            normalize_id_name(e)
    return _ELEMENTS_CACHE

def get_site_elements(token: str, site_id: str) -> List[Dict[str, Any]]:
    sid = str(site_id)
    return [e for e in _get_all_elements_cached(token) if str(e.get("site_id") or e.get("site") or "") == sid]

def get_element_interfaces(token: str, element_id: str) -> List[Dict[str, Any]]:
    elems = _get_all_elements_cached(token)
    match = next((e for e in elems if str(e.get("id") or e.get("element_id")) == str(element_id)), None)
    if not match:
        return []
    site_id = str(match.get("site_id") or match.get("site") or "")
    if not site_id:
        return []
    ep = INTERFACES_EP.format(site_id=site_id, element_id=element_id)
    raw = api_get(ep, token)
    if isinstance(raw, list):
        intfs = raw
    elif isinstance(raw, dict) and isinstance(raw.get("items"), list):
        intfs = raw["items"]
    elif isinstance(raw, dict):
        intfs = [raw]
    else:
        intfs = []
    for it in intfs:
        normalize_id_name(it)
    return intfs

def classify_sites(sites: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    branches, gateways = [], []
    for s in sites:
        if s.get("branch_gateway", False):
            gateways.append(s)
        else:
            branches.append(s)
    return branches, gateways

# ---------- WAN labels / site WAN ifaces ----------

def _load_wan_labels_map(token: str) -> Dict[str, Dict[str, str]]:
    global _WAN_LABELS_CACHE
    if _WAN_LABELS_CACHE is None:
        items = fetch_all_pages(WAN_LABELS_EP, token)
        m: Dict[str, Dict[str, str]] = {}
        for it in items:
            lid = str(it.get("id"))
            if lid:
                m[lid] = {"name": it.get("name") or "", "label": it.get("label") or ""}
        _WAN_LABELS_CACHE = m
    return _WAN_LABELS_CACHE

def _get_site_wan_ifaces(token: str, site_id: str) -> List[Dict[str, Any]]:
    sid = str(site_id)
    if sid not in _SITE_WAN_IFACES_CACHE:
        ep = SITE_WAN_IFACES_EP.format(site_id=sid)
        data = api_get(ep, token)
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            _SITE_WAN_IFACES_CACHE[sid] = data["items"]
        elif isinstance(data, list):
            _SITE_WAN_IFACES_CACHE[sid] = data
        else:
            _SITE_WAN_IFACES_CACHE[sid] = []
    return _SITE_WAN_IFACES_CACHE[sid]

def _label_names_for_site_wan_iface_ids(token: str, site_id: str, sw_ids: List[str]) -> List[str]:
    if not sw_ids:
        return []
    labels_map = _load_wan_labels_map(token)
    site_wans = _get_site_wan_ifaces(token, site_id)
    idx = {str(w.get("id")): w for w in site_wans if w.get("id")}
    out: List[str] = []
    for swid in sw_ids:
        w = idx.get(str(swid))
        if not isinstance(w, dict):
            continue
        label_ids = []
        if isinstance(w.get("labels"), list):
            label_ids.extend([str(x) for x in w.get("labels") if x])
        if w.get("label_id"):
            label_ids.append(str(w["label_id"]))
        if not label_ids:
            continue
        for lid in label_ids:
            meta = labels_map.get(str(lid))
            if not meta:
                out.append(f"label_id:{lid}")
            else:
                name = meta.get("name") or ""
                code = meta.get("label") or ""
                out.append(f"{name} ({code})" if name and code else (name or code or f"label_id:{lid}"))
    # de-dupe
    seen = set()
    uniq = []
    for s in out:
        if s not in seen:
            seen.add(s)
            uniq.append(s)
    return uniq

def is_wan_interface(intf: Dict[str, Any], label_names: List[str]) -> bool:
    if label_names:
        return True
    used_for = (intf.get("used_for") or "").lower()
    t = (intf.get("type") or "").lower()
    return used_for in ("public", "wan") or t == "cellular"

# ---------- AIOps site health (enhanced + debug) ----------

def _peek_row(row: Dict[str, Any]) -> None:
    """Print a compact but informative look at a single health row."""
    try:
        keys = list(row.keys())
        dims = row.get("dimensions") or {}
        meta = row.get("metadata") or {}
        print("   row keys:", keys[:12])
        if dims:
            print("   dimensions:", {k: dims.get(k) for k in list(dims.keys())[:6]})
        if meta:
            print("   metadata:", {k: meta.get(k) for k in list(meta.keys())[:6]})
        # print potential status fields
        for k in ("site_health", "status", "state", "health"):
            if k in row:
                print(f"   {k}:", row[k])
        # any scores
        for k,v in row.items():
            if isinstance(k, str) and "score" in k.lower():
                print(f"   {k}:", v)
    except Exception as e:
        print("   _peek_row error:", e)

def _extract_site_id_from_row(row: Dict[str, Any]) -> Optional[str]:
    # direct
    for k in ("site_id", "siteId", "site"):
        if row.get(k):
            return str(row[k])
    # inside dimensions/metadata
    for container_key in ("dimensions", "metadata"):
        cont = row.get(container_key)
        if isinstance(cont, dict):
            for k in ("site_id", "siteId", "site"):
                if cont.get(k):
                    return str(cont[k])
    return None

def _extract_status_from_row(row: Dict[str, Any]) -> Optional[str]:
    # Accept aiops enums: poor|fair|good|all
    for k in ("status", "site_health", "state", "health"):
        v = row.get(k)
        if isinstance(v, str) and v:
            return v
    # sometimes nested
    for container_key in ("dimensions", "metadata"):
        cont = row.get(container_key)
        if isinstance(cont, dict):
            for k in ("status", "site_health", "state", "health"):
                v = cont.get(k)
                if isinstance(v, str) and v:
                    return v
    return None

def debug_aiops_health(token: str, start_time: str, end_time: str, region_hint: Optional[str] = None) -> None:
    url = f"{BASE_API_URL}{AIOPS_HEALTH_EP}"
    headers = get_headers(token)
    if region_hint:
        headers["x-panw-region"] = region_hint

    trials = [
        ("summary + site_health=all", {
            "start_time": start_time, "end_time": end_time, "view": "summary", "interval": "5min",
            "filter": {"site_health": ["all"]}
        }),
        ("detail + explicit enums", {
            "start_time": start_time, "end_time": end_time, "view": "detail", "interval": "1hour",
            "filter": {"site_health": ["poor", "fair", "good"]}
        }),
        # Best-effort grouping knobs. If schema rejects, you'll see 400 and we move on.
        ("summary + all + group_by(site)", {
            "start_time": start_time, "end_time": end_time, "view": "summary", "interval": "1hour",
            "filter": {"site_health": ["all"]},
            "group_by": ["site"]
        }),
        ("detail + enums + dimensions(site)", {
            "start_time": start_time, "end_time": end_time, "view": "detail", "interval": "1hour",
            "filter": {"site_health": ["poor", "fair", "good"]},
            "dimensions": ["site"]
        }),
    ]

    print("\n=== AIOps health DEBUG ===")
    print(f"start_time={start_time}  end_time={end_time}  x-panw-region={headers.get('x-panw-region')}")
    for name, payload in trials:
        print(f"\n--- Trial: {name} ---")
        print("payload:", json.dumps(payload))
        try:
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
            print("status:", resp.status_code)
            rid = resp.headers.get("x-request-id") or resp.headers.get("x-pan-request-id")
            if rid:
                print("request-id:", rid)
            if resp.status_code >= 400:
                print("body:", resp.text[:2000])
                continue
            data = resp.json() if resp.text.strip() else None
            if isinstance(data, dict):
                print("  top-level keys:", list(data.keys()))
                container = None
                for k in ("items", "data", "sites", "results"):
                    if isinstance(data.get(k), list):
                        container = data[k]; print(f"  using list container '{k}', len={len(container)}")
                        break
            elif isinstance(data, list):
                container = data
                print(f"  got top-level list, len={len(container)}")
            else:
                container = None

            if not container:
                print("  No list container found.")
                continue

            # peek at first few rows in full
            for i, row in enumerate(container[:5]):
                print(f"  row[{i}]:")
                if isinstance(row, dict):
                    _peek_row(row)
                else:
                    print("   non-dict row type:", type(row).__name__)

            # try to find sample site rows
            hits = []
            for row in container:
                if not isinstance(row, dict):
                    continue
                sid = _extract_site_id_from_row(row)
                status = _extract_status_from_row(row)
                if sid and status:
                    hits.append({"site": sid, "status": status})
                    if len(hits) >= 5:
                        break
            print("  sample site rows:", hits if hits else "none")

        except Exception as e:
            print("ERROR:", e)

def get_aiops_site_health_map(token: str, hours_window: int = 24) -> Dict[str, Dict[str, Any]]:
    start_time = iso_utc_hours_ago(hours_window)
    end_time = iso_utc_now()

    payloads = [
        # Minimal valid per your 200: filter required; enum uses poor|fair|good|all
        {"start_time": start_time, "end_time": end_time, "interval": "5min", "view": "summary",
         "filter": {"site_health": ["all"]}},
        # Try detail with explicit enums
        {"start_time": start_time, "end_time": end_time, "interval": "1hour", "view": "detail",
         "filter": {"site_health": ["poor", "fair", "good"]}},
        # Try grouping hints (ignored by API if unsupported)
        {"start_time": start_time, "end_time": end_time, "interval": "1hour", "view": "summary",
         "filter": {"site_health": ["all"]}, "group_by": ["site"]},
        {"start_time": start_time, "end_time": end_time, "interval": "1hour", "view": "detail",
         "filter": {"site_health": ["poor", "fair", "good"]}, "dimensions": ["site"]},
    ]

    site_health: Dict[str, Dict[str, Any]] = {}
    last_error: Optional[str] = None

    for p in payloads:
        try:
            data = api_post(AIOPS_HEALTH_EP, token, p)
        except requests.HTTPError as e:
            last_error = f"{e.response.status_code} {e.response.text[:400]}"
            continue

        # find a list container
        items: List[Dict[str, Any]] = []
        container = None
        if isinstance(data, dict):
            for k in ("items", "data", "sites", "results"):
                v = data.get(k)
                if isinstance(v, list):
                    container = v
                    break
        elif isinstance(data, list):
            container = data

        if not container:
            # last resort: scan tree
            for d in _flatten_dicts(data):
                if isinstance(d, dict) and any(k in d for k in ("site_id", "siteId", "site")):
                    items.append(d)
        else:
            items = container

        for row in items:
            if not isinstance(row, dict):
                continue
            sid = _extract_site_id_from_row(row)
            if not sid:
                continue
            status = _extract_status_from_row(row)
            # score: any numeric field containing "score"
            score = None
            for k, v in row.items():
                if isinstance(k, str) and "score" in k.lower() and isinstance(v, (int, float)):
                    score = float(v); break
            # normalize status to something readable (keep original if already good/fair/poor)
            if status:
                status = str(status).lower()
                if status in ("good", "fair", "poor", "all"):
                    pass  # leave as is
            site_health[str(sid)] = {"status": status, "score": score}

        if site_health:
            break

    if not site_health and last_error:
        print(f"AIOps health failed (all payloads). Last error: {last_error}")
    return site_health

# ---------- printing ----------

def _health_str_for_site(site_id: str, health_map: Optional[Dict[str, Dict[str, Any]]]) -> str:
    if not health_map:
        return ""
    h = health_map.get(str(site_id))
    if not h:
        return "  [Health: n/a]"
    status = h.get("status")
    score = h.get("score")
    if status and score is not None:
        return f"  [Health: {status}, score {score:.1f}]"
    if status:
        return f"  [Health: {status}]"
    if score is not None:
        return f"  [Health score: {score:.1f}]"
    return "  [Health: n/a]"

def print_group(title: str, sites: List[Dict[str, Any]], token: str,
                print_interfaces: bool = False, wan_only: bool = False,
                health_map: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
    print(f"\n########## {title} ({len(sites)}) ##########\n")
    if not sites:
        print("(none)\n"); return

    for s in sorted(sites, key=lambda x: (x.get("name") or "").lower()):
        s_name = s.get("name", "")
        s_id = str(s.get("id", ""))
        health_extra = _health_str_for_site(s_id, health_map)
        print(f"{s_name}  (Site ID: {s_id}){health_extra}")

        elements = get_site_elements(token, s_id)
        if not elements:
            print("  - Elements: (none)\n")
            continue

        _ = _get_site_wan_ifaces(token, s_id)  # warm cache per-site

        for e in sorted(elements, key=lambda x: (x.get("name") or "").lower()):
            e_name = e.get("name", "")
            e_id = str(e.get("id", ""))
            print(f"  - {e_name}  (Element ID: {e_id})")
            if not print_interfaces:
                continue

            intfs = get_element_interfaces(token, e_id)
            if not intfs:
                print("      Interfaces: (none)")
                continue

            for it in sorted(intfs, key=lambda x: (x.get("name") or "").lower()):
                sw_ids = [str(x) for x in (it.get("site_wan_interface_ids") or [])]
                label_names = _label_names_for_site_wan_iface_ids(token, s_id, sw_ids)
                if wan_only and not is_wan_interface(it, label_names):
                    continue
                if_name = it.get("name") or it.get("id") or ""
                if label_names:
                    print(f"      - {if_name} [labels: {', '.join(label_names)}]")
                else:
                    print(f"      - {if_name}")
        print("")

# ---------- main ----------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sites → Elements → Interfaces (labels) + optional AIOps Health")
    parser.add_argument("--interfaces", action="store_true", help="Print interfaces under each element")
    parser.add_argument("--wan-only", action="store_true", help="Only include interfaces tied to circuits/obvious WAN")
    parser.add_argument("--health", action="store_true", help="Fetch and print site health via AIOps")
    parser.add_argument("--health-window", type=int, default=24, help="Lookback hours for AIOps health (default: 24)")
    parser.add_argument("--debug-health", action="store_true", help="Verbose AIOps health probes + row peeks")
    args = parser.parse_args()

    _tenant_id = get_env_variable("TENANT_ID")
    token = get_token()
    profile = get_profile(token)

    tenant = profile.get("tsg_id") or profile.get("tenant_id") or profile.get("customer_id") or "unknown-tenant"
    user = profile.get("email") or profile.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # Optional: deep debug across a wider window so you actually see samples if they exist
    if args.debug_health:
        dbg_start = iso_utc_hours_ago(max(args.health_window, 24 * 7))
        debug_aiops_health(token, dbg_start, iso_utc_now(), region_hint=get_headers(token).get("x-panw-region"))

    sites = get_all_sites(token)
    branches, gateways = classify_sites(sites)

    want_interfaces = args.interfaces or args.wan_only
    health_map = get_aiops_site_health_map(token, args.health_window) if args.health else None
    if args.health and not health_map:
        print("Note: AIOps health returned no items for the given window.")

    print_group("Branches", branches, token, print_interfaces=want_interfaces, wan_only=args.wan_only, health_map=health_map)
    print_group("Branch Gateways", gateways, token, print_interfaces=want_interfaces, wan_only=args.wan_only, health_map=health_map)
