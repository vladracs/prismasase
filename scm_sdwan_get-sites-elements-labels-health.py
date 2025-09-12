#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Author: Vladimir F de Sousa - vfrancad@gmail.com
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

# ---- Endpoints
SITES_EP = "/sdwan/v4.11/api/sites"
ELEMENTS_TENANT_EP = "/sdwan/v3.1/api/elements"
INTERFACES_EP = "/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"
WAN_INTERFACES_EP = "/sdwan/v2.8/api/sites/{site_id}/waninterfaces"

# **Correct label catalog** (try a few versions)
WAN_LABELS_EPS = [
    "/sdwan/v2.6/api/waninterfacelabels",
    "/sdwan/v2.5/api/waninterfacelabels",
    "/sdwan/v2.0/api/waninterfacelabels",
]

# Optional AIOps health (kept from your working logic)
AIOPS_HEALTH_EP_PRIMARY = "/sdwan/v2.0/api/monitor/aiops/health"
AIOPS_HEALTH_EP_FALLBACK = "/sdwan/monitor/v2.0/api/monitor/aiops/health"

# ---- Caches
_ELEMENTS_CACHE: Optional[List[Dict[str, Any]]] = None
_WAN_BY_SITE_CACHE: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}
_WAN_BY_ID_CACHE: Dict[str, Dict[str, Dict[str, Any]]] = {}
# id -> {"name": friendly_name, "code": short_code}
_WAN_LABEL_MAP_CACHE: Optional[Dict[str, Dict[str, str]]] = None

# ---------- Auth / Headers ----------
def get_env_variable(name: str) -> str:
    v = os.getenv(name)
    if not v:
        raise ValueError(f"Environment variable {name} is not set")
    return v

def get_token() -> str:
    data_payload = {
        "client_id": get_env_variable("CLIENT_ID"),
        "client_secret": get_env_variable("CLIENT_SECRET"),
        "scope": f"tsg_id:{get_env_variable('TENANT_ID')}",
        "grant_type": "client_credentials",
    }
    r = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data_payload,
        timeout=30,
    )
    r.raise_for_status()
    return r.json()["access_token"]

def get_headers(token: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de",
    }

def get_profile(token: str) -> Dict[str, Any]:
    url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    r = requests.get(url, headers=get_headers(token), timeout=30)
    print("profile api status:", r.status_code)
    r.raise_for_status()
    return r.json()

# ---------- Basic GET/POST + pagination ----------
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
    results: List[Dict[str, Any]] = []
    q = dict(params or {})
    next_keys = ("next", "next_page", "nextPageToken", "page.next", "next_token")
    while True:
        data = api_get(endpoint, token, params=q)
        if isinstance(data, list):
            results.extend(data)
        elif isinstance(data, dict):
            if isinstance(data.get("items"), list):
                results.extend(data["items"])
            elif data and not results:
                results.append(data)
        nxt = None
        if isinstance(data, dict):
            for k in next_keys:
                if data.get(k):
                    nxt = data[k]; break
        if not nxt:
            break
        for ck in ("cursor", "page", "page_token", "next"):
            q[ck] = nxt
    return results

# ---------- Time helpers (for health, optional) ----------
def _to_iso_utc(dt: datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    else:
        dt = dt.astimezone(timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")

def _parse_user_time(s: str) -> datetime:
    s = s.strip()
    if s.lower() == "now":
        return datetime.now(timezone.utc)
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    fmts = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S", "%Y-%m-%d")
    for f in fmts:
        try:
            dt = datetime.strptime(s, f)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except ValueError:
            pass
    raise ValueError(f"Unrecognized time format: {s}")

def resolve_window(start: Optional[str], end: Optional[str], last_hours: Optional[int]) -> Tuple[str, str]:
    now = datetime.now(timezone.utc)
    if last_hours is not None:
        end_dt = now
        start_dt = end_dt - timedelta(hours=last_hours)
    else:
        start_dt = _parse_user_time(start) if start else None
        end_dt = _parse_user_time(end) if end else None
        if start_dt and not end_dt:
            end_dt = now
        elif end_dt and not start_dt:
            start_dt = end_dt - timedelta(hours=24)
        elif not start_dt and not end_dt:
            end_dt = now
            start_dt = end_dt - timedelta(hours=24)
    if start_dt >= end_dt:
        raise ValueError("start_time must be before end_time")
    return _to_iso_utc(start_dt), _to_iso_utc(end_dt)

# ---------- Normalizers ----------
def normalize_id_name(obj: Dict[str, Any]) -> None:
    if "id" not in obj:
        if "site_id" in obj: obj["id"] = obj["site_id"]
        elif "element_id" in obj: obj["id"] = obj["element_id"]
    if "name" not in obj and "display_name" in obj:
        obj["name"] = obj["display_name"]

# ---------- Inventory ----------
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
    return [e for e in _get_all_elements_cached(token)
            if str(e.get("site_id") or e.get("site") or "") == sid]

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
    if isinstance(raw, list): intfs = raw
    elif isinstance(raw, dict) and isinstance(raw.get("items"), list): intfs = raw["items"]
    elif isinstance(raw, dict): intfs = [raw]
    else: intfs = []
    for it in intfs:
        normalize_id_name(it)
    return intfs

def classify_sites(sites: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    branches, gateways = [], []
    for s in sites:
        (gateways if s.get("branch_gateway", False) else branches).append(s)
    return branches, gateways

# ---------- WAN helpers ----------
def _get_site_wans_by_id(token: str, site_id: str) -> Dict[str, Dict[str, Any]]:
    sid = str(site_id)
    if sid in _WAN_BY_ID_CACHE:
        return _WAN_BY_ID_CACHE[sid]
    ep = WAN_INTERFACES_EP.format(site_id=sid)
    raw = api_get(ep, token)
    if isinstance(raw, dict) and isinstance(raw.get("items"), list):
        items = raw["items"]
    elif isinstance(raw, list):
        items = raw
    else:
        items = []
    for it in items: normalize_id_name(it)
    by_id: Dict[str, Dict[str, Any]] = {}
    for it in items:
        wid = str(it.get("id") or it.get("wan_interface_id") or "")
        if wid: by_id[wid] = it
    _WAN_BY_ID_CACHE[sid] = by_id
    return by_id

# ---------- WAN label catalog (id -> {name, code}) ----------
def _get_wan_label_map(token: str) -> Dict[str, Dict[str, str]]:
    global _WAN_LABEL_MAP_CACHE
    if _WAN_LABEL_MAP_CACHE is not None:
        return _WAN_LABEL_MAP_CACHE

    out: Dict[str, Dict[str, str]] = {}
    for ep in WAN_LABELS_EPS:
        try:
            data = api_get(ep, token)
        except requests.HTTPError:
            continue
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            items = data["items"]
        elif isinstance(data, list):
            items = data
        else:
            items = []
        for it in items:
            lid = str(it.get("id") or "")
            # Friendly "name" (e.g., "Ethernet Internet") and short "label" code (e.g., "public-7")
            fname = it.get("name") or it.get("display_name") or ""
            code = it.get("label") or ""
            if lid:
                out[lid] = {"name": str(fname or code), "code": str(code)}
        if out:
            break

    _WAN_LABEL_MAP_CACHE = out
    return out

def _label_strings_from_wan(wan_obj: Dict[str, Any], label_map: Dict[str, Dict[str, str]]) -> List[str]:
    """
    Pull human labels from a WAN object.
    Most commonly via wan_obj['label_id'].
    Returns list of 'Friendly (code)' strings, de-duplicated.
    """
    labels: List[str] = []

    def add_label_by_id(lid: str):
        meta = label_map.get(str(lid))
        if not meta:
            labels.append(f"label_id:{lid}")
            return
        name = meta.get("name") or ""
        code = meta.get("code") or ""
        if code and code != name:
            labels.append(f"{name} ({code})")
        else:
            labels.append(name or code)

    # The common field
    lid = wan_obj.get("label_id")
    if isinstance(lid, list):
        for x in lid:
            if x: add_label_by_id(str(x))
    elif lid:
        add_label_by_id(str(lid))

    # Some tenants also expose nested link.* labels as IDs
    link = wan_obj.get("link") or {}
    for key in ("label_id", "labels"):
        v = link.get(key)
        if isinstance(v, list):
            for x in v:
                if x: add_label_by_id(str(x))
        elif v:
            add_label_by_id(str(v))

    # dedupe, keep order
    seen = set(); uniq = []
    for x in labels:
        if x and x not in seen:
            uniq.append(x); seen.add(x)
    return uniq

# ---------- AIOps Site Health (optional, unchanged) ----------
def _flatten_dicts(obj):
    if isinstance(obj, dict):
        yield obj
        for v in obj.values():
            yield from _flatten_dicts(v)
    elif isinstance(obj, list):
        for it in obj:
            yield from _flatten_dicts(it)

def _health_items_from_response(data: Any) -> List[Dict[str, Any]]:
    if isinstance(data, dict):
        for key in ("items", "data", "sites", "results"):
            v = data.get(key)
            if isinstance(v, list):
                return v
        out = []
        for d in _flatten_dicts(data):
            if any(k in d for k in ("site_id", "siteId", "site")):
                out.append(d)
        return out
    elif isinstance(data, list):
        return data
    return []

def _extract_health_status(item: Dict[str, Any]) -> Optional[str]:
    for k in ("status", "site_health", "state", "health"):
        v = item.get(k)
        if isinstance(v, str) and v:
            return v
    return None

def _extract_health_score(item: Dict[str, Any]) -> Optional[float]:
    for k, v in item.items():
        if "score" in str(k).lower() and isinstance(v, (int, float)):
            return float(v)
    return None

def get_aiops_site_health_map(token: str, start_time_iso: str, end_time_iso: str) -> Dict[str, Dict[str, Any]]:
    def _query(ep: str, payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        d = api_post(ep, token, payload)
        items = _health_items_from_response(d)
        out: Dict[str, Dict[str, Any]] = {}
        for it in items:
            sid = str(it.get("site_id") or it.get("siteId") or it.get("site") or it.get("id") or "")
            if not sid:
                continue
            out[sid] = {"status": _extract_health_status(it), "score": _extract_health_score(it)}
        return out

    payload_primary = {
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "interval": "5min",
        "view": "summary",
        "metrics": [{"name": "HealthScore", "statistics": ["avg"], "unit": "PERCENT"}],
        "filter": {"site_health": ["all"]},
    }
    try:
        data = _query(AIOPS_HEALTH_EP_PRIMARY, payload_primary)
        if data: return data
    except requests.HTTPError:
        pass

    payload_no_metrics = {
        "start_time": start_time_iso,
        "end_time": end_time_iso,
        "interval": "5min",
        "view": "summary",
        "filter": {"site_health": ["all"]},
    }
    try:
        data = _query(AIOPS_HEALTH_EP_PRIMARY, payload_no_metrics)
        if data: return data
    except requests.HTTPError:
        pass

    try:
        data = _query(AIOPS_HEALTH_EP_FALLBACK, payload_no_metrics)
        if data: return data
    except requests.HTTPError as e:
        txt = getattr(e.response, "text", str(e))
        print("AIOps health failed (legacy path):", txt)

    return {}

# ---------- Printing ----------
def _health_str_for_site(site_id: str, health_map: Optional[Dict[str, Dict[str, Any]]]) -> str:
    if not health_map:
        return ""
    h = health_map.get(str(site_id))
    if not h:
        return "  [Health: n/a]"
    status, score = h.get("status"), h.get("score")
    if status and score is not None:
        return f"  [Health: {status}, score {score:.1f}]"
    if status:
        return f"  [Health: {status}]"
    if score is not None:
        return f"  [Health score: {score:.1f}]"
    return "  [Health: n/a]"

def print_group(
    title: str,
    sites: List[Dict[str, Any]],
    token: str,
    print_interfaces: bool = False,
    wan_only: bool = False,
    health_map: Optional[Dict[str, Dict[str, Any]]] = None,
) -> None:
    print(f"\n########## {title} ({len(sites)}) ##########\n")
    if not sites:
        print("(none)\n"); return

    for s in sorted(sites, key=lambda x: (x.get("name") or "").lower()):
        s_name, s_id = s.get("name", ""), s.get("id", "")
        print(f"{s_name}  (Site ID: {s_id}){_health_str_for_site(s_id, health_map)}")

        elements = get_site_elements(token, s_id)
        if not elements:
            print("  - Elements: (none)\n"); continue

        # Prepare once per site if needed
        wan_id_map = _get_site_wans_by_id(token, s_id) if (print_interfaces and wan_only) else None
        label_map = _get_wan_label_map(token) if (print_interfaces and wan_only) else None

        for e in sorted(elements, key=lambda x: (x.get("name") or "").lower()):
            e_name, e_id = e.get("name", ""), e.get("id", "")
            print(f"  - {e_name}  (Element ID: {e_id})")

            if not print_interfaces:
                continue

            intfs = get_element_interfaces(token, e_id)
            if wan_only:
                # keep only element interfaces that are bound to a site WAN interface
                intfs = [it for it in intfs if it.get("site_wan_interface_ids")]

            if not intfs:
                print("      Interfaces: (none)" if not wan_only else "      WAN (with labels): (none)")
                continue

            printed_any = False
            for it in sorted(intfs, key=lambda x: (x.get("name") or x.get("id") or "")):
                if_name = it.get("name") or it.get("id") or ""

                if wan_only:
                    wid_list = it.get("site_wan_interface_ids") or []
                    labels_found: List[str] = []
                    for wid in wid_list:
                        wan_obj = (wan_id_map or {}).get(str(wid))
                        if not wan_obj:
                            continue
                        labels_found.extend(_label_strings_from_wan(wan_obj, label_map or {}))

                    labels_found = sorted(set(labels_found))
                    if not labels_found:
                        # skip if we insisted on WAN-only with labels
                        continue

                    printed_any = True
                    print(f"      - {if_name} [labels: {', '.join(labels_found)}]")
                else:
                    printed_any = True
                    print(f"      - {if_name}")

            if wan_only and not printed_any:
                print("      WAN (with labels): (none)")
        print("")

# ---------- Main ----------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(
        description="Sites → Elements grouped by Branch/Branch Gateway (+ optional Interfaces & AIOps Health)"
    )
    ap.add_argument("--interfaces", action="store_true", help="Also print interfaces under each element")
    ap.add_argument("--wan-only", action="store_true", help="Only ports attached to WAN interfaces (with labels); implies --interfaces")
    ap.add_argument("--health", action="store_true", help="Fetch and print site health via AIOps")
    ap.add_argument("--start", default=None, help="Health start time (ISO 8601), e.g. 2025-09-10T00:00:00Z")
    ap.add_argument("--end", default=None, help="Health end time (ISO 8601), e.g. 2025-09-11T00:00:00Z")
    ap.add_argument("--last", type=int, default=None, help="Health last N hours (overrides --start/--end)")
    args = ap.parse_args()

    print_if = args.interfaces or args.wan_only

    # Auth
    _ = get_env_variable("TENANT_ID")
    token = get_token()
    profile = get_profile(token)
    tenant = profile.get("tsg_id") or profile.get("tenant_id") or profile.get("customer_id") or "unknown-tenant"
    user = profile.get("email") or profile.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # Sites + grouping
    sites = get_all_sites(token)
    branches, gateways = classify_sites(sites)

    # Optional health
    health_map = None
    if args.health:
        start_iso, end_iso = resolve_window(args.start, args.end, args.last)
        health_map = get_aiops_site_health_map(token, start_iso, end_iso)
        if not health_map:
            print("Note: AIOps health returned no items for the given window.")

    # Output
    print_group("Branches", branches, token,
                print_interfaces=print_if, wan_only=args.wan_only, health_map=health_map)
    print_group("Branch Gateways", gateways, token,
                print_interfaces=print_if, wan_only=args.wan_only, health_map=health_map)
