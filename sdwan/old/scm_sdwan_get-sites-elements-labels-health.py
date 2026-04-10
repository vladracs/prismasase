#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Minimal, working Sites → Elements (+ WAN labels) + AIOps site health
#
# Env:
#   export CLIENT_ID="..."
#   export CLIENT_SECRET="..."
#   export TENANT_ID="..."   # (aka tsg_id)

#Prereqs
#Python 3.9+
#pip install requests
#Prisma SASE OAuth2 credentials
#Note: The script sends requests with header x-panw-region: de.
#If your tenant is in a different region, change that value in the script.
#What the script does
#
#Lists Sites → Elements, grouped as Branches and Branch Gateways.
#(Optional) Lists interfaces per element and shows circuit label names attached to them.
#(Optional) Fetches AIOps Site Health (Good/Fair/Poor) and shows it next to each site.
#
#Options

#--interfaces
#Print interfaces under each element (shows only interfaces that have circuit labels; prints the port name/number and the human-readable label, e.g. public-10, Unmetered 5G Internet (public-5)).

#--health
#Fetch and show site health (Good/Fair/Poor) for the selected time window.

#--start <ISO8601> and --end <ISO8601>
#Optional time window for health, e.g. --start 2025-09-12T17:51:16Z --end 2025-09-12T20:46:16Z.
#If omitted, the script defaults to the last 24 hours.

import os
import json
import argparse
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timedelta, timezone

import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

# Inventory endpoints
SITES_EP = "/sdwan/v4.11/api/sites"
ELEMENTS_TENANT_EP = "/sdwan/v3.1/api/elements"
INTERFACES_EP = "/sdwan/v4.21/api/sites/{site_id}/elements/{element_id}/interfaces"

# WAN label lookup + site WAN↔interface mapper
WAN_LABELS_EP = "/sdwan/v2.6/api/waninterfacelabels"
SITE_WANINTERFACES_EP = "/sdwan/v2.8/api/sites/{site_id}/waninterfaces"

# AIOps health
AIOPS_HEALTH_EP = "/sdwan/monitor/v2.0/api/monitor/aiops/health"

# cache
_ELEMENTS_CACHE: Optional[List[Dict[str, Any]]] = None


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

def headers(token: str) -> Dict[str, str]:
    return {
        "accept": "application/json",
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "x-panw-region": "de",  # adjust if your tenant region differs
    }


# ---------- tiny HTTP ----------
def api_get(ep: str, token: str, params: Optional[Dict[str, Any]] = None) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.get(url, headers=headers(token), params=params, timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def api_post(ep: str, token: str, payload: Dict[str, Any]) -> Any:
    url = ep if ep.startswith("http") else f"{BASE_API_URL}{ep}"
    r = requests.post(url, headers=headers(token), data=json.dumps(payload), timeout=60)
    r.raise_for_status()
    if not r.text.strip():
        return None
    try:
        return r.json()
    except json.JSONDecodeError:
        return r.text

def fetch_all_pages(ep: str, token: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    res: List[Dict[str, Any]] = []
    q = dict(params or {})
    while True:
        data = api_get(ep, token, params=q)
        if isinstance(data, list):
            res.extend(data)
        elif isinstance(data, dict):
            if isinstance(data.get("items"), list):
                res.extend(data["items"])
            else:
                if not res and data:
                    res.append(data)
        # very light cursor handling (common keys)
        nxt = None
        if isinstance(data, dict):
            for k in ("next", "next_page", "nextPageToken", "page.next", "next_token"):
                if data.get(k):
                    nxt = data[k]
                    break
        if not nxt:
            break
        for ck in ("cursor", "page", "page_token", "next"):
            q[ck] = nxt
    return res


# ---------- inventory ----------
def normalize_id_name(o: Dict[str, Any]) -> None:
    if "id" not in o:
        if "site_id" in o:
            o["id"] = o["site_id"]
        elif "element_id" in o:
            o["id"] = o["element_id"]
    if "name" not in o and "display_name" in o:
        o["name"] = o["display_name"]

def get_profile(token: str) -> Dict[str, Any]:
    prof = api_get("/sdwan/v2.1/api/profile", token)
    print("profile api status: 200")
    return prof

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
    elems = _get_all_elements_cached(token)
    sid = str(site_id)
    return [e for e in elems if str(e.get("site_id") or e.get("site") or "") == sid]

def get_element_interfaces(token: str, element_id: str) -> List[Dict[str, Any]]:
    elems = _get_all_elements_cached(token)
    m = next((e for e in elems if str(e.get("id") or e.get("element_id")) == str(element_id)), None)
    if not m:
        return []
    site_id = str(m.get("site_id") or m.get("site") or "")
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


# ---------- WAN labels ----------
def get_wan_label_lookup(token: str) -> Dict[str, str]:
    """
    Returns { label_id: 'Name (code)' }  e.g. 1751883670130002245 -> 'Unmetered 5G Internet (public-5)'
    """
    items = fetch_all_pages(WAN_LABELS_EP, token)
    lookup: Dict[str, str] = {}
    for it in items:
        lid = str(it.get("id", ""))
        name = it.get("name") or ""
        code = it.get("label") or ""
        if lid:
            disp = f"{name} ({code})" if name and code and name != code else (name or code or lid)
            lookup[lid] = disp
    return lookup

def get_site_interface_labels_map(token: str, site_id: str, label_lookup: Dict[str, str]) -> Dict[str, List[str]]:
    """
    For a site, returns: { interface_id: [label_display, ...] }
    Uses /sites/{site}/waninterfaces (each has label_id and interface_ids[]).
    """
    ep = SITE_WANINTERFACES_EP.format(site_id=site_id)
    data = api_get(ep, token)
    items = data.get("items", []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
    mapping: Dict[str, List[str]] = {}
    for wi in items:
        label_id = str(wi.get("label_id") or "")
        if not label_id:
            continue
        label_disp = label_lookup.get(label_id, f"label_id:{label_id}")
        for intf_id in wi.get("interface_ids", []) or []:
            iid = str(intf_id)
            mapping.setdefault(iid, []).append(label_disp)
    return mapping


# ---------- AIOps site health (simple & working) ----------
def iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def iso_utc_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def get_aiops_site_health_map(token: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, str]:
    """
    Calls AIOps health with:
      view=summary, interval=5min, filter.site_health=[good,fair,poor]

    Expected response shape (example):
      {
        "_status_code": 200,
        "interval": "5min",
        "start_time": "...",
        "end_time": "...",
        "data": [{
          "type": "site_health",
          "total": 1,
          "poor": {"count": 0, "site_ids": []},
          "fair": {"count": 1, "site_ids": ["1752745283015002645"]},
          "good": {"count": 0, "site_ids": []}
        }],
        "view": "summary"
      }

    Returns: { "<site_id>": "good"|"fair"|"poor" }
    """
    from datetime import datetime, timedelta, timezone

    def _iso_now() -> str:
        return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _iso_hours_ago(h: int) -> str:
        return (datetime.now(timezone.utc) - timedelta(hours=h)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    if not start_time or not end_time:
        # default: last 6 hours
        start_time = _iso_hours_ago(6)
        end_time = _iso_now()

    payload = {
        "start_time": start_time,
        "end_time": end_time,
        "interval": "5min",
        "filter": {"site_health": ["good", "fair", "poor"]},
        "view": "summary",
    }

    data = api_post(AIOPS_HEALTH_EP, token, payload)

    site_health: Dict[str, str] = {}

    # --- Primary: parse summary buckets with site_ids ---
    if isinstance(data, dict):
        arr = data.get("data")
        if isinstance(arr, list):
            bucket = next((x for x in arr if isinstance(x, dict) and x.get("type") == "site_health"), None)
            if bucket:
                for status in ("good", "fair", "poor"):
                    ids = ((bucket.get(status) or {}).get("site_ids")) or []
                    for sid in ids:
                        site_health[str(sid)] = status

    # --- Fallback: if some tenants return per-row shapes (rare) ---
    if not site_health:
        def _walk(obj: Any):
            if isinstance(obj, dict):
                sid = obj.get("site_id") or obj.get("site") or obj.get("id")
                sh = obj.get("site_health") or obj.get("status") or obj.get("health")
                if sid and isinstance(sh, str):
                    sh_norm = sh.strip().lower()
                    if sh_norm in ("good", "fair", "poor"):
                        site_health[str(sid)] = sh_norm
                for v in obj.values():
                    _walk(v)
            elif isinstance(obj, list):
                for it in obj:
                    _walk(it)
        _walk(data)

    # optional, tiny debug
    if not site_health:
        print("Note: AIOps health returned no site rows for the given window.")
    else:
        counts = {"good": 0, "fair": 0, "poor": 0}
        for s in site_health.values():
            if s in counts:
                counts[s] += 1
        print(f"AIOps health mapped: good={counts['good']} fair={counts['fair']} poor={counts['poor']}")

    return site_health



# ---------- printing ----------
def health_suffix(site_id: str, health_map: Optional[Dict[str, str]]) -> str:
    if not health_map:
        return ""
    st = health_map.get(str(site_id))
    if not st:
        return "  [Health: n/a]"
    return f"  [Health: {st.capitalize()}]"

def print_group(
    title: str,
    sites: List[Dict[str, Any]],
    token: str,
    print_interfaces: bool,
    wan_only: bool,
    label_lookup: Dict[str, str],
    health_map: Optional[Dict[str, str]] = None,
) -> None:
    print(f"\n########## {title} ({len(sites)}) ##########\n")
    if not sites:
        print("(none)\n")
        return

    for s in sorted(sites, key=lambda x: (x.get("name") or "").lower()):
        s_name = s.get("name", "")
        s_id = s.get("id", "")
        print(f"{s_name}  (Site ID: {s_id}){health_suffix(s_id, health_map)}")

        elements = get_site_elements(token, s_id)
        if not elements:
            print("  - Elements: (none)\n")
            continue

        # Build mapping of interface_id -> [labels] once per site
        intf_labels_map = get_site_interface_labels_map(token, s_id, label_lookup)

        for e in sorted(elements, key=lambda x: (x.get("name") or "").lower()):
            e_name = e.get("name", "")
            e_id = e.get("id", "")
            print(f"  - {e_name}  (Element ID: {e_id})")

            if not print_interfaces:
                continue

            intfs = get_element_interfaces(token, e_id)
            if not intfs:
                print("      Interfaces: (none)")
                continue

            for it in sorted(intfs, key=lambda x: (x.get("name") or "").lower()):
                iid = str(it.get("id", ""))
                iname = it.get("name") or iid

                labels_for_intf = intf_labels_map.get(iid, [])
                # If wan-only is set, only print interfaces that have a circuit label
                if wan_only and not labels_for_intf:
                    continue

                label_str = ""
                if labels_for_intf:
                    # Join multiple labels if present (rare but possible)
                    label_str = f" [labels: {', '.join(labels_for_intf)}]"

                # If wan-only is False, you still see all interfaces, with labels (if any)
                print(f"      - {iname}{label_str}")

        print("")  # spacing per site


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(
        description="Sites → Elements (optional WAN-labeled Interfaces) + AIOps health (good/fair/poor)"
    )
    parser.add_argument("--interfaces", action="store_true", help="Print interfaces under each element")
    parser.add_argument("--wan-only", action="store_true", help="Only show interfaces that have a circuit label")
    parser.add_argument("--health", action="store_true", help="Show site health (good/fair/poor) from AIOps")
    parser.add_argument("--health-window-hours", type=int, default=6,
                        help="Lookback window in hours for site health (default: 6). Ignored if --health-start/end provided.")
    parser.add_argument("--health-start", type=str, default=None,
                        help="Optional ISO8601 start (e.g., 2025-09-12T17:51:16Z)")
    parser.add_argument("--health-end", type=str, default=None,
                        help="Optional ISO8601 end   (e.g., 2025-09-12T20:46:16Z)")
    args = parser.parse_args()

    # Validate env and auth
    _ = _must_env("TENANT_ID")
    token = get_token()
    prof = get_profile(token)
    tenant = prof.get("tsg_id") or prof.get("tenant_id") or prof.get("customer_id") or "unknown-tenant"
    user = prof.get("email") or prof.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # Inventory
    sites = get_all_sites(token)
    branches, gateways = classify_sites(sites)

    # Label lookup (once)
    label_lookup = get_wan_label_lookup(token)

    # Health (optional)
    health_map: Optional[Dict[str, str]] = None
    if args.health:
        if args.health_start and args.health_end:
            start_t, end_t = args.health_start, args.health_end
        else:
            start_t = iso_utc_hours_ago(args.health_window_hours)
            end_t = iso_utc_now()
        try:
            health_map = get_aiops_site_health_map(token, start_t, end_t)
            if not health_map:
                print("Note: AIOps health returned no site rows for the given window.")
        except requests.HTTPError as e:
            print(f"AIOps health error: {e}")
            health_map = None

    print_if = args.interfaces or args.wan_only

    print_group("Branches", branches, token, print_if, args.wan_only, label_lookup, health_map)
    print_group("Branch Gateways", gateways, token, print_if, args.wan_only, label_lookup, health_map)


if __name__ == "__main__":
    main()
