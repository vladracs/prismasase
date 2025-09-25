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

# Topology
TOPOLOGY_EP = "/sdwan/v3.6/api/topology"

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
    Returns { label_id: 'Name (code)' }
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


# ---------- AIOps site health ----------
def iso_utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def iso_utc_hours_ago(hours: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=hours)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

def get_aiops_site_health_map(token: str, start_time: Optional[str] = None, end_time: Optional[str] = None) -> Dict[str, str]:
    if not start_time or not end_time:
        start_time = iso_utc_hours_ago(6)
        end_time = iso_utc_now()

    payload = {
        "start_time": start_time,
        "end_time": end_time,
        "interval": "5min",
        "filter": {"site_health": ["good", "fair", "poor"]},
        "view": "summary",
    }

    data = api_post(AIOPS_HEALTH_EP, token, payload)
    site_health: Dict[str, str] = {}

    if isinstance(data, dict):
        arr = data.get("data")
        if isinstance(arr, list):
            bucket = next((x for x in arr if isinstance(x, dict) and x.get("type") == "site_health"), None)
            if bucket:
                for status in ("good", "fair", "poor"):
                    ids = ((bucket.get(status) or {}).get("site_ids")) or []
                    for sid in ids:
                        site_health[str(sid)] = status

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

    if not site_health:
        print("Note: AIOps health returned no site rows for the given window.")
    else:
        counts = {"good": 0, "fair": 0, "poor": 0}
        for s in site_health.values():
            if s in counts:
                counts[s] += 1
        print(f"AIOps health mapped: good={counts['good']} fair={counts['fair']} poor={counts['poor']}")
    return site_health


# ---------- printing (existing) ----------
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
                if wan_only and not labels_for_intf:
                    continue

                label_str = f" [labels: {', '.join(labels_for_intf)}]" if labels_for_intf else ""
                print(f"      - {iname}{label_str}")

        print("")


# ========== NEW: Topology helpers ==========
def get_topology(
    token: str,
    site_id: Optional[str],
    include_servicelinks: bool = True,
    include_stub_links: bool = True,
    topo_type: str = "anynet",   # "anynet" or "all" (API expects a string; "anynet" is what you used)
) -> Dict[str, Any]:
    """
    Calls /sdwan/v3.6/api/topology with your desired filters.
    """
    payload: Dict[str, Any] = {
        "type": topo_type,  # "anynet" shows fabric + (optionally) servicelinks + stubs per your flags
    }
    if site_id:
        payload["site_id"] = str(site_id)
    if include_servicelinks:
        payload["servicelinks"] = True
    if include_stub_links:
        payload["stub_links"] = True

    data = api_post(TOPOLOGY_EP, token, payload)
    if not isinstance(data, dict):
        raise ValueError("Unexpected topology response")
    # Normalize presence of keys
    data.setdefault("nodes", [])
    data.setdefault("links", [])
    return data

def _node_name(n: Dict[str, Any]) -> str:
    t = n.get("type")
    if t == "SITE":
        return n.get("name") or str(n.get("id"))
    if t == "SERVICE_ENDPOINT":
        return n.get("name") or "ServiceEndpoint"
    if t == "INET_CLOUD":
        return n.get("name") or "Internet"
    return n.get("name") or str(n.get("id"))

def print_topology(topo: Dict[str, Any], wide: bool = False, on_demand_only: bool = False) -> None:
    nodes: List[Dict[str, Any]] = topo.get("nodes", [])
    links: List[Dict[str, Any]] = topo.get("links", [])

    # Build id -> node lookup
    node_by_id: Dict[str, Dict[str, Any]] = {str(n.get("id")): n for n in nodes}

    # Header
    typ = topo.get("type", "anynet")
    print(f"\n########## Topology view (type={typ}) ##########")
    print(f"Nodes: {len(nodes)} | Links: {len(links)}\n")

    # Pretty print nodes
    if nodes:
        print("Nodes:")
        for n in nodes:
            nid = str(n.get("id"))
            ntype = n.get("type")
            name = _node_name(n)
            role = n.get("role")
            is_sase = n.get("is_sase")
            extra = []
            if role:
                extra.append(f"role={role}")
            if is_sase is True:
                extra.append("SASE")
            if ntype == "SITE" and n.get("state"):
                extra.append(f"state={n.get('state')}")
            extra_str = f" ({', '.join(extra)})" if extra else ""
            print(f"  - {name} [{ntype}] id={nid}{extra_str}")
        print("")

    # Filter links if requested
    if on_demand_only:
        links = [l for l in links if (l.get("sub_type") == "on-demand")]

    if not links:
        print("Links: (none)\n")
        return

    # Links table
    print("Links:")
    for L in links:
        ltype = L.get("type")  # servicelink | public-anynet | internet-stub | ...
        status = L.get("status")
        subtype = L.get("sub_type")
        src_id = str(L.get("source_node_id"))
        dst_id = str(L.get("target_node_id"))
        src = node_by_id.get(src_id, {"name": src_id, "type": "?"})
        dst = node_by_id.get(dst_id, {"name": dst_id, "type": "?"})
        src_name = _node_name(src)
        dst_name = _node_name(dst)

        # WAN/network decorations (when present)
        src_wan = L.get("source_wan_network") or L.get("network")
        dst_wan = L.get("target_wan_network") or L.get("network")

        left = f"{src_name}"
        if src_wan:
            left += f" [{src_wan}]"
        right = f"{dst_name}"
        if dst_wan and ltype != "servicelink":
            right += f" [{dst_wan}]"

        # Extras
        extras: List[str] = []
        if ltype == "servicelink":
            sep = L.get("sep_name")
            wan_name = L.get("wan_nw_name")
            if wan_name:
                extras.append(f"WAN={wan_name}")
            if sep:
                extras.append(f"SEP={sep}")
        if ltype.endswith("anynet"):
            v = L.get("vpnlinks")
            if isinstance(v, list):
                extras.append(f"vpnlinks={len(v)}")
        if "admin_up" in L:
            extras.append(f"admin_up={L.get('admin_up')}")
        if L.get("cost") is not None:
            extras.append(f"cost={L.get('cost')}")
        if subtype:
            extras.append(f"sub={subtype}")

        # Wide mode includes path_id and IDs
        if wide:
            pid = L.get("path_id")
            extras.insert(0, f"path_id={pid}")
            extras.append(f"src_id={src_id}")
            extras.append(f"dst_id={dst_id}")

        extras_str = f" ({', '.join(extras)})" if extras else ""
        print(f"  - {status:<4} | {ltype:<14} | {left}  -->  {right}{extras_str}")

    print("")


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(
        description="Topology"
    )
 
    # NEW: topology args
    parser.add_argument("--topology-site", type=str, default=None,
                        help="If set, prints a topology view centered on the given site_id (same as topology API site_id).")
    parser.add_argument("--topology-type", type=str, default="anynet",
                        help='Topology type to request. Default: "anynet".')
    parser.add_argument("--servicelinks", action="store_true",
                        help="Include Service Link edges in topology view (default on).")
    parser.add_argument("--no-servicelinks", action="store_true",
                        help="Exclude Service Link edges in topology view.")
    parser.add_argument("--stub-links", action="store_true",
                        help="Include internet-stub edges (default on).")
    parser.add_argument("--no-stub-links", action="store_true",
                        help="Exclude internet-stub edges.")
    parser.add_argument("--on-demand-only", action="store_true",
                        help="Show only on-demand anynet links in topology output.")
    parser.add_argument("--wide", action="store_true",
                        help="Wide topology output (include IDs and path_id).")
    args = parser.parse_args()

    # Validate env and auth
    _ = _must_env("TENANT_ID")
    token = get_token()
    prof = get_profile(token)  # mandatory call for prisma sd-wan api - do not remove
    tenant = prof.get("tsg_id") or prof.get("tenant_id") or prof.get("customer_id") or "unknown-tenant"
    user = prof.get("email") or prof.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # If user asked for topology, do it first (fast and self-contained)
    if args.topology_site or args.topology_type:
        inc_sl = False if args.no_servicelinks else True if (args.servicelinks or not args.no_servicelinks) else True
        inc_stub = False if args.no_stub_links else True if (args.stub_links or not args.no_stub_links) else True

        topo = get_topology(
            token=token,
            site_id=args.topology_site,
            include_servicelinks=inc_sl,
            include_stub_links=inc_stub,
            topo_type=args.topology_type or "anynet",
        )
        print_topology(topo, wide=args.wide, on_demand_only=args.on_demand_only)


if __name__ == "__main__":
    main()
