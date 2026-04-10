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
# Usage examples:
#   python3 scm_sdwan_topology.py --topology-site 1752745283015002645
#   python3 scm_sdwan_topology.py --topology-site 1752745283015002645 --details --wide
#   python3 scm_sdwan_topology.py --topology-site 1752745283015002645 --on-demand-only
#   python3 scm_sdwan_topology.py --topology-site 1752745283015002645 --no-servicelinks --no-stub-links
#
# Notes:
# - Adds detailed enrichment for AnyNet vpnlinks and Service Links (crypto + rekey timers when available).
# - Region header defaults to "de"; adjust if your tenant differs.

import os
import json
import argparse
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

# Elements cache (for resolving site_id from element_id when printing Service Link details)
ELEMENTS_TENANT_EP = "/sdwan/v3.1/api/elements"

# Topology
TOPOLOGY_EP = "/sdwan/v3.6/api/topology"

# Status endpoints
VPNLINK_STATUS_EP_TMPL = "/sdwan/v2.1/api/vpnlinks/{vpn_link_id}/status"
IF_STATUS_EP_TMPL = "/sdwan/v3.9/api/sites/{site_id}/elements/{element_id}/interfaces/{interface_id}/status"

# Cache
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


# ---------- Elements cache ----------
def _get_all_elements_cached(token: str) -> List[Dict[str, Any]]:
    global _ELEMENTS_CACHE
    if _ELEMENTS_CACHE is None:
        data = api_get(ELEMENTS_TENANT_EP, token)
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            _ELEMENTS_CACHE = data["items"]
        elif isinstance(data, list):
            _ELEMENTS_CACHE = data
        else:
            _ELEMENTS_CACHE = []
    return _ELEMENTS_CACHE

def get_site_id_for_element(token: str, element_id: str) -> Optional[str]:
    elems = _get_all_elements_cached(token)
    m = next((e for e in elems if str(e.get("id") or e.get("element_id")) == str(element_id)), None)
    if not m:
        return None
    return str(m.get("site_id") or m.get("site") or "")


# ---------- Profile (mandatory warm-up) ----------
def get_profile(token: str) -> Dict[str, Any]:
    prof = api_get("/sdwan/v2.1/api/profile", token)
    print("profile api status: 200")
    return prof


# ---------- Topology + Details ----------
def get_topology(
    token: str,
    site_id: Optional[str],
    include_servicelinks: bool = True,
    include_stub_links: bool = True,
    topo_type: str = "anynet",
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"type": topo_type}
    if site_id:
        payload["site_id"] = str(site_id)
    if include_servicelinks:
        payload["servicelinks"] = True
    if include_stub_links:
        payload["stub_links"] = True

    data = api_post(TOPOLOGY_EP, token, payload)
    if not isinstance(data, dict):
        raise ValueError("Unexpected topology response")
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

def _fmt_epoch_ms(ms: Optional[int]) -> str:
    try:
        if not ms:
            return "n/a"
        return datetime.fromtimestamp(int(ms)/1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return str(ms)

def get_vpnlink_status(token: str, vpn_link_id: str) -> Dict[str, Any]:
    ep = VPNLINK_STATUS_EP_TMPL.format(vpn_link_id=str(vpn_link_id))
    data = api_get(ep, token)
    return data if isinstance(data, dict) else {}

def get_interface_status(token: str, site_id: str, element_id: str, interface_id: str) -> Dict[str, Any]:
    ep = IF_STATUS_EP_TMPL.format(site_id=str(site_id), element_id=str(element_id), interface_id=str(interface_id))
    data = api_get(ep, token)
    return data if isinstance(data, dict) else {}

def print_topology(topo: Dict[str, Any], *, wide: bool = False, on_demand_only: bool = False,
                   details: bool = False, token: Optional[str] = None) -> None:
    nodes: List[Dict[str, Any]] = topo.get("nodes", [])
    links: List[Dict[str, Any]] = topo.get("links", [])

    node_by_id: Dict[str, Dict[str, Any]] = {str(n.get("id")): n for n in nodes}

    typ = topo.get("type", "anynet")
    print(f"\n########## Topology view (type={typ}) ##########")
    print(f"Nodes: {len(nodes)} | Links: {len(links)}\n")

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

    if on_demand_only:
        links = [l for l in links if (l.get("sub_type") == "on-demand")]

    if not links:
        print("Links: (none)\n")
        return

    print("Links:")
    for L in links:
        ltype = L.get("type")
        status = L.get("status")
        subtype = L.get("sub_type")
        src_id = str(L.get("source_node_id"))
        dst_id = str(L.get("target_node_id"))
        src = node_by_id.get(src_id, {"name": src_id, "type": "?"})
        dst = node_by_id.get(dst_id, {"name": dst_id, "type": "?"})
        src_name = _node_name(src)
        dst_name = _node_name(dst)

        src_wan = L.get("source_wan_network") or L.get("network")
        dst_wan = L.get("target_wan_network") or L.get("network")

        left = f"{src_name}" + (f" [{src_wan}]" if src_wan else "")
        right = f"{dst_name}"
        if dst_wan and ltype != "servicelink":
            right += f" [{dst_wan}]"

        extras: List[str] = []
        if ltype == "servicelink":
            sep = L.get("sep_name")
            wan_name = L.get("wan_nw_name")
            if wan_name:
                extras.append(f"WAN={wan_name}")
            if sep:
                extras.append(f"SEP={sep}")
        if ltype and ltype.endswith("anynet"):
            v = L.get("vpnlinks")
            if isinstance(v, list):
                extras.append(f"vpnlinks={len(v)}")
        if "admin_up" in L:
            extras.append(f"admin_up={L.get('admin_up')}")
        if L.get("cost") is not None:
            extras.append(f"cost={L.get('cost')}")
        if subtype:
            extras.append(f"sub={subtype}")
        if wide:
            extras.insert(0, f"path_id={L.get('path_id')}")
            extras.append(f"src_id={src_id}")
            extras.append(f"dst_id={dst_id}")

        extras_str = f" ({', '.join(extras)})" if extras else ""
        print(f"  - {status:<4} | {ltype:<14} | {left}  -->  {right}{extras_str}")

        # ----- Detailed enrichment -----
        if details and token:
            # a) AnyNet vpnlinks
            if ltype and ltype.endswith("anynet"):
                vlist = L.get("vpnlinks") or []
                for vid in vlist:
                    st = get_vpnlink_status(token, str(vid)) or {}
                    op = st.get("operational_state") or st.get("oper_state") or "?"
                    ex = st.get("extended_state") or st.get("state") or ""
                    peer = (st.get("remote_endpoint") or {}).get("peer_ip") or st.get("peer_ip") or ""
                    last = _fmt_epoch_ms(st.get("last_state_change"))
                    ike = st.get("ike") or st.get("ike_algo") or ""
                    ipsec = st.get("ipsec") or st.get("ipsec_algo") or ""
                    algos = []
                    if ike: algos.append(f"IKE={ike}")
                    if ipsec: algos.append(f"IPsec={ipsec}")
                    algostr = f" [{', '.join(algos)}]" if algos else ""
                    print(f"      · vpnlink {vid}: oper={op} ext={ex} peer={peer} last_change={last}{algostr}")

            # b) Service Links (interface-level status with crypto/rekeys)
            if ltype == "servicelink":
                elem_if = L.get("elem_interface_id")
                elem_id = L.get("element_id")
                if elem_if and elem_id:
                    site_id = get_site_id_for_element(token, str(elem_id))
                    if site_id:
                        ist = get_interface_status(token, site_id, str(elem_id), str(elem_if)) or {}
                        sl = ist.get("service_link") or {}
                        op = ist.get("operational_state") or "?"
                        ex = ist.get("extended_state") or ""
                        peer = ist.get("remote_v4_addr") or ""
                        ike = sl.get("ike_algo") or ""
                        ipsec = sl.get("ipsec_algo") or ""
                        laddr = sl.get("local_tunnel_v4_addr") or ""
                        last_ike = _fmt_epoch_ms(sl.get("ike_last_rekeyed"))
                        next_ike = _fmt_epoch_ms(sl.get("ike_next_rekey"))
                        last_ipsec = _fmt_epoch_ms(sl.get("ipsec_last_rekeyed"))
                        next_ipsec = _fmt_epoch_ms(sl.get("ipsec_next_rekey"))
                        print(f"      · servicelink if:{elem_if} oper={op} ext={ex} local={laddr} peer={peer}")
                        if ike or ipsec:
                            print(f"        crypto: IKE={ike}  IPsec={ipsec}")
                        print(f"        rekeys: IKE last={last_ike} next={next_ike} | IPsec last={last_ipsec} next={next_ipsec}")


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Prisma SD-WAN Topology (with per-tunnel details)")
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
    parser.add_argument("--details", action="store_true",
                        help="Fetch per-tunnel details for AnyNet VPN links and Service Links.")
    args = parser.parse_args()

    # Validate env and auth
    _ = _must_env("TENANT_ID")
    token = get_token()
    prof = get_profile(token)  # mandatory call for prisma sd-wan api - do not remove
    tenant = prof.get("tsg_id") or prof.get("tenant_id") or prof.get("customer_id") or "unknown-tenant"
    user = prof.get("email") or prof.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # Topology first (fast)
    inc_sl = False if args.no_servicelinks else True if (args.servicelinks or not args.no_servicelinks) else True
    inc_stub = False if args.no_stub_links else True if (args.stub_links or not args.no_stub_links) else True

    topo = get_topology(
        token=token,
        site_id=args.topology_site,
        include_servicelinks=inc_sl,
        include_stub_links=inc_stub,
        topo_type=args.topology_type or "anynet",
    )
    print_topology(topo, wide=args.wide, on_demand_only=args.on_demand_only, details=args.details, token=token)


if __name__ == "__main__":
    main()
