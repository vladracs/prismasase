#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Vladimir F de Sousa - vfrancad@gmail.com
# Disclaimer: Personal project by a Palo Alto Networks employee.
# Not an official PANW product. No support/warranty. See DISCLAIMER.md.
# Prisma SD-WAN Topology by Site Name (prints AnyNet vpnlink cipher/keepalive/flags correctly)
#
# Env:
#   export CLIENT_ID="..."
#   export CLIENT_SECRET="..."
#   export TENANT_ID="..."   # (aka tsg_id)
#   python3 scm_sdwan_topology-detail_byname_plus2.py --site "BERLIN" --details --wide
#
# Arguments:
#   --site "<SITE_NAME>"   Mandatory: name of the site to query (case-sensitive match)
#   --details              Enriches output with per-VPN tunnel details (cipher, keepalives, flags)
#   --wide                 Prints extra columns/fields for links (WAN, subtype, cost, etc.)
#   --basenet              Fetch basenet topology details for all discovered path_ids
#   --graph                Render the topology graph (<SITE_NAME>-topology.png, needs Graphviz installed)
#   --graph-format <fmt>   Graph format (default: png). Options: png, svg, pdf...
#   --graph-out <file>     Output filename prefix for the graph (default: <SITE_NAME>-topology)
#
# Examples:
#   # Show BERLIN topology with tunnel details
#   python3 scm_sdwan_topology-detail_byname_plus2.py --site "BERLIN" --details
#
#   # Render BERLIN topology to SVG
#   python3 scm_sdwan_topology-detail_byname_plus2.py --site "BERLIN" --graph --graph-format svg
#
# Notes:
#   - Requires 'graphviz' Python package AND system binaries (brew install graphviz / apt-get install graphviz).
#   - Site name must exactly match what the API reports (use scm_get_sites_elements_v1.py to list).
#   - VPN link info is enriched by chaining multiple APIs:
#       1. /sdwan/v2.2|v2.1|v2.0/api/vpnlinks/{id}/status
#       2. /sdwan/v2.0/api/vpnlinks/{id}/state
#       3. /sdwan/v2.1|v2.0/api/vpnlinks/{id}
#   - Service Links also show crypto/rekey timers from interface status.

import os
import re
import json
import argparse
import shutil
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone

import requests

# Optional Graphviz
HAS_GRAPHVIZ = False
try:
    from graphviz import Digraph  # type: ignore
    HAS_GRAPHVIZ = True
except Exception:
    HAS_GRAPHVIZ = False

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

# Inventory
SITES_EP = "/sdwan/v4.11/api/sites"
ELEMENTS_TENANT_EP = "/sdwan/v3.1/api/elements"

# Topology
TOPOLOGY_EP = "/sdwan/v3.6/api/topology"

# VPNLink endpoints
VPNLINK_STATUS_EP_TMPLS = [
    "/sdwan/v2.2/api/vpnlinks/{vpn_link_id}/status",
    "/sdwan/v2.1/api/vpnlinks/{vpn_link_id}/status",
    "/sdwan/v2.0/api/vpnlinks/{vpn_link_id}/status",
]
VPNLINK_STATE_EP_TMPL = "/sdwan/v2.0/api/vpnlinks/{vpn_link_id}/state"
VPNLINK_INFO_EP_TMPLS = [
    "/sdwan/v2.1/api/vpnlinks/{vpn_link_id}",
    "/sdwan/v2.0/api/vpnlinks/{vpn_link_id}",
]

# Cache
_SITES_CACHE: Optional[List[Dict[str, Any]]] = None
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


# ---------- Inventory ----------
def normalize_id_name(o: Dict[str, Any]) -> None:
    if "id" not in o:
        if "site_id" in o:
            o["id"] = o["site_id"]
        elif "element_id" in o:
            o["id"] = o["element_id"]
    if "name" not in o and "display_name" in o:
        o["name"] = o["display_name"]

def get_all_sites(token: str) -> List[Dict[str, Any]]:
    global _SITES_CACHE
    if _SITES_CACHE is None:
        data = api_get(SITES_EP, token)
        if isinstance(data, dict) and isinstance(data.get("items"), list):
            _SITES_CACHE = data["items"]
        elif isinstance(data, list):
            _SITES_CACHE = data
        else:
            _SITES_CACHE = []
        for s in _SITES_CACHE:
            normalize_id_name(s)
    return _SITES_CACHE

def site_name_to_id(token: str, name: str) -> Optional[str]:
    name_norm = name.strip().lower()
    for s in get_all_sites(token):
        sname = (s.get("name") or "").strip().lower()
        if sname == name_norm:
            return str(s.get("id"))
    for s in get_all_sites(token):
        sname = (s.get("name") or "").strip().lower()
        if sname.startswith(name_norm):
            return str(s.get("id"))
    return None

def site_id_to_name(token: str, site_id: str) -> Optional[str]:
    for s in get_all_sites(token):
        if str(s.get("id")) == str(site_id):
            return s.get("name")
    return None

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
        for e in _ELEMENTS_CACHE:
            normalize_id_name(e)
    return _ELEMENTS_CACHE


# ---------- Profile (mandatory) ----------
def get_profile(token: str) -> Dict[str, Any]:
    prof = api_get("/sdwan/v2.1/api/profile", token)
    print("profile api status: 200")
    return prof


# ---------- Topology ----------
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


# ---------- VPNLink helpers ----------
def get_vpnlink_status(token: str, vpn_link_id: str) -> Dict[str, Any]:
    last_err = None
    for tmpl in VPNLINK_STATUS_EP_TMPLS:
        ep = tmpl.format(vpn_link_id=str(vpn_link_id))
        try:
            data = api_get(ep, token)
            if isinstance(data, dict) and data:
                out = dict(data)
                peer = (out.get("remote_endpoint") or {}).get("peer_ip") or out.get("peer_ip")
                if peer:
                    out["peer_ip"] = peer
                if "operational_state" not in out and "oper_state" in out:
                    out["operational_state"] = out["oper_state"]
                if "extended_state" not in out and "state" in out:
                    out["extended_state"] = out["state"]
                return out
        except Exception as e:
            last_err = e
            continue
    return {}

def get_vpnlink_state(token: str, vpn_link_id: str) -> Dict[str, Any]:
    ep = VPNLINK_STATE_EP_TMPL.format(vpn_link_id=str(vpn_link_id))
    try:
        data = api_get(ep, token)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def get_vpnlink_info(token: str, vpn_link_id: str) -> Dict[str, Any]:
    for tmpl in VPNLINK_INFO_EP_TMPLS:
        ep = tmpl.format(vpn_link_id=str(vpn_link_id))
        try:
            data = api_get(ep, token)
            if isinstance(data, dict) and data.get("id"):
                return data
        except Exception:
            continue
    return {}

def merge_vpnlink_meta(st: Dict[str, Any], state: Dict[str, Any], info: Dict[str, Any]) -> Tuple[str,str,str,Any,Any,Any,Any,List[str],str,str]:
    """Return (common, ep1c, ep2c, e1i, e1f, e2i, e2f, flags[], ep1_name, ep2_name)
    Priority: STATUS -> STATE -> INFO
    """
    def pick(*keys):
        for d in (st, state, info):
            for k in keys:
                if k in d and d.get(k) is not None:
                    return d.get(k)
        return None

    common = pick("common_cipher")
    ep1c   = pick("ep1_cipher")
    ep2c   = pick("ep2_cipher")
    e1i    = pick("ep1_keep_alive_interval")
    e1f    = pick("ep1_keep_alive_failure_count")
    e2i    = pick("ep2_keep_alive_interval")
    e2f    = pick("ep2_keep_alive_failure_count")

    flags_order = []
    for k in ("active","usable","link_up"):
        v = pick(k)
        if isinstance(v, bool):
            flags_order.append(f"{k}={'yes' if v else 'no'}")

    ep1_id = pick("ep1_site_id") or ""
    ep2_id = pick("ep2_site_id") or ""
    return (
        common or "n/a",
        ep1c or "n/a",
        ep2c or "n/a",
        e1i if e1i is not None else "n/a",
        e1f if e1f is not None else "n/a",
        e2i if e2i is not None else "n/a",
        e2f if e2f is not None else "n/a",
        flags_order,
        str(ep1_id),
        str(ep2_id),
    )


# ---------- Utilities ----------
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

def collect_anynet_path_ids(topo: Dict[str, Any]) -> List[str]:
    ids: List[str] = []
    for L in topo.get("links", []) or []:
        if L.get("type") == "public-anynet" and L.get("path_id"):
            ids.append(str(L["path_id"]))
    return ids

def sanitize_filename(name: str) -> str:
    s = re.sub(r'[^A-Za-z0-9\-]+', '_', name.strip())
    s = re.sub(r'_+', '_', s).strip('_')
    return s or "site"


# ---------- Printers ----------
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

        # ----- Detailed enrichment for AnyNet & ServiceLinks -----
        if details and token:
            # a) AnyNet vpnlinks
            if ltype and ltype.endswith("anynet"):
                vlist = L.get("vpnlinks") or []
                for vid in vlist:
                    st = get_vpnlink_status(token, str(vid)) or {}
                    op = st.get("operational_state") or "?"
                    ex = st.get("extended_state") or ""
                    peer = st.get("peer_ip") or ""
                    last = _fmt_epoch_ms(st.get("last_state_change"))
                    ike = st.get("ike") or st.get("ike_algo") or ""
                    ipsec = st.get("ipsec") or st.get("ipsec_algo") or ""
                    algos = []
                    if ike: algos.append(f"IKE={ike}")
                    if ipsec: algos.append(f"IPsec={ipsec}")
                    algostr = f" [{', '.join(algos)}]" if algos else ""
                    print(f"      · vpnlink {vid}: oper={op} ext={ex} peer={peer} last_change={last}{algostr}")

                    state = get_vpnlink_state(token, str(vid)) or {}
                    info = get_vpnlink_info(token, str(vid)) or {}
                    common, ep1c, ep2c, e1i, e1f, e2i, e2f, flags, ep1_id, ep2_id = merge_vpnlink_meta(st, state, info)
                    ep1n = site_id_to_name(token, ep1_id) if ep1_id else ""
                    ep2n = site_id_to_name(token, ep2_id) if ep2_id else ""
                    ns = f" (ep1={ep1n}, ep2={ep2n})" if (ep1n or ep2n) else ""
                    print(
                        f"         meta:{ns} common_cipher={common} ep1={ep1c} ep2={ep2c} "
                        f"keepalive(ep1)={e1i}/{e1f} keepalive(ep2)={e2i}/{e2f} flags=[{', '.join(flags)}]"
                    )

            # b) Service Links
            if ltype == "servicelink":
                elem_if = L.get("elem_interface_id")
                elem_id = L.get("element_id")
                if elem_if and elem_id:
                    sid = None
                    for e in _get_all_elements_cached(token):
                        if str(e.get("id") or e.get("element_id")) == str(elem_id):
                            sid = str(e.get("site_id") or e.get("site") or "")
                            break
                    if sid:
                        ist = api_get(f"/sdwan/v3.9/api/sites/{sid}/elements/{elem_id}/interfaces/{elem_if}/status", token) or {}
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


def print_basenet(topo: Dict[str, Any]) -> None:
    nodes = {str(n.get("id")): n for n in topo.get("nodes", []) or []}
    links = topo.get("links", []) or []
    print("\n########## Basenet detail ##########")
    print(f"Nodes: {len(nodes)} | Links: {len(links)}\n")
    if not links:
        print("(none)\n")
        return
    for L in links:
        pid = L.get("path_id") or ""
        ltype = L.get("type") or ""
        status = L.get("status") or ""
        src = str(L.get("source_node_id"))
        dst = str(L.get("target_node_id"))
        sname = nodes.get(src, {}).get("name") or src
        dname = nodes.get(dst, {}).get("name") or dst
        print(f"  - path_id={pid} | {ltype:<12} | {sname} --> {dname} | status={status}")
    print("")


# ---------- Graph ----------
def render_topology_graph(topo: dict, filename_base: str, fmt: str = "png") -> Optional[str]:
    if not HAS_GRAPHVIZ:
        print("WARN: Python 'graphviz' package not installed. Skipping --graph output.")
        return None
    if not shutil.which("dot"):
        print("WARN: Graphviz 'dot' executable not found in PATH. Skipping --graph output.")
        return None

    g = Digraph("sdwan_topology", format=fmt)
    g.attr("graph", rankdir="LR")

    for n in topo.get("nodes", []):
        nid = str(n.get("id"))
        label = n.get("name") or nid
        ntype = n.get("type")
        is_sase = bool(n.get("is_sase"))
        shape = "box" if ntype == "SITE" else "ellipse"
        fill = "lightblue" if is_sase else "lightgrey"
        g.node(nid, label=label, shape=shape, style="filled", fillcolor=fill)

    for l in topo.get("links", []):
        src = str(l.get("source_node_id"))
        dst = str(l.get("target_node_id"))
        status = l.get("status", "")
        ltype = l.get("type", "")
        color = "green" if status == "up" else "red"
        label = f"{ltype}\\n{status}"
        g.edge(src, dst, label=label, color=color)

    try:
        out = g.render(filename_base, view=False)
        print(f"Graph written to: {out}")
        return out
    except Exception as e:
        print(f"WARN: Failed to render graph with Graphviz: {e}")
        return None


# ---------- main ----------
def main():
    parser = argparse.ArgumentParser(description="Prisma SD-WAN Topology (site-name input)")
    parser.add_argument("--site", required=True, help="Site NAME (exact or prefix; case-insensitive)")
    parser.add_argument("--details", action="store_true",
                        help="Fetch per-tunnel details for AnyNet VPN links and Service Links.")
    parser.add_argument("--wide", action="store_true",
                        help="Wide topology output (include IDs and path_id).")
    parser.add_argument("--on-demand-only", action="store_true",
                        help="Show only on-demand anynet links in topology output.")
    parser.add_argument("--basenet", action="store_true",
                        help="Also fetch basenet topology for the anynet path_ids discovered for this site.")
    parser.add_argument("--graph", action="store_true",
                        help="Render a Graphviz diagram; writes <site_name>-topology.<fmt> unless overridden.")
    parser.add_argument("--graph-out", type=str, default=None,
                        help="Optional base filename for the graph (without extension). If not set, uses <site_name>-topology.")
    parser.add_argument("--graph-format", type=str, default="png",
                        help="Graph output format (png, svg, pdf...). Default: png.")
    args = parser.parse_args()

    # Validate env and auth
    _ = _must_env("TENANT_ID")
    token = get_token()
    prof = get_profile(token)  # mandatory call
    tenant = prof.get("tsg_id") or prof.get("tenant_id") or prof.get("customer_id") or "unknown-tenant"
    user = prof.get("email") or prof.get("user") or "unknown-user"
    print(f"Profile: {user} @ {tenant}")

    # Resolve site name -> id
    site_id = site_name_to_id(token, args.site)
    if not site_id:
        names = sorted({s.get("name","") for s in get_all_sites(token) if s.get("name")})
        print(f"ERROR: Could not find site named '{args.site}'. Available examples: {', '.join(names[:10])} ...")
        return

    # Fetch AnyNet topology
    topo = get_topology(
        token=token,
        site_id=site_id,
        include_servicelinks=True,
        include_stub_links=True,
        topo_type="anynet",
    )

    # Print AnyNet (+details)
    print_topology(topo, wide=args.wide, on_demand_only=args.on_demand_only, details=args.details, token=token)

    # Optional Basenet drilldown
    if args.basenet:
        pids = collect_anynet_path_ids(topo)
        if not pids:
            print("Note: No public-anynet path_ids found to query basenet.")
        else:
            btopo = api_post(TOPOLOGY_EP, token, {"type":"basenet","links":pids,"links_only":True}) or {}
            btopo.setdefault("nodes", []); btopo.setdefault("links", [])
            print_basenet(btopo)

    # Optional Graph output
    if args.graph:
        site_name = site_id_to_name(token, site_id) or args.site
        base = args.graph_out or f"{sanitize_filename(site_name)}-topology"
        render_topology_graph(topo, filename_base=base, fmt=args.graph_format)


if __name__ == "__main__":
    main()
