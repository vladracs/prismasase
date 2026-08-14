#!/usr/bin/env python3
# ============================================================================
# DISCLAIMER
# ----------------------------------------------------------------------------
# I am currently employed by Palo Alto Networks; however, the scripts, examples,
# and documentation in this repository are provided solely in my personal
# capacity for educational purposes. They are not official, are not supported,
# and do not represent the views of Palo Alto Networks.
#
# NO WARRANTY / NO LIABILITY. The materials are provided AS IS without
# warranties of any kind. You assume all risks from use. I and my employer
# disclaim any liability for damages arising from use of this code.
#
# NO SUPPORT. Please do not contact Palo Alto Networks support regarding this
# repository. Issues and questions should be filed in GitHub on a best-effort
# basis only.
#
# COMPLIANCE. By using these materials, you agree to:
#   - adhere to all applicable contracts, licenses, and API terms (including
#     those of Palo Alto Networks and third parties);
#   - avoid exposing secrets/keys and confidential information;
#   - comply with export, privacy, and security laws/policies.
#
# TRADEMARKS. Palo Alto Networks(R), Prisma(R) SASE, and Prisma(R) SD-WAN are
# trademarks of Palo Alto Networks. Other names may be trademarks of their
# respective owners. No affiliation or endorsement is implied.
# ============================================================================
"""
Per-site WAN circuit + device usage report.

For every site (or one, via --site NAME) prints:
  * WAN circuits (public / private) with:
      - circuit name, link_bw_down / _up (Mbps), cost, underlying wannetwork
  * Devices (elements) at that site
  * Which WAN circuits each device's interfaces are bound to
    (join key = interface.site_wan_interface_ids)

Read-only. Uses prisma-sase SDK only.
"""
from __future__ import annotations
import argparse
import os
import sys
from collections import defaultdict
from typing import Any

import prisma_sase
from _readonly_guard import enforce_readonly


def login() -> prisma_sase.API:
    cid  = os.environ.get("PRISMA_CLIENT_ID")
    csec = os.environ.get("PRISMA_CLIENT_SECRET")
    tsg  = os.environ.get("PRISMA_TSG_ID")
    if not all([cid, csec, tsg]):
        print("ERROR: Missing PRISMA_CLIENT_ID / PRISMA_CLIENT_SECRET / PRISMA_TSG_ID")
        sys.exit(1)
    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com",
                          update_check=False)
    sdk.interactive.login_secret(cid, csec, tsg)
    # panw_region repair (SDK's mapping table is incomplete)
    if not sdk.panw_region:
        t = sdk.get.tenants()
        if t.cgx_status:
            sdk.panw_region = (t.cgx_content or {}).get("x_panw_region")
    enforce_readonly(sdk)
    print(f"--- TENANT [{tsg}] ({sdk.tenant_name}) | panw_region={sdk.panw_region!r} ---")
    return sdk


def _items(resp) -> list:
    if not resp.cgx_status:
        return []
    return (resp.cgx_content or {}).get("items") or []


def main():
    ap = argparse.ArgumentParser(description="Per-site WAN circuit + device usage report.")
    ap.add_argument("--site", help="Filter to a single site by exact name (case-insensitive).")
    ap.add_argument("--only-with-devices", action="store_true",
                    help="Skip sites that have no elements.")
    args = ap.parse_args()

    sdk = login()

    # --- fetch shared tables once ---
    sites       = _items(sdk.get.sites())
    elements    = _items(sdk.get.elements())
    wannetworks = _items(sdk.get.wannetworks())

    wn_by_id = {w["id"]: w for w in wannetworks}

    # element_id -> element  and  site_id -> [elements]
    els_by_site: dict[str, list] = defaultdict(list)
    for e in elements:
        sid = e.get("site_id")
        if sid:
            els_by_site[sid].append(e)

    # --- site filter ---
    if args.site:
        sites = [s for s in sites if (s.get("name") or "").lower() == args.site.lower()]
        if not sites:
            print(f"ERROR: no site named '{args.site}'")
            sys.exit(2)

    sites.sort(key=lambda s: (s.get("name") or "").lower())

    total_circuits = total_devices = 0

    for site in sites:
        site_id   = site["id"]
        site_name = site.get("name") or "(unnamed)"
        admin     = site.get("admin_state") or "?"

        # WAN circuits for this site
        circuits = _items(sdk.get.waninterfaces(site_id=site_id))
        elems    = els_by_site.get(site_id, [])

        if args.only_with_devices and not elems:
            continue

        print()
        print("=" * 78)
        print(f"SITE: {site_name}   ({admin})   id={site_id}")
        print("=" * 78)

        # --- WAN circuits ---
        if not circuits:
            print("  WAN circuits: (none)")
        else:
            pub = [c for c in circuits if c.get("type") == "publicwan"]
            prv = [c for c in circuits if c.get("type") == "privatewan"]
            print(f"  WAN circuits: {len(circuits)} total  ({len(pub)} public, {len(prv)} private)")
            # column headers
            fmt = "    {kind:<8} {name:<22} {net:<18} {dn:>10}  {up:>10}  {cost:>5}"
            print(fmt.format(kind="TYPE", name="NAME", net="WAN NETWORK",
                             dn="DOWN Mbps", up="UP Mbps", cost="COST"))
            print("    " + "-" * 74)
            for c in sorted(circuits, key=lambda x: (x.get("type") or "", (x.get("name") or "").lower())):
                kind = "public" if c.get("type") == "publicwan" else \
                       "private" if c.get("type") == "privatewan" else (c.get("type") or "?")
                net  = wn_by_id.get(c.get("network_id"), {}).get("name") or "-"
                dn   = c.get("link_bw_down")
                up   = c.get("link_bw_up")
                cost = c.get("cost")
                print(fmt.format(
                    kind=kind,
                    name=(c.get("name") or "(unnamed)")[:22],
                    net=net[:18],
                    dn=f"{dn:g}" if isinstance(dn, (int, float)) else "-",
                    up=f"{up:g}" if isinstance(up, (int, float)) else "-",
                    cost=str(cost) if cost is not None else "-",
                ))
            total_circuits += len(circuits)

        # --- Devices + their WAN bindings ---
        print()
        if not elems:
            print("  Devices: (none)")
            continue
        total_devices += len(elems)

        # circuit_id -> circuit name (for pretty output)
        circ_name = {c["id"]: (c.get("name") or c["id"]) for c in circuits}

        print(f"  Devices: {len(elems)}")
        for e in sorted(elems, key=lambda x: (x.get("name") or "").lower()):
            connected = "connected" if e.get("connected") else "offline"
            model     = e.get("model_name") or "-"
            print(f"    • {e.get('name')}  ({connected}, {model}, sw={e.get('software_version') or '-'})")

            # interfaces for this element at this site
            ifs = _items(sdk.get.interfaces(site_id=site_id, element_id=e["id"]))
            # only interfaces that are WAN-facing AND bound to a circuit
            bound = [
                i for i in ifs
                if i.get("used_for") in ("public", "private")
                and i.get("site_wan_interface_ids")
            ]
            if not bound:
                print(f"        (no interfaces bound to a WAN circuit)")
                continue
            for i in sorted(bound, key=lambda x: (x.get("name") or "")):
                ids  = i.get("site_wan_interface_ids") or []
                names = ", ".join(circ_name.get(cid, cid) for cid in ids)
                print(f"        - if {i.get('name'):<10}  used_for={i.get('used_for'):<8}  -> {names}")

    # --- footer ---
    print()
    print("-" * 78)
    print(f"Total: sites reported = {len(sites)}  |  circuits = {total_circuits}  |  devices = {total_devices}")


if __name__ == "__main__":
    main()
