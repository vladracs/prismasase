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
Site Cellular Report.

Iterates over all sites and devices, checking for cellular modules, 
and reporting their status.
"""
from __future__ import annotations
import argparse
import sys
import csv
from typing import Any

import prisma_sase
from _readonly_guard import enforce_readonly

def login() -> prisma_sase.API:
    return sdk

def _items(resp) -> list:
    if not resp.cgx_status:
        return []
    return (resp.cgx_content or {}).get("items") or []

def extract_active_fw(firmware_list: list[dict[str, Any]]) -> str:
    """Parses the firmware array and returns the fw_version where 'active' is True."""
    if not isinstance(firmware_list, list):
        return "Unknown"
    for fw in firmware_list:
        if fw.get("active"):
            return fw.get("fw_version", "Unknown")
    return "Unknown"

def main():
    ap = argparse.ArgumentParser(description="Per-site Cellular device report.")
    ap.add_argument("--site", help="Filter to a single site by exact name (case-insensitive).")
    ap.add_argument("--csv", help="Output to CSV file instead of stdout", type=str)
    args = ap.parse_args()

    global sdk
    sdk = prisma_sase.API()
    sdk.interactive.login_interactive()
    
    # --- fetch shared tables once ---
    sites       = _items(sdk.get.sites())
    elements    = _items(sdk.get.elements())
    
    # site filter
    if args.site:
        sites = [s for s in sites if (s.get("name") or "").lower() == args.site.lower()]
        if not sites:
            print(f"ERROR: no site named '{args.site}'")
            sys.exit(2)
            
    sites_by_id = {s["id"]: s for s in sites}
    
    report_data = []

    print("Scanning elements for Cellular Modules...", file=sys.stderr)
    
    for e in elements:
        site_id = e.get("site_id")
        if not site_id or site_id not in sites_by_id:
            continue
            
        site_name = sites_by_id[site_id].get("name") or "(unnamed)"
        element_id = e.get("id")
        element_name = e.get("name") or "(unnamed)"
        
        # Check cellular modules
        cell_resp = sdk.rest_call(method="GET", uri=f"/sdwan/v2.1/api/elements/{element_id}/cellular_modules")
        modules = _items(cell_resp)
        
        for module in modules:
            module_id = module.get("id")
            
            # Fetch detailed status
            status_resp = sdk.rest_call(method="GET", uri=f"/sdwan/v2.1/api/elements/{element_id}/cellular_modules/{module_id}/status")
            
            if status_resp.cgx_status:
                status = status_resp.cgx_content or {}
                net_state = status.get("network_state") or {}
                active_fw = extract_active_fw(status.get("firmware") or [])
                
                report_data.append({
                    "Site": site_name,
                    "Element": element_name,
                    "Model": status.get("model_name", "-"),
                    "Manufacturer": status.get("manufacturer", "-"),
                    "IMEI": status.get("imei", "-"),
                    "Serial": status.get("serial_number", "-"),
                    "State": status.get("modem_state", "-"),
                    "Carrier": status.get("carrier", "-"),
                    "Signal": status.get("signal_strength_indicator", "-"),
                    "Network Reg": status.get("network_registration_state", "-"),
                    "Freq Band": net_state.get("frequency_band", "-"),
                    "FW Version": active_fw
                })
                
    if not report_data:
        print("No cellular modules found.", file=sys.stderr)
        return

    if args.csv:
        with open(args.csv, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=report_data[0].keys())
            writer.writeheader()
            writer.writerows(report_data)
        print(f"Report saved to {args.csv}", file=sys.stderr)
    else:
        # Print to stdout
        fmt = "{site:<20} {element:<20} {state:<10} {signal:<10} {carrier:<15} {fw:<15}"
        print(fmt.format(site="SITE", element="ELEMENT", state="STATE", signal="SIGNAL", carrier="CARRIER", fw="FW VERSION"))
        print("-" * 95)
        for row in report_data:
            print(fmt.format(
                site=row["Site"][:19],
                element=row["Element"][:19],
                state=row["State"],
                signal=row["Signal"],
                carrier=row["Carrier"],
                fw=row["FW Version"]
            ))

if __name__ == "__main__":
    main()
