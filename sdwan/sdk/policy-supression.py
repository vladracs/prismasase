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
Create an event suppression policy and tie it to a specific ION (element).

Three steps, all via the prisma-sase SDK:
  1. POST eventcorrelationpolicysets       -> create the policy set
  2. POST eventcorrelationpolicyrules      -> create the suppression rule
                                              under that set, scoped to the
                                              target element via:
                                                resource_type = "element"
                                                resource_ids  = [<element_id>]
  3. PUT  eventcorrelationpolicysets       -> activate the set
                                              (active_policyset = True)
                                              GET-modify-PUT with _etag.

If the set already exists, it is reused (idempotent on the name).
The element is resolved by name -> id via sdk.get.elements().

WRITE-CAPABLE SCRIPT. By design this script does NOT import the
_readonly_guard module. It will create / update configuration. Always
review the intended-changes summary before confirming.

Usage:
  export PRISMA_CLIENT_ID=...
  export PRISMA_CLIENT_SECRET=...
  export PRISMA_TSG_ID=...

  python3 create_event_suppression.py \
      --element BR1-ION-1 \
      --policy-set "Suppress-CarrierFlap" \
      --rule "suppress-carrier-degraded" \
      --event-codes CARRIER_PERFORMANCE_DEGRADED \
      [--dampening 5] \
      [--description "..."] \
      [--force-yes]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional

import prisma_sase


# ---------------------------------------------------------------------------
# Auth + region helper (same pattern used across read-only scripts).
# ---------------------------------------------------------------------------
def login() -> prisma_sase.API:
    cid  = os.environ.get("PRISMA_CLIENT_ID")
    csec = os.environ.get("PRISMA_CLIENT_SECRET")
    tsg  = os.environ.get("PRISMA_TSG_ID")
    if not all([cid, csec, tsg]):
        print("ERROR: Missing PRISMA_CLIENT_ID / PRISMA_CLIENT_SECRET / PRISMA_TSG_ID env vars.")
        sys.exit(1)

    sdk = prisma_sase.API(controller="https://api.sase.paloaltonetworks.com")
    sdk.interactive.login_secret(cid, csec, tsg)

    # Repair sdk.panw_region: the SDK's built-in telemetry_panw_mapping is
    # incomplete (e.g. lacks 'de'), so panw_region can come back as None.
    # The correct value is published on the tenant object as x_panw_region.
    if not sdk.panw_region:
        t = sdk.get.tenants()
        if t.cgx_status:
            sdk.panw_region = (t.cgx_content or {}).get("x_panw_region")

    print(f"--- CAUTION: RUNNING AGAINST PRISMA SASE TENANT [{tsg}] "
          f"({sdk.tenant_name}) | panw_region={sdk.panw_region!r} ---")
    return sdk


# ---------------------------------------------------------------------------
# Lookups
# ---------------------------------------------------------------------------
def find_element_id(sdk: prisma_sase.API, name: str) -> Optional[dict]:
    resp = sdk.get.elements()
    if not resp.cgx_status:
        print("ERROR: failed to fetch elements:")
        print(json.dumps(resp.cgx_content, indent=2))
        return None
    items = resp.cgx_content.get("items", []) or []
    exact = [e for e in items if (e.get("name") or "").lower() == name.lower()]
    if exact:
        return exact[0]
    partial = [e for e in items if name.lower() in (e.get("name") or "").lower()]
    if len(partial) == 1:
        print(f"NOTE: using partial match -> {partial[0].get('name')}")
        return partial[0]
    if len(partial) > 1:
        names = ", ".join(e.get("name") for e in partial)
        print(f"ERROR: ambiguous element name '{name}'. Matches: {names}")
        return None
    print(f"ERROR: no element named '{name}' found.")
    return None


def find_policy_set(sdk: prisma_sase.API, name: str) -> Optional[dict]:
    resp = sdk.get.eventcorrelationpolicysets()
    if not resp.cgx_status:
        print("ERROR: failed to fetch policy sets:")
        print(json.dumps(resp.cgx_content, indent=2))
        return None
    for item in (resp.cgx_content.get("items") or []):
        if item.get("name") == name:
            return item
    return None


def find_rule(sdk: prisma_sase.API, policyset_id: str, name: str) -> Optional[dict]:
    resp = sdk.get.eventcorrelationpolicyrules(policyset_id)
    if not resp.cgx_status:
        return None
    for item in (resp.cgx_content.get("items") or []):
        if item.get("name") == name:
            return item
    return None


# ---------------------------------------------------------------------------
# Step builders
# ---------------------------------------------------------------------------
def step1_policyset(sdk: prisma_sase.API, name: str, description: str) -> Optional[str]:
    existing = find_policy_set(sdk, name)
    if existing:
        print(f"[1/3] Policy set '{name}' already exists -> {existing.get('id')} (reusing)")
        return existing.get("id")

    # NOTE: the controller requires ALL schema keys to be present in the body,
    # even when null. Sending a minimal payload returns 400 INVALID_JSON_INPUT.
    payload = {
        "name": name,
        "description": description,
        "tags": None,
        "severity_priority_mapping": [
            {"severity": "critical", "priority": "p2"},
            {"severity": "major",    "priority": "p3"},
            {"severity": "minor",    "priority": "p4"},
        ],
        "policyrule_order": None,
        "active_policyset": False,   # will activate in step 3
        "clone_from": None,
    }
    print(f"[1/3] Creating event correlation policy set '{name}'...")
    resp = sdk.post.eventcorrelationpolicysets(data=payload)
    if not resp.cgx_status:
        print("ERROR creating policy set:")
        print(json.dumps(resp.cgx_content, indent=2))
        return None
    pid = resp.cgx_content.get("id")
    print(f"      created -> {pid}")
    return pid


def step2_rule(sdk: prisma_sase.API, policyset_id: str, rule_name: str,
               element_id: str, event_codes: list[str],
               dampening: int, description: str) -> Optional[str]:
    existing = find_rule(sdk, policyset_id, rule_name)
    if existing:
        print(f"[2/3] Rule '{rule_name}' already exists under set -> {existing.get('id')} (skipping create)")
        return existing.get("id")

    # NOTE: send all schema keys explicitly (null where unused); the
    # controller rejects partial payloads with 400 INVALID_JSON_INPUT.
    payload = {
        "name": rule_name,
        "description": description,
        "tags": None,
        "dampening_duration": dampening,
        "start_time": None,
        "end_time": None,
        "escalation_rules": None,
        "event_codes": event_codes,
        "suppress": "yes",
        "enabled": True,
        # priority is intentionally omitted: when 'suppress'=='yes' the
        # controller rejects priority=null with EVENT_POLICY_INVALID_PRIORITY.
        # --- the ION binding ---
        "resource_type": "element",
        "resource_ids": [element_id],
        "sub_resource_type": None,
    }
    print(f"[2/3] Creating suppression rule '{rule_name}' bound to element_id={element_id}...")
    resp = sdk.post.eventcorrelationpolicyrules(policyset_id, data=payload)
    if not resp.cgx_status:
        print("ERROR creating rule:")
        print(json.dumps(resp.cgx_content, indent=2))
        return None
    rid = resp.cgx_content.get("id")
    print(f"      created -> {rid}")
    return rid


def step3_activate(sdk: prisma_sase.API, policyset_id: str) -> bool:
    # GET-modify-PUT with _etag
    cur = sdk.get.eventcorrelationpolicysets(policyset_id)
    if not cur.cgx_status:
        print("ERROR fetching policy set for activation:")
        print(json.dumps(cur.cgx_content, indent=2))
        return False
    body = cur.cgx_content
    if body.get("active_policyset") is True:
        print(f"[3/3] Policy set already active -> nothing to do.")
        return True

    body["active_policyset"] = True
    print(f"[3/3] Activating policy set (PUT with _etag={body.get('_etag')})...")
    resp = sdk.put.eventcorrelationpolicysets(policyset_id, data=body)
    if not resp.cgx_status:
        print("ERROR activating policy set:")
        print(json.dumps(resp.cgx_content, indent=2))
        return False
    print("      activated.")
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(
        description="Create a Prisma SD-WAN event suppression policy bound to an ION.",
    )
    ap.add_argument("--element",      required=True,
                    help="ION (element) name. Exact match preferred; unique partial OK.")
    ap.add_argument("--policy-set",   required=True,
                    help="Event Correlation Policy Set name (created if missing).")
    ap.add_argument("--rule",         required=True,
                    help="Suppression rule name (created if missing).")
    ap.add_argument("--event-codes",  required=True, nargs="+",
                    help="One or more event codes to suppress, e.g. CARRIER_PERFORMANCE_DEGRADED.")
    ap.add_argument("--dampening",    type=int, default=5,
                    help="Dampening duration in minutes (default 5).")
    ap.add_argument("--description",  default="Suppression rule created via prisma-sase SDK.",
                    help="Description applied to both policy set and rule.")
    ap.add_argument("--force-yes",    action="store_true",
                    help="Skip the interactive confirmation prompt.")
    args = ap.parse_args()

    sdk = login()

    # Resolve element name -> id
    elem = find_element_id(sdk, args.element)
    if not elem:
        sys.exit(2)
    element_id = elem["id"]
    site_id    = elem.get("site_id")

    # Print the intended-changes summary (mandatory per skill safety rules)
    print()
    print("=" * 72)
    print("INTENDED CHANGES")
    print("-" * 72)
    print(f"  Tenant            : {sdk.tenant_name} ({os.environ['PRISMA_TSG_ID']})")
    print(f"  Target element    : {elem.get('name')}  id={element_id}  site_id={site_id}")
    print(f"  Policy set name   : {args.policy_set}   (created if missing)")
    print(f"  Suppression rule  : {args.rule}         (created if missing)")
    print(f"  Event codes       : {args.event_codes}")
    print(f"  Dampening (min)   : {args.dampening}")
    print(f"  After create      : policy set will be ACTIVATED (active_policyset=True)")
    print("=" * 72)
    print()

    if not args.force_yes:
        ans = input("Proceed with these changes? [type 'yes' to continue]: ").strip().lower()
        if ans != "yes":
            print("Aborted by user.")
            sys.exit(0)

    # Step 1
    policyset_id = step1_policyset(sdk, args.policy_set, args.description)
    if not policyset_id:
        sys.exit(3)

    # Step 2 -- the ION bind happens here via resource_type/resource_ids
    rule_id = step2_rule(
        sdk,
        policyset_id=policyset_id,
        rule_name=args.rule,
        element_id=element_id,
        event_codes=args.event_codes,
        dampening=args.dampening,
        description=args.description,
    )
    if not rule_id:
        sys.exit(4)

    # Step 3
    if not step3_activate(sdk, policyset_id):
        sys.exit(5)

    print()
    print("SUCCESS")
    print(f"  policy_set_id = {policyset_id}")
    print(f"  rule_id       = {rule_id}")
    print(f"  bound to      = {elem.get('name')}  ({element_id})")


if __name__ == "__main__":
    main()
