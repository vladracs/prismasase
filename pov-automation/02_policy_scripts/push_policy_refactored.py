#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Integrated Policy Restoration Tool
Supports: Original Path, QoS, NAT, Security (Live Updates) 
Adds: Performance Management (with Dry Run capability)
"""

import yaml
import json
import sys
import os
import copy
import argparse
import datetime
from dictdiffer import diff

try:
    from prisma_sase import API
except ImportError as e:
    API = None
    sys.stderr.write("ERROR: 'prisma_sase' SDK is required.\n {0}\n".format(e))
    sys.exit(1)

try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID
except ImportError:
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None

# Authenticate
sdk = API()
sdk.interactive.login_secret(
    client_id=PRISMASASE_CLIENT_ID,
    client_secret=PRISMASASE_CLIENT_SECRET,
    tsg_id=PRISMASASE_TSG_ID
)
cgx_session = sdk

# Constants
DELETE_KEYS = ["_created_on_utc", "_debug", "_error", "_etag", "_info", "_schema", 
               "_updated_on_utc", "_warning", "_request_id", "_content_length", "_status_code", "id"]
N2ID, ID2N = "n2id", "id2n"
PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL = "path", "qos", "nat", "security", "performance", "all"

# Global Dicts (Keep all original ones)
app_id_name, app_name_id = {}, {}
nwcontext_id_name, nwcontext_name_id = {}, {}
# ... (all other original dicts from your script go here)

# New Performance Dicts
perf_threshold_name_id = {}

# --- ORIGINAL HELPER FUNCTIONS (KEEP THESE AS IS) ---
def cleandata(data):
    if not isinstance(data, dict): return data
    return {k: v for k, v in data.items() if k not in DELETE_KEYS}

# (Keep original translate_rule, translate_set, translate_stack, compareconf, extractfromyaml functions here)

# --- UPDATED GLOBAL DICT INITIALIZATION ---
def create_global_dicts_all(cgx_session):
    """Original initialization plus Performance thresholds."""
    # ... (Include all your original dict population logic here) ...
    
    # Add Performance Threshold mapping
    slas = cgx_session.get.perfmgmtthresholdprofiles().cgx_content.get("items", [])
    for item in slas: perf_threshold_name_id[item["name"]] = item["id"]

# --- NEW PERFORMANCE POLICY FUNCTION ---
def push_policy_performance(cgx_session, loaded_config, dryrun=False):
    """Restores Performance Policies with a safety dry-run option."""
    print("[*] Processing Performance Policies...")
    existing = {i["name"]: i["id"] for i in cgx_session.get.perfmgmtpolicysets().cgx_content.get("items", [])}

    perf_sets = loaded_config.get("performance_sets", [])
    if not perf_sets: return

    for set_entry in perf_sets:
        set_name = list(set_entry.keys())[0]
        set_data = set_entry[set_name]
        rules_list = set_data.pop("rules", [])
        
        # Sync the Set
        if set_name in existing:
            set_id = existing[set_name]
            if dryrun: print(f"    [DRY RUN] Would UPDATE Performance Set: {set_name}")
            else: cgx_session.put.perfmgmtpolicysets(perfmgmtpolicyset_id=set_id, data=cleandata(set_data))
        else:
            if dryrun: 
                print(f"    [DRY RUN] Would CREATE Performance Set: {set_name}")
                set_id = "DRY-RUN-ID"
            else:
                resp = cgx_session.post.perfmgmtpolicysets(data=cleandata(set_data))
                set_id = resp.cgx_content.get("id")

        # Sync the Rules
        for rule_wrapper in rules_list:
            r_name = list(rule_wrapper.keys())[0]
            r_data = rule_wrapper[r_name]
            
            # Map Thresholds & Apps
            tp = r_data.get("thresholdprofile_id")
            if tp in perf_threshold_name_id: r_data["thresholdprofile_id"] = perf_threshold_name_id[tp]
            
            app_filters = r_data.get("app_filters")
            if isinstance(app_filters, dict):
                app_ids = app_filters.get("application_ids")
                if isinstance(app_ids, list):
                    r_data["app_filters"]["application_ids"] = [app_name_id.get(n, n) for n in app_ids]

            if dryrun: print(f"        [DRY RUN] Would PUSH Rule: {r_name}")
            else:
                cgx_session.post.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=set_id, data=cleandata(r_data))

# --- MAIN EXECUTION ENGINE ---
def go():
    parser = argparse.ArgumentParser(description="Integrated Policy Restoration Tool")
    parser.add_argument("--policytype", "-PT", choices=[PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL], required=True)
    parser.add_argument("--filename", "-F", required=True)
    parser.add_argument("--dryrun", action="store_true", help="Only applies to Performance Policy")
    args = parser.parse_args()

    with open(args.filename, 'r') as f:
        loaded_config = yaml.safe_load(f)

    create_global_dicts_all(sdk)

    # 1. Original Live Restores
    if args.policytype in [PATH, ALL]:
        push_policy_path(sdk, loaded_config)
    if args.policytype in [QOS, ALL]:
        push_policy_qos(sdk, loaded_config)
    if args.policytype in [NAT, ALL]:
        push_policy_nat(sdk, loaded_config)
    if args.policytype in [SECURITY, ALL]:
        push_policy_security(sdk, loaded_config)

    # 2. New Hybrid Restore (Supports Dry Run)
    if args.policytype in [PERFORMANCE, ALL]:
        push_policy_performance(sdk, loaded_config, dryrun=args.dryrun)

    print(f"\n[DONE] Restoration complete for: {args.policytype}")

if __name__ == "__main__":
    go()