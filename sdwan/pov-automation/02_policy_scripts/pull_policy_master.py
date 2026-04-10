import yaml
import json
import sys
import os
import argparse
import datetime
import prisma_sase

# ---------- Constants ----------
SCRIPT_NAME = "Policy Tool: Master Pull (Individual Exports)"
__version__ = "1.4.0"

DELETE_KEYS = ["_created_on_utc", "_debug", "_error", "_etag",
               "_info", "_schema", "_updated_on_utc", "_warning",
               "_request_id", "_content_length", "_status_code", "id"]

PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL = "path", "qos", "nat", "security", "performance", "all"

# Global Mapping Dicts
app_id_name = {}
perf_threshold_id_name = {}
perf_set_id_name = {}
nw_set_id_name = {}
qos_set_id_name = {}
nat_set_id_name = {}
sec_set_id_name = {}

def cleandata(data):
    if not isinstance(data, dict): return data
    return {k: v for k, v in data.items() if k not in DELETE_KEYS}

def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')

yaml.add_representer(type(None), represent_none, Dumper=yaml.SafeDumper)

def create_global_dicts_all(sdk):
    print("[*] Building translation dictionaries...")
    apps = sdk.get.appdefs().cgx_content.get("items", [])
    for item in apps: app_id_name[item["id"]] = item["display_name"]
    
    for item in sdk.get.networkpolicysets().cgx_content.get("items", []): nw_set_id_name[item["id"]] = item["name"]
    for item in sdk.get.prioritypolicysets().cgx_content.get("items", []): qos_set_id_name[item["id"]] = item["name"]
    for item in sdk.get.natpolicysets().cgx_content.get("items", []): nat_set_id_name[item["id"]] = item["name"]
    for item in sdk.get.ngfwsecuritypolicysets().cgx_content.get("items", []): sec_set_id_name[item["id"]] = item["name"]
    for item in sdk.get.perfmgmtpolicysets().cgx_content.get("items", []): perf_set_id_name[item["id"]] = item["name"]
    for item in sdk.get.perfmgmtthresholdprofiles().cgx_content.get("items", []): perf_threshold_id_name[item["id"]] = item["name"]

def translate_rule(rule, rule_type):
    if rule_type == PERFORMANCE:
        tp_id = rule.get("thresholdprofile_id")
        if tp_id in perf_threshold_id_name:
            rule["thresholdprofile_id"] = perf_threshold_id_name[tp_id]
    
    apps = rule.get("app_def_ids")
    if apps:
        rule["app_def_ids"] = [app_id_name.get(aid, aid) for aid in apps]
    return rule

def pull_generic_policy(sdk, section_key, stack_func, set_func, rule_func, set_map, rule_type):
    print(f"[*] Extracting {rule_type.upper()} Data...")
    stack_list, set_list = [], []
    
    # 1. Process Stacks (Remain as is)
    stacks = stack_func().cgx_content.get("items", [])
    for s in stacks:
        clean = cleandata(s)
        if clean.get("policyset_ids"):
            clean["policyset_ids"] = [set_map.get(sid, sid) for sid in clean["policyset_ids"]]
        stack_list.append({s["name"]: clean})

    # 2. Process Sets & Rules (FIXED FOR HEAVY SCRIPT)
    sets = set_func().cgx_content.get("items", [])
    for pset in sets:
        rule_list = [] # MUST be a list of dictionaries
        res = rule_func(pset["id"])
        items = res.cgx_content.get("items", []) if hasattr(res, 'cgx_content') else []

        for r in items:
            # THIS IS THE KEY CHANGE: 
            # Original script requires: - {"Rule Name": {config_data}}
            rule_entry = {r["name"]: translate_rule(cleandata(r), rule_type)}
            rule_list.append(rule_entry)
        
        clean_set = cleandata(pset)
        
        # Mapping to the exact internal keys the original script looks for
        rule_keys = {
            PATH: "networkpolicyrules",
            QOS: "prioritypolicyrules",
            NAT: "natpolicyrules",
            SECURITY: "ngfwsecuritypolicyrules",
            PERFORMANCE: "perfmgmtpolicyrules"
        }
        
        clean_set[rule_keys[rule_type]] = rule_list
        set_list.append({pset["name"]: clean_set})

    output_key_map = {
        "networkpolicy": ("networkpolicysetstacks", "networkpolicysets"),
        "priority": ("prioritypolicysetstacks", "prioritypolicysets"),
        "nat": ("natpolicysetstacks", "natpolicysets"),
        "ngfwsecurity": ("ngfwsecuritypolicysetstacks", "ngfwsecuritypolicysets"),
        "perfmgmt": ("perfmgmtpolicysetstacks", "perfmgmtpolicysets")
    }
    
    stack_key, set_key = output_key_map[section_key]
    return {stack_key: stack_list, set_key: set_list}
def main():
    parser = argparse.ArgumentParser(description=SCRIPT_NAME)
    parser.add_argument("-PT", "--policytype", default="all", choices=[PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL])
    args = parser.parse_args()

    # Load Auth from local settings file or environment
    try:
        from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID
    except ImportError:
        PRISMASASE_CLIENT_ID = os.environ.get("PRISMASASE_CLIENT_ID")
        PRISMASASE_CLIENT_SECRET = os.environ.get("PRISMASASE_CLIENT_SECRET")
        PRISMASASE_TSG_ID = os.environ.get("PRISMASASE_TSG_ID")

    sdk = prisma_sase.API(update_check=False)
    sdk.interactive.login_secret(PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID)
    
    create_global_dicts_all(sdk)

    # PT_MAP translates our short names to (API prefix, StacksFunc, SetsFunc, RulesFunc, NameMap, Type)
    pt_map = {
        PATH:     ("networkpolicy", sdk.get.networkpolicysetstacks, sdk.get.networkpolicysets, lambda sid: sdk.get.networkpolicyrules(networkpolicyset_id=sid), nw_set_id_name),
        QOS:      ("priority", sdk.get.prioritypolicysetstacks, sdk.get.prioritypolicysets, lambda sid: sdk.get.prioritypolicyrules(prioritypolicyset_id=sid), qos_set_id_name),
        NAT:      ("nat", sdk.get.natpolicysetstacks, sdk.get.natpolicysets, lambda sid: sdk.get.natpolicyrules(natpolicyset_id=sid), nat_set_id_name),
        SECURITY: ("ngfwsecurity", sdk.get.ngfwsecuritypolicysetstacks, sdk.get.ngfwsecuritypolicysets, lambda sid: sdk.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=sid), sec_set_id_name),
        PERFORMANCE: ("perfmgmt", sdk.get.perfmgmtpolicysetstacks, sdk.get.perfmgmtpolicysets, lambda sid: sdk.get.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=sid), perf_set_id_name)
    }

    targets = [PATH, QOS, NAT, SECURITY, PERFORMANCE] if args.policytype == ALL else [args.policytype]

    for p in targets:
        params = pt_map[p]
        filename = f"./{p}_policyconfig.yml"
        
        # Get data for JUST this pillar
        data = pull_generic_policy(sdk, params[0], params[1], params[2], params[3], params[4], p)
        
        with open(filename, "w") as f:
            yaml.safe_dump(data, f, default_flow_style=False)
        print(f"[SUCCESS] Exported: {filename}")

if __name__ == "__main__":
    main()
