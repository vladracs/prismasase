import yaml
import json
import sys
import os
import argparse
import datetime
import prisma_sase

# ---------- Constants ----------
SCRIPT_NAME = "Policy Tool: Master Pull"
__version__ = "1.3.0"

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

CONFIG = {}

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
    print(f"[*] Pulling {section_key.replace('_', ' ').title()}...")
    stack_data, set_data = {}, {}
    
    stacks = stack_func().cgx_content.get("items", [])
    for s in stacks:
        clean = cleandata(s)
        if clean.get("policyset_ids"):
            clean["policyset_ids"] = [set_map.get(sid, sid) for sid in clean["policyset_ids"]]
        stack_data[s["name"]] = clean

    sets = set_func().cgx_content.get("items", [])
    for pset in sets:
        rule_config = {}
        # Fetching rules
        res = rule_func(pset["id"])
        
        # Determine if we handle a standard SDK response or a raw requests response
        items = []
        if hasattr(res, 'cgx_content'):
            items = res.cgx_content.get("items", [])
        elif isinstance(res, dict):
            items = res.get("items", [])

        for r in items:
            rule_config[r["name"]] = translate_rule(cleandata(r), rule_type)
        
        clean_set = cleandata(pset)
        clean_set["rules"] = [{rn: rule_config[rn]} for rn in rule_config.keys()]
        set_data[pset["name"]] = clean_set

    CONFIG[f"{section_key}_stacks"] = [{n: stack_data[n]} for n in stack_data.keys()]
    CONFIG[f"{section_key}_sets"] = [{n: set_data[n]} for n in set_data.keys()]

def main():
    parser = argparse.ArgumentParser(description=SCRIPT_NAME)
    parser.add_argument("-PT", "--policytype", default="all", choices=[PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL])
    parser.add_argument("-O", "--output", help="Output file name")
    args = parser.parse_args()

    sdk = prisma_sase.API(update_check=False)
    sdk.interactive.login_secret(
        client_id=os.environ.get("PRISMASASE_CLIENT_ID"),
        client_secret=os.environ.get("PRISMASASE_CLIENT_SECRET"),
        tsg_id=os.environ.get("PRISMASASE_TSG_ID")
    )
    sdk.get.profile().raise_for_status()

    filename = args.output or f"./prisma_sdwan_{args.policytype}_policies.yml"
    create_global_dicts_all(sdk)

    # Use the session's internal requester for Performance Rules to bypass SDK naming issues
    # Use the SDK's internal raw requester to bypass the missing attribute
    def get_perf_rules(sid):
        url = f"sdwan/v2.2/api/perfmgmtpolicysets/{sid}/perfmgmtpolicyrules"
        # Calling sdk.get as a method directly allows passing a raw URL path
        return sdk.get(url) 

    # Use the explicit SDK method name found in the 6.5.1+ documentation
    pt_map = {
        PATH:     ("path", sdk.get.networkpolicysetstacks, sdk.get.networkpolicysets, lambda sid: sdk.get.networkpolicyrules(networkpolicyset_id=sid), nw_set_id_name),
        QOS:      ("qos", sdk.get.prioritypolicysetstacks, sdk.get.prioritypolicysets, lambda sid: sdk.get.prioritypolicyrules(prioritypolicyset_id=sid), qos_set_id_name),
        NAT:      ("nat", sdk.get.natpolicysetstacks, sdk.get.natpolicysets, lambda sid: sdk.get.natpolicyrules(natpolicyset_id=sid), nat_set_id_name),
        SECURITY: ("security", sdk.get.ngfwsecuritypolicysetstacks, sdk.get.ngfwsecuritypolicysets, lambda sid: sdk.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=sid), sec_set_id_name),
        # CORRECTED METHOD NAME FOR PERFORMANCE RULES:
        PERFORMANCE: ("performance", sdk.get.perfmgmtpolicysetstacks, sdk.get.perfmgmtpolicysets, lambda sid: sdk.get.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=sid), perf_set_id_name)
    }

    if args.policytype == ALL:
        for p_type in [PATH, QOS, NAT, SECURITY, PERFORMANCE]:
            params = pt_map[p_type]
            pull_generic_policy(sdk, params[0], params[1], params[2], params[3], params[4], p_type)
    else:
        params = pt_map[args.policytype]
        pull_generic_policy(sdk, params[0], params[1], params[2], params[3], params[4], args.policytype)

    with open(filename, "w") as f:
        yaml.safe_dump(CONFIG, f, default_flow_style=False)
    
    print(f"\n[SUCCESS] Master Policy Export Complete: {filename}")

if __name__ == "__main__":
    main()