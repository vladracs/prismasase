#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Refactored script to update Prisma SD-WAN Policies
This script expects a YAML file with the policy configuration, acting as the source of truth.
Use pull_policy.py to generate the YAML file.

**Version:** 1.0.0b4
**Author:** Tanushree K
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
    import prisma_sase
except ImportError:
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None

# Authenticate with Prisma SASE SDK
sdk = API()
sdk.interactive.login_secret(
    client_id=PRISMASASE_CLIENT_ID,
    client_secret=PRISMASASE_CLIENT_SECRET,
    tsg_id=PRISMASASE_TSG_ID
)

cgx_session = sdk


# Version for reference
__version__ = "1.0.0b4"
version = __version__

__author__ = "Tanushree K <tkamath@paloaltonetworks.com>"
__email__ = "tkamath@paloaltonetworks.com"
SCRIPT_NAME = "Policy Tool: Push Policy"

DELETE_KEYS = ["_created_on_utc", "_debug", "_error", "_etag",
               "_info", "_schema", "_updated_on_utc", "_warning",
               "_request_id", "_content_length", "_status_code",
               "name", "id"]

#
# Global Dicts
#

# Common across policies
app_id_name = {}
app_name_id = {}
nwcontext_id_name = {}
nwcontext_name_id = {}
perf_threshold_name_id = {}

# Path
nwglobalprefix_id_name = {}
nwglobalprefix_name_id = {}
nwlocalprefix_id_name = {}
nwlocalprefix_name_id = {}
label_label_name = {}
label_name_label = {}
nwpolicyset_id_name = {}
nwpolicyset_name_id = {}
nwpolicyset_name_config = {}
nwpolicystack_id_name = {}
nwpolicystack_name_id = {}
nwpolicystack_name_config = {}
nwpolicyrule_id_name = {}
nwpolicyrule_name_id = {}
nwpolicyrule_name_config = {}
servicelabel_id_name = {}
servicelabel_name_id = {}

# QoS
qosglobalprefix_id_name = {}
qosglobalprefix_name_id = {}
qoslocalprefix_id_name = {}
qoslocalprefix_name_id = {}
qospolicyset_id_name = {}
qospolicyset_name_id = {}
qospolicyset_name_config = {}
qospolicystack_id_name = {}
qospolicystack_name_id = {}
qospolicystack_name_config = {}
qospolicyrule_id_name = {}
qospolicyrule_name_id = {}
qospolicyrule_name_config = {}

# NAT
natglobalprefix_id_name = {}
natglobalprefix_name_id = {}
natlocalprefix_id_name = {}
natlocalprefix_name_id = {}
natpolicyset_id_name = {}
natpolicyset_name_id = {}
natpolicyset_name_config = {}
natpolicystack_id_name = {}
natpolicystack_name_id = {}
natpolicystack_name_config = {}
natpolicyrule_id_name = {}
natpolicyrule_name_id = {}
natpolicyrule_name_config = {}
natzone_id_name = {}
natzone_name_id = {}
natpool_id_name = {}
natpool_name_id = {}

# Security
ngfwglobalprefix_id_name = {}
ngfwglobalprefix_name_id = {}
ngfwlocalprefix_id_name = {}
ngfwlocalprefix_name_id = {}
ngfwpolicyset_id_name = {}
ngfwpolicyset_name_id = {}
ngfwpolicyset_name_config = {}
ngfwpolicystack_id_name = {}
ngfwpolicystack_name_id = {}
ngfwpolicystack_name_config = {}
ngfwpolicyrule_id_name = {}
ngfwpolicyrule_name_id = {}
ngfwpolicyrule_name_config = {}
seczone_id_name = {}
seczone_name_id = {}

# Make sure these are declared at the top of your script with your other globals
perfmgmtpolicyset_name_config = {}
perfmgmtpolicystack_name_config = {}
perf_threshold_name_id = {}

def create_global_dicts_performance(cgx_session):
    """
    Scouts the live Prisma SD-WAN controller to build Name-to-ID memory maps
    specifically for Performance Policies.
    """
    global perfmgmtpolicyset_name_config
    global perfmgmtpolicystack_name_config
    global perf_threshold_name_id

    # 1. Fetch live Performance Sets
    resp = cgx_session.get.perfmgmtpolicysets()
    if resp.cgx_status:
        for item in resp.cgx_content.get("items", []):
            perfmgmtpolicyset_name_config[item["name"]] = item
    else:
        print("ERR: Could not retrieve live Performance Sets")

    # 2. Fetch live Performance Stacks
    resp = cgx_session.get.perfmgmtpolicysetstacks()
    if resp.cgx_status:
        for item in resp.cgx_content.get("items", []):
            perfmgmtpolicystack_name_config[item["name"]] = item
    else:
        print("ERR: Could not retrieve live Performance Stacks")

    # 3. Fetch live Threshold Profiles (For SLA Translations)
    resp = cgx_session.get.perfmgmtthresholdprofiles()
    if resp.cgx_status:
        for item in resp.cgx_content.get("items", []):
            perf_threshold_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve live Threshold Profiles")


N2ID = "n2id"
ID2N = "id2n"

PATH = "path"
QOS = "qos"
NAT = "nat"
SECURITY = "security"
PERFORMANCE = "performance"
ALL = "all"

# Security
SECURITY_POLICY_STACKS="ngfwsecuritypolicysetstacks"
SECURITY_POLICY_SETS="ngfwsecuritypolicysets"
SECURITY_POLICY_RULES="ngfwsecuritypolicyrules"

# Path
NETWORK_POLICY_STACKS = "networkpolicysetstacks"
NETWORK_POLICY_SETS = "networkpolicysets"
NETWORK_POLICY_RULES = "networkpolicyrules"

# QoS
PRIORITY_POLICY_STACKS = "prioritypolicysetstacks"
PRIORITY_POLICY_SETS = "prioritypolicysets"
PRIORITY_POLICY_RULES = "prioritypolicyrules"

# NAT
NAT_POLICY_STACKS = "natpolicysetstacks"
NAT_POLICY_SETS = "natpolicysets"
NAT_POLICY_RULES = "natpolicyrules"

NATACTIONS_name_enum = {
    "No NAT": "no_nat",
    "Source NAT": "source_nat_dynamic",
    "Destination NAT": "destination_nat_dynamic",
    "Static Source NAT": "source_nat_static",
    "Static Destination NAT": "destination_nat_static",
    "ALG Disable": "alg_disable"
}


NATACTIONS_enum_name = {
    "no_nat": "No NAT",
    "source_nat_dynamic": "Source NAT",
    "destination_nat_dynamic": "Destination NAT",
    "source_nat_static": "Static Source NAT",
    "destination_nat_static": "Static Destination NAT",
    "alg_disable": "ALG Disable"
}

def create_global_dicts_all(cgx_session):
    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            app_id_name[item["id"]] = item["display_name"]
            app_name_id[item["display_name"]] = item["id"]

    else:
        print("ERR: Could not retrieve appdefs")
        print(resp.cgx_content)

    #
    # NW Context
    #
    resp = cgx_session.get.networkcontexts()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwcontext_id_name[item["id"]] = item["name"]
            nwcontext_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Contexts")
        print(resp.cgx_content)
    #
    # NW Global Prefix
    #
    resp = cgx_session.get.networkpolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwglobalprefix_id_name[item["id"]] = item["name"]
            nwglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NW Local Prefix
    #
    resp = cgx_session.get.networkpolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwlocalprefix_id_name[item["id"]] = item["name"]
            nwlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Local Prefix Filters")
        print(resp.cgx_content)

    #
    # WAN Interface Labels
    #

    label_label_name["public-*"] = "Any Public"
    label_label_name["private-*"] = "Any Private"
    label_name_label["Any Public"] = "public-*"
    label_name_label["Any Private"] = "private-*"

    resp = cgx_session.get.waninterfacelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            label_label_name[item["label"]] = item["name"]
            label_name_label[item["name"]] = item["label"]

    else:
        print("ERR: Could not retrieve WAN Interface Labels")
        print(resp.cgx_content)

    #
    # NW Policy Stack
    #
    resp = cgx_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwpolicystack_id_name[item["id"]] = item["name"]
            nwpolicystack_name_id[item["name"]] = item["id"]
            nwpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve NW Policy Stacks")
        print(resp.cgx_content)

    #
    # NW Policy Set
    #
    resp = cgx_session.get.networkpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwpolicyset_id_name[item["id"]] = item["name"]
            nwpolicyset_name_id[item["name"]] = item["id"]
            nwpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    nwpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    nwpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    nwpolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve NW Policy Rules")
                print(resp.cgx_content)
    else:
        print("ERR: Could not retrieve NW Policy Sets")
        print(resp.cgx_content)

    #
    # Service Labels
    #
    resp = cgx_session.get.servicelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            servicelabel_id_name[item["id"]] = item["name"]
            servicelabel_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Service Labels")
        print(resp.cgx_content)

    #
    # Qos Global Prefix
    #
    resp = cgx_session.get.prioritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qosglobalprefix_id_name[item["id"]] = item["name"]
            qosglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve QoS Global Prefix Filters")
        print(resp.cgx_content)

    #
    # QoS Local Prefix
    #
    resp = cgx_session.get.prioritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qoslocalprefix_id_name[item["id"]] = item["name"]
            qoslocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve QoS Local Prefix Filters")
        print(resp.cgx_content)

    #
    # QoS Policy Stack
    #
    resp = cgx_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qospolicystack_id_name[item["id"]] = item["name"]
            qospolicystack_name_id[item["name"]] = item["id"]
            qospolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve QoS Policy Stacks")
        print(resp.cgx_content)

    #
    # QoS Policy Set
    #
    resp = cgx_session.get.prioritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qospolicyset_id_name[item["id"]] = item["name"]
            qospolicyset_name_id[item["name"]] = item["id"]
            qospolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    qospolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    qospolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    qospolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve QoS Policy Rules")
                print(resp.cgx_content)
    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        print(resp.cgx_content)

    #
    # NAT Zone
    #
    resp = cgx_session.get.natzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natzone_id_name[item["id"]] = item["name"]
            natzone_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Zones")
        print(resp.cgx_content)

    #
    # NAT Pool
    #
    resp = cgx_session.get.natpolicypools()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpool_id_name[item["id"]] = item["name"]
            natpool_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Pools")
        print(resp.cgx_content)

    #
    # NAT Global Prefix
    #
    resp = cgx_session.get.natglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natglobalprefix_id_name[item["id"]] = item["name"]
            natglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NAT Local Prefix
    #
    resp = cgx_session.get.natlocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natlocalprefix_id_name[item["id"]] = item["name"]
            natlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Local Prefix Filters")
        print(resp.cgx_content)

    #
    # NAT Policy Stack
    #
    resp = cgx_session.get.natpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpolicystack_id_name[item["id"]] = item["name"]
            natpolicystack_name_id[item["name"]] = item["id"]
            natpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve NAT Policy Stacks")
        print(resp.cgx_content)

    #
    # NAT Policy Set
    #
    resp = cgx_session.get.natpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpolicyset_id_name[item["id"]] = item["name"]
            natpolicyset_name_id[item["name"]] = item["id"]
            natpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.natpolicyrules(natpolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    natpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    natpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    natpolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve NAT Policy Rules")
                print(resp.cgx_content)

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        print(resp.cgx_content)

    #
    # NGFW Global Prefix
    #
    resp = cgx_session.get.ngfwsecuritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwglobalprefix_id_name[item["id"]] = item["name"]
            ngfwglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NGFW Local Prefix
    #
    resp = cgx_session.get.ngfwsecuritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwlocalprefix_id_name[item["id"]] = item["name"]
            ngfwlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Local Prefix Filters")
        print(resp.cgx_content)

    #
    # NGFW Policy Stack
    #
    resp = cgx_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwpolicystack_id_name[item["id"]] = item["name"]
            ngfwpolicystack_name_id[item["name"]] = item["id"]
            ngfwpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve Security Policy Stacks")
        print(resp.cgx_content)

    #
    # NGFW Policy Set
    #
    resp = cgx_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwpolicyset_id_name[item["id"]] = item["name"]
            ngfwpolicyset_name_id[item["name"]] = item["id"]
            ngfwpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    ngfwpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    ngfwpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    ngfwpolicyrule_name_config[(item["id"], rule["name"])] = rule
    else:
        print("ERR: Could not retrieve Security Policy Sets")
        print(resp.cgx_content)

    #
    # Security Zones
    #
    resp = cgx_session.get.securityzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            seczone_id_name[item["id"]] = item["name"]
            seczone_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Zones")
        print(resp.cgx_content)


    
    #
   # --- ADD THIS BLOCK AT THE END OF THE FUNCTION ---
    print("INFO: Building Performance Translation Dicts")
    resp = cgx_session.get.perfmgmtthresholdprofiles()
    if resp.cgx_status:
        slas = resp.cgx_content.get("items", [])
        for item in slas:
            # This maps "HTTPS-DC1-VYOS" to its ID "17622..."
            perf_threshold_name_id[item["name"]] = item["id"]
    else:
        print("ERR: Could not retrieve Performance Threshold Profiles")
        print(resp.cgx_content)
# ------------------------------------------------
    return

def create_global_dicts_path(cgx_session):

    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            app_id_name[item["id"]] = item["display_name"]
            app_name_id[item["display_name"]] = item["id"]

    else:
        print("ERR: Could not retrieve appdefs")
        print(resp.cgx_content)

    #
    # NW Context
    #
    resp = cgx_session.get.networkcontexts()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwcontext_id_name[item["id"]] = item["name"]
            nwcontext_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Contexts")
        print(resp.cgx_content)
    #
    # NW Global Prefix
    #
    resp = cgx_session.get.networkpolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwglobalprefix_id_name[item["id"]] = item["name"]
            nwglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NW Local Prefix
    #
    resp = cgx_session.get.networkpolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwlocalprefix_id_name[item["id"]] = item["name"]
            nwlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Local Prefix Filters")
        print(resp.cgx_content)

    #
    # WAN Interface Labels
    #

    label_label_name["public-*"] = "Any Public"
    label_label_name["private-*"] = "Any Private"
    label_name_label["Any Public"] = "public-*"
    label_name_label["Any Private"] = "private-*"

    resp = cgx_session.get.waninterfacelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            label_label_name[item["label"]] = item["name"]
            label_name_label[item["name"]] = item["label"]

    else:
        print("ERR: Could not retrieve WAN Interface Labels")
        print(resp.cgx_content)

    #
    # NW Policy Stack
    #
    resp = cgx_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwpolicystack_id_name[item["id"]] = item["name"]
            nwpolicystack_name_id[item["name"]] = item["id"]
            nwpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve NW Policy Stacks")
        print(resp.cgx_content)

    #
    # NW Policy Set
    #
    resp = cgx_session.get.networkpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwpolicyset_id_name[item["id"]] = item["name"]
            nwpolicyset_name_id[item["name"]] = item["id"]
            nwpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    nwpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    nwpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    nwpolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve NW Policy Rules")
                print(resp.cgx_content)
    else:
        print("ERR: Could not retrieve NW Policy Sets")
        print(resp.cgx_content)

    #
    # Service Labels
    #
    resp = cgx_session.get.servicelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            servicelabel_id_name[item["id"]] = item["name"]
            servicelabel_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Service Labels")
        print(resp.cgx_content)

    return


def create_global_dicts_qos(cgx_session):
    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            app_id_name[item["id"]] = item["display_name"]
            app_name_id[item["display_name"]] = item["id"]

    else:
        print("ERR: Could not retrieve appdefs")
        print(resp.cgx_content)

    #
    # NW Context
    #
    resp = cgx_session.get.networkcontexts()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            nwcontext_id_name[item["id"]] = item["name"]
            nwcontext_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NW Contexts")
        print(resp.cgx_content)
    #
    # Qos Global Prefix
    #
    resp = cgx_session.get.prioritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qosglobalprefix_id_name[item["id"]] = item["name"]
            qosglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve QoS Global Prefix Filters")
        print(resp.cgx_content)

    #
    # QoS Local Prefix
    #
    resp = cgx_session.get.prioritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qoslocalprefix_id_name[item["id"]] = item["name"]
            qoslocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve QoS Local Prefix Filters")
        print(resp.cgx_content)

    #
    # QoS Policy Stack
    #
    resp = cgx_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qospolicystack_id_name[item["id"]] = item["name"]
            qospolicystack_name_id[item["name"]] = item["id"]
            qospolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve QoS Policy Stacks")
        print(resp.cgx_content)

    #
    # QoS Policy Set
    #
    resp = cgx_session.get.prioritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            qospolicyset_id_name[item["id"]] = item["name"]
            qospolicyset_name_id[item["name"]] = item["id"]
            qospolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    qospolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    qospolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    qospolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve QoS Policy Rules")
                print(resp.cgx_content)
    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        print(resp.cgx_content)

    return


def create_global_dicts_nat(cgx_session):
    #
    # NAT Zone
    #
    resp = cgx_session.get.natzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natzone_id_name[item["id"]] = item["name"]
            natzone_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Zones")
        print(resp.cgx_content)

    #
    # NAT Pool
    #
    resp = cgx_session.get.natpolicypools()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpool_id_name[item["id"]] = item["name"]
            natpool_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Pools")
        print(resp.cgx_content)

    #
    # NAT Global Prefix
    #
    resp = cgx_session.get.natglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natglobalprefix_id_name[item["id"]] = item["name"]
            natglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NAT Local Prefix
    #
    resp = cgx_session.get.natlocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natlocalprefix_id_name[item["id"]] = item["name"]
            natlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve NAT Local Prefix Filters")
        print(resp.cgx_content)

    #
    # NAT Policy Stack
    #
    resp = cgx_session.get.natpolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpolicystack_id_name[item["id"]] = item["name"]
            natpolicystack_name_id[item["name"]] = item["id"]
            natpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve NAT Policy Stacks")
        print(resp.cgx_content)

    #
    # NAT Policy Set
    #
    resp = cgx_session.get.natpolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            natpolicyset_id_name[item["id"]] = item["name"]
            natpolicyset_name_id[item["name"]] = item["id"]
            natpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.natpolicyrules(natpolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    natpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    natpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    natpolicyrule_name_config[(item["id"], rule["name"])] = rule
            else:
                print("ERR: Could not retrieve NAT Policy Rules")
                print(resp.cgx_content)

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        print(resp.cgx_content)


    return


def create_global_dicts_security(cgx_session):

    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            app_id_name[item["id"]] = item["display_name"]
            app_name_id[item["display_name"]] = item["id"]

    else:
        print("ERR: Could not retrieve appdefs")
        print(resp.cgx_content)

    #
    # NGFW Global Prefix
    #
    resp = cgx_session.get.ngfwsecuritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwglobalprefix_id_name[item["id"]] = item["name"]
            ngfwglobalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Global Prefix Filters")
        print(resp.cgx_content)

    #
    # NGFW Local Prefix
    #
    resp = cgx_session.get.ngfwsecuritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwlocalprefix_id_name[item["id"]] = item["name"]
            ngfwlocalprefix_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Local Prefix Filters")
        print(resp.cgx_content)

    #
    # NGFW Policy Stack
    #
    resp = cgx_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwpolicystack_id_name[item["id"]] = item["name"]
            ngfwpolicystack_name_id[item["name"]] = item["id"]
            ngfwpolicystack_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve Security Policy Stacks")
        print(resp.cgx_content)

    #
    # NGFW Policy Set
    #
    resp = cgx_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            ngfwpolicyset_id_name[item["id"]] = item["name"]
            ngfwpolicyset_name_id[item["name"]] = item["id"]
            ngfwpolicyset_name_config[item["name"]] = item

            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=item["id"])
            if resp.cgx_content:
                rules = resp.cgx_content.get("items", None)
                for rule in rules:
                    ngfwpolicyrule_id_name[(item["id"], rule["id"])] = rule["name"]
                    ngfwpolicyrule_name_id[(item["id"], rule["name"])] = rule["id"]
                    ngfwpolicyrule_name_config[(item["id"], rule["name"])] = rule
    else:
        print("ERR: Could not retrieve Security Policy Sets")
        print(resp.cgx_content)

    #
    # Security Zones
    #
    resp = cgx_session.get.securityzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            seczone_id_name[item["id"]] = item["name"]
            seczone_name_id[item["name"]] = item["id"]

    else:
        print("ERR: Could not retrieve Security Zones")
        print(resp.cgx_content)

    return


def cleandata(data):
    tmp = data
    for key in DELETE_KEYS:
        if key in tmp.keys():
            del tmp[key]

    return tmp


# replace NULL exported YAML values with blanks. Semantically the same, but easier to read.
def represent_none(self, _):
    return self.represent_scalar('tag:yaml.org,2002:null', '')


yaml.add_representer(type(None), represent_none, Dumper=yaml.SafeDumper)


def translate_rule(rule, rule_type, action):
    ############################################################################
    # Translate Rule - Path
    ############################################################################

    if rule_type == PATH:
        if action == ID2N:
            #
            # NW Context
            #
            network_context_id = rule.get("network_context_id", None)
            if network_context_id in nwcontext_id_name.keys():
                rule["network_context_id"] = nwcontext_id_name[network_context_id]

            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in nwglobalprefix_id_name.keys():
                rule["source_prefixes_id"] = nwglobalprefix_id_name[source_prefixes_id]
            elif source_prefixes_id in nwlocalprefix_id_name.keys():
                rule["source_prefixes_id"] = nwlocalprefix_id_name[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in nwglobalprefix_id_name.keys():
                rule["destination_prefixes_id"] = nwglobalprefix_id_name[destination_prefixes_id]
            elif destination_prefixes_id in nwlocalprefix_id_name.keys():
                rule["destination_prefixes_id"] = nwlocalprefix_id_name[destination_prefixes_id]

            #
            # Service Context
            #
            service_context = rule.get("service_context", None)
            if service_context is not None:
                active_service_label_id = service_context.get("active_service_label_id", None)
                if active_service_label_id in servicelabel_id_name.keys():
                    service_context["active_service_label_id"] = servicelabel_id_name[active_service_label_id]

                backup_service_label_id = service_context.get("backup_service_label_id", None)
                if backup_service_label_id in servicelabel_id_name.keys():
                    service_context["backup_service_label_id"] = servicelabel_id_name[backup_service_label_id]

            rule["service_context"] = service_context

            #
            # Appdefs
            #
            app_def_names = []
            app_def_ids = rule.get("app_def_ids", None)
            if app_def_ids is not None:
                for appid in app_def_ids:
                    if appid in app_id_name.keys():
                        app_def_names.append(app_id_name[appid])
                    else:
                        print("WARN: App ID {} in rule {} could not be translated".format(appid, rule["name"]))
                        app_def_names.append(appid)

                rule["app_def_ids"] = app_def_names

            #
            # Labels
            #
            paths_allowed = rule.get("paths_allowed", None)

            if paths_allowed is not None:

                #
                # Labels - active_paths
                #
                active_paths_names = []
                active_paths = paths_allowed.get("active_paths", None)
                if active_paths is not None:
                    for path in active_paths:
                        label = path.get("label", None)
                        if label in label_label_name.keys():
                            path["label"] = label_label_name[label]

                        active_paths_names.append(path)

                paths_allowed["active_paths"] = active_paths_names

                #
                # Labels - backup_paths
                #
                backup_paths_names = []
                backup_paths = paths_allowed.get("backup_paths", None)
                if backup_paths is not None:
                    for path in backup_paths:
                        label = path.get("label", None)
                        if label in label_label_name.keys():
                            path["label"] = label_label_name[label]

                        backup_paths_names.append(path)

                paths_allowed["backup_paths"] = backup_paths_names

                #
                # Labels - l3_failure_paths
                #
                l3_failure_paths_names = []
                l3_failure_paths = paths_allowed.get("l3_failure_paths", None)
                if l3_failure_paths is not None:
                    for path in l3_failure_paths:
                        label = path.get("label", None)
                        if label in label_label_name.keys():
                            path["label"] = label_label_name[label]

                        l3_failure_paths_names.append(path)

                paths_allowed["l3_failure_paths"] = l3_failure_paths_names

            rule["paths_allowed"] = paths_allowed


        elif action == N2ID:
            #
            # NW Context
            #
            network_context_id = rule.get("network_context_id", None)
            if network_context_id in nwcontext_name_id.keys():
                rule["network_context_id"] = nwcontext_name_id[network_context_id]

            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in nwglobalprefix_name_id.keys():
                rule["source_prefixes_id"] = nwglobalprefix_name_id[source_prefixes_id]
            elif source_prefixes_id in nwlocalprefix_name_id.keys():
                rule["source_prefixes_id"] = nwlocalprefix_name_id[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in nwglobalprefix_name_id.keys():
                rule["destination_prefixes_id"] = nwglobalprefix_name_id[destination_prefixes_id]
            elif destination_prefixes_id in nwlocalprefix_name_id.keys():
                rule["destination_prefixes_id"] = nwlocalprefix_name_id[destination_prefixes_id]

            #
            # Service Context
            #
            service_context = rule.get("service_context", None)
            if service_context is not None:
                active_service_label_id = service_context.get("active_service_label_id", None)
                if active_service_label_id in servicelabel_name_id.keys():
                    service_context["active_service_label_id"] = servicelabel_name_id[active_service_label_id]

                backup_service_label_id = service_context.get("backup_service_label_id", None)
                if backup_service_label_id in servicelabel_name_id.keys():
                    service_context["backup_service_label_id"] = servicelabel_name_id[backup_service_label_id]

            rule["service_context"] = service_context

            #
            # Appdefs
            #
            app_def_ids = []
            app_def_names = rule.get("app_def_ids", None)
            if app_def_names is not None:
                for appname in app_def_names:
                    if appname in app_name_id.keys():
                        app_def_ids.append(app_name_id[appname])
                    else:
                        print("WARN: App Name {} in rule {} could not be translated".format(appname, rule["name"]))
                        app_def_ids.append(appname)

                rule["app_def_ids"] = app_def_ids

            #
            # Labels
            #
            paths_allowed = rule.get("paths_allowed", None)

            if paths_allowed is not None:

                #
                # Labels - active_paths
                #
                active_paths_names = []
                active_paths = paths_allowed.get("active_paths", None)
                if active_paths is not None:
                    for path in active_paths:
                        label = path.get("label", None)
                        if label in label_name_label.keys():
                            path["label"] = label_name_label[label]

                        active_paths_names.append(path)

                paths_allowed["active_paths"] = active_paths_names

                #
                # Labels - backup_paths
                #
                backup_paths_names = []
                backup_paths = paths_allowed.get("backup_paths", None)
                if backup_paths is not None:
                    for path in backup_paths:
                        label = path.get("label", None)
                        if label in label_name_label.keys():
                            path["label"] = label_name_label[label]

                        backup_paths_names.append(path)

                paths_allowed["backup_paths"] = backup_paths_names

                #
                # Labels - l3_failure_paths
                #
                l3_failure_paths_names = []
                l3_failure_paths = paths_allowed.get("l3_failure_paths", None)
                if l3_failure_paths is not None:
                    for path in l3_failure_paths:
                        label = path.get("label", None)
                        if label in label_name_label.keys():
                            path["label"] = label_name_label[label]

                        l3_failure_paths_names.append(path)

                paths_allowed["l3_failure_paths"] = l3_failure_paths_names

            rule["paths_allowed"] = paths_allowed

    ############################################################################
    # Translate Rule - QoS
    ############################################################################
    elif rule_type == QOS:
        if action == ID2N:
            #
            # NW Context
            #
            network_context_id = rule.get("network_context_id", None)
            if network_context_id in nwcontext_id_name.keys():
                rule["network_context_id"] = nwcontext_id_name[network_context_id]

            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in qosglobalprefix_id_name.keys():
                rule["source_prefixes_id"] = qosglobalprefix_id_name[source_prefixes_id]
            elif source_prefixes_id in qoslocalprefix_id_name.keys():
                rule["source_prefixes_id"] = qoslocalprefix_id_name[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in qosglobalprefix_id_name.keys():
                rule["destination_prefixes_id"] = qosglobalprefix_id_name[destination_prefixes_id]
            elif destination_prefixes_id in qoslocalprefix_id_name.keys():
                rule["destination_prefixes_id"] = qoslocalprefix_id_name[destination_prefixes_id]

            #
            # Appdefs
            #
            app_def_names = []
            app_def_ids = rule.get("app_def_ids", None)
            if app_def_ids is not None:
                for appid in app_def_ids:
                    if appid in app_id_name.keys():
                        app_def_names.append(app_id_name[appid])
                    else:
                        print("WARN: App ID {} in rule {} could not be translated".format(appid, rule["name"]))
                        app_def_names.append(appid)

                rule["app_def_ids"] = app_def_names



        elif action == N2ID:
            #
            # NW Context
            #
            network_context_id = rule.get("network_context_id", None)
            if network_context_id in nwcontext_name_id.keys():
                rule["network_context_id"] = nwcontext_name_id[network_context_id]

            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in qosglobalprefix_name_id.keys():
                rule["source_prefixes_id"] = qosglobalprefix_name_id[source_prefixes_id]
            elif source_prefixes_id in qoslocalprefix_name_id.keys():
                rule["source_prefixes_id"] = qoslocalprefix_name_id[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in qosglobalprefix_name_id.keys():
                rule["destination_prefixes_id"] = qosglobalprefix_name_id[destination_prefixes_id]
            elif destination_prefixes_id in qoslocalprefix_name_id.keys():
                rule["destination_prefixes_id"] = qoslocalprefix_name_id[destination_prefixes_id]

            #
            # Appdefs
            #
            app_def_ids = []
            app_def_names = rule.get("app_def_ids", None)
            if app_def_names is not None:
                for appname in app_def_names:
                    if appname in app_name_id.keys():
                        app_def_ids.append(app_name_id[appname])
                    else:
                        print("WARN: App Name {} in rule {} could not be translated".format(appname, rule["name"]))
                        app_def_ids.append(appname)

                rule["app_def_ids"] = app_def_ids

    ############################################################################
    # Translate Rule - NAT
    ############################################################################
    elif rule_type == NAT:
        if action == ID2N:

            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in natglobalprefix_id_name.keys():
                rule["source_prefixes_id"] = natglobalprefix_id_name[source_prefixes_id]
            elif source_prefixes_id in natlocalprefix_id_name.keys():
                rule["source_prefixes_id"] = natlocalprefix_id_name[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in natglobalprefix_id_name.keys():
                rule["destination_prefixes_id"] = natglobalprefix_id_name[destination_prefixes_id]
            elif destination_prefixes_id in natlocalprefix_id_name.keys():
                rule["destination_prefixes_id"] = natlocalprefix_id_name[destination_prefixes_id]

            #
            # Source NAT Zone
            #
            source_zone_id = rule.get("source_zone_id", None)
            if source_zone_id in natzone_id_name.keys():
                rule["source_zone_id"] = natzone_id_name[source_zone_id]
            #
            # Destination NAT Zone
            #
            destination_zone_id = rule.get("destination_zone_id", None)
            if destination_zone_id in natzone_id_name.keys():
                rule["destination_zone_id"] = natzone_id_name[destination_zone_id]

            #
            # NAT Pool & action type
            #
            actions_name = []
            natactions = rule.get("actions", None)
            for nataction in natactions:
                nat_pool_id = nataction.get("nat_pool_id", None)
                if nat_pool_id in natpool_id_name.keys():
                    nataction["nat_pool_id"] = natpool_id_name[nat_pool_id]

                nataction["type"] = NATACTIONS_enum_name[nataction["type"]]

                actions_name.append(nataction)

            rule["actions"] = actions_name


        elif action == N2ID:
            #
            # Source Prefix
            #
            source_prefixes_id = rule.get("source_prefixes_id", None)
            if source_prefixes_id in natglobalprefix_name_id.keys():
                rule["source_prefixes_id"] = natglobalprefix_name_id[source_prefixes_id]
            elif source_prefixes_id in natlocalprefix_name_id.keys():
                rule["source_prefixes_id"] = natlocalprefix_name_id[source_prefixes_id]

            #
            # Destination Prefix
            #
            destination_prefixes_id = rule.get("destination_prefixes_id", None)
            if destination_prefixes_id in natglobalprefix_name_id.keys():
                rule["destination_prefixes_id"] = natglobalprefix_name_id[destination_prefixes_id]
            elif destination_prefixes_id in natlocalprefix_name_id.keys():
                rule["destination_prefixes_id"] = natlocalprefix_name_id[destination_prefixes_id]

            #
            # Source NAT Zone
            #
            source_zone_id = rule.get("source_zone_id", None)
            if source_zone_id in natzone_name_id.keys():
                rule["source_zone_id"] = natzone_name_id[source_zone_id]

            #
            # Destination NAT Zone
            #
            destination_zone_id = rule.get("destination_zone_id", None)
            if destination_zone_id in natzone_name_id.keys():
                rule["destination_zone_id"] = natzone_name_id[destination_zone_id]

            #
            # NAT Pool & action type
            #
            actions_id = []
            natactions = rule.get("actions", None)
            for nataction in natactions:
                nat_pool_id = nataction.get("nat_pool_id", None)
                if nat_pool_id in natpool_name_id.keys():
                    nataction["nat_pool_id"] = natpool_name_id[nat_pool_id]

                nataction["type"] = NATACTIONS_name_enum[nataction["type"]]

                actions_id.append(nataction)

            rule["actions"] = actions_id

    ############################################################################
    # Translate Rule - Security
    ############################################################################
    elif rule_type == SECURITY:
        if action == ID2N:

            #
            # Source Prefix
            #
            source_prefix_ids = rule.get("source_prefix_ids", None)
            src_pf_names = []
            if source_prefix_ids is not None:
                for pfid in source_prefix_ids:
                    if pfid in ngfwglobalprefix_id_name.keys():
                        src_pf_names.append(ngfwglobalprefix_id_name[pfid])

                    elif pfid in ngfwlocalprefix_id_name.keys():
                        src_pf_names.append(ngfwlocalprefix_id_name[pfid])

                rule["source_prefix_ids"] = src_pf_names

            #
            # Destination Prefix
            #
            destination_prefix_ids = rule.get("destination_prefix_ids", None)
            dst_pf_names = []
            if destination_prefix_ids is not None:
                for pfid in destination_prefix_ids:

                    if pfid in ngfwglobalprefix_id_name.keys():
                        dst_pf_names.append(ngfwglobalprefix_id_name[pfid])

                    elif pfid in ngfwlocalprefix_id_name.keys():
                        dst_pf_names.append(ngfwlocalprefix_id_name[pfid])

                rule["destination_prefix_ids"] = dst_pf_names

            #
            # Source Zone
            #
            source_zone_ids = rule.get("source_zone_ids", None)
            src_zone_names = []
            if source_zone_ids is not None:
                for zid in source_zone_ids:
                    if zid in seczone_id_name.keys():
                        src_zone_names.append(seczone_id_name[zid])

                rule["source_zone_ids"] = src_zone_names

            #
            # Destination Zone
            #
            destination_zone_ids = rule.get("destination_zone_ids", None)
            dst_zone_names = []
            if destination_zone_ids is not None:
                for zid in destination_zone_ids:

                    if zid in seczone_id_name.keys():
                        dst_zone_names.append(seczone_id_name[zid])

                rule["destination_zone_ids"] = dst_zone_names

            #
            # Appdefs
            #
            app_def_names = []
            app_def_ids = rule.get("app_def_ids", None)
            if app_def_ids is not None:
                for appid in app_def_ids:
                    if appid in app_id_name.keys():
                        app_def_names.append(app_id_name[appid])
                    else:
                        print("WARN: App ID {} in rule {} could not be transalted".format(appid, rule["name"]))
                        app_def_names.append(appid)

                rule["app_def_ids"] = app_def_names


        elif action == N2ID:
            #
            # Source Prefix
            #
            source_prefix_ids = rule.get("source_prefix_ids", None)
            src_pf_ids = []
            if source_prefix_ids is not None:
                for pfname in source_prefix_ids:

                    if pfname in ngfwglobalprefix_name_id.keys():
                        src_pf_ids.append(ngfwglobalprefix_name_id[pfname])

                    elif pfname in ngfwlocalprefix_name_id.keys():
                        src_pf_ids.append(ngfwlocalprefix_name_id[pfname])

                rule["source_prefix_ids"] = src_pf_ids

            #
            # Destination Prefix
            #
            destination_prefix_ids = rule.get("destination_prefix_ids", None)
            dst_pf_ids = []
            if destination_prefix_ids is not None:
                for pfname in destination_prefix_ids:

                    if pfname in ngfwglobalprefix_name_id.keys():
                        dst_pf_ids.append(ngfwglobalprefix_name_id[pfname])

                    elif pfname in ngfwlocalprefix_name_id.keys():
                        dst_pf_ids.append(ngfwlocalprefix_name_id[pfname])

                rule["destination_prefix_ids"] = dst_pf_ids

            #
            # Source Zone
            #
            source_zone_ids = rule.get("source_zone_ids", None)
            src_zone_ids = []
            if source_zone_ids is not None:
                for zname in source_zone_ids:
                    if zname in seczone_name_id.keys():
                        src_zone_ids.append(seczone_name_id[zname])

                rule["source_zone_ids"] = src_zone_ids

            #
            # Destination Zone
            #
            destination_zone_ids = rule.get("destination_zone_ids", None)
            dst_zone_ids = []
            if destination_zone_ids is not None:
                for zname in destination_zone_ids:

                    if zname in seczone_name_id.keys():
                        dst_zone_ids.append(seczone_name_id[zname])

                rule["destination_zone_ids"] = dst_zone_ids

            #
            # Appdefs
            #
            app_def_ids = []
            app_def_names = rule.get("app_def_ids", None)
            if app_def_names is not None:
                for appname in app_def_names:
                    if appname in app_name_id.keys():
                        app_def_ids.append(app_name_id[appname])
                    else:
                        print("WARN: App Name {} in rule {} could not be transalted".format(appname, rule["name"]))
                        app_def_ids.append(appname)

                rule["app_def_ids"] = app_def_ids

    return rule


def translate_stack(stack, stack_type, action):
    ############################################################################
    # Translate Stack - Path
    ############################################################################
    if stack_type == PATH:
        if action == ID2N:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in nwpolicyset_id_name.keys():
                    stack["defaultrule_policyset_id"] = nwpolicyset_id_name[defaultrule_policyset_id]

                policset_names = []
                policyset_ids = stack.get("policyset_ids", None)

                if policyset_ids is not None:
                    for pid in policyset_ids:
                        if pid in nwpolicyset_id_name.keys():
                            policset_names.append(nwpolicyset_id_name[pid])

                stack["policyset_ids"] = policset_names


        elif action == N2ID:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in nwpolicyset_name_id.keys():
                    stack["defaultrule_policyset_id"] = nwpolicyset_name_id[defaultrule_policyset_id]

                policset_ids = []
                policyset_names = stack.get("policyset_ids", None)
                if policyset_names is not None:
                    for pname in policyset_names:
                        if pname in nwpolicyset_name_id.keys():
                            policset_ids.append(nwpolicyset_name_id[pname])

                stack["policyset_ids"] = policset_ids

    ############################################################################
    # Translate Stack - QoS
    ############################################################################
    elif stack_type == QOS:
        if action == ID2N:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in qospolicyset_id_name.keys():
                    stack["defaultrule_policyset_id"] = qospolicyset_id_name[defaultrule_policyset_id]

                policset_names = []
                policyset_ids = stack.get("policyset_ids", None)

                if policyset_ids is not None:
                    for pid in policyset_ids:
                        if pid in qospolicyset_id_name.keys():
                            policset_names.append(qospolicyset_id_name[pid])

                stack["policyset_ids"] = policset_names


        elif action == N2ID:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in qospolicyset_name_id.keys():
                    stack["defaultrule_policyset_id"] = qospolicyset_name_id[defaultrule_policyset_id]

                policset_ids = []
                policyset_names = stack.get("policyset_ids", None)
                if policyset_names is not None:
                    for pname in policyset_names:
                        if pname in qospolicyset_name_id.keys():
                            policset_ids.append(qospolicyset_name_id[pname])

                stack["policyset_ids"] = policset_ids

    ############################################################################
    # Translate Stack - NAT
    ############################################################################
    elif stack_type == NAT:
        if action == ID2N:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in natpolicyset_id_name.keys():
                    stack["defaultrule_policyset_id"] = natpolicyset_id_name[defaultrule_policyset_id]

                policset_names = []
                policyset_ids = stack.get("policyset_ids", None)

                if policyset_ids is not None:
                    for pid in policyset_ids:
                        if pid in natpolicyset_id_name.keys():
                            policset_names.append(natpolicyset_id_name[pid])

                stack["policyset_ids"] = policset_names


        elif action == N2ID:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in natpolicyset_name_id.keys():
                    stack["defaultrule_policyset_id"] = natpolicyset_name_id[defaultrule_policyset_id]

                policset_ids = []
                policyset_names = stack.get("policyset_ids", None)
                if policyset_names is not None:
                    for pname in policyset_names:
                        if pname in natpolicyset_name_id.keys():
                            policset_ids.append(natpolicyset_name_id[pname])

                stack["policyset_ids"] = policset_ids

    ############################################################################
    # Translate Stack - NAT
    ############################################################################
    elif stack_type == SECURITY:
        if action == ID2N:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in ngfwpolicyset_id_name.keys():
                    stack["defaultrule_policyset_id"] = ngfwpolicyset_id_name[defaultrule_policyset_id]

                policset_names = []
                policyset_ids = stack.get("policyset_ids", None)

                if policyset_ids is not None:
                    for pid in policyset_ids:
                        if pid in ngfwpolicyset_id_name.keys():
                            policset_names.append(ngfwpolicyset_id_name[pid])

                stack["policyset_ids"] = policset_names


        elif action == N2ID:
            if stack is not None:
                defaultrule_policyset_id = stack.get("defaultrule_policyset_id", None)

                if defaultrule_policyset_id in ngfwpolicyset_name_id.keys():
                    stack["defaultrule_policyset_id"] = ngfwpolicyset_name_id[defaultrule_policyset_id]

                policset_ids = []
                policyset_names = stack.get("policyset_ids", None)
                if policyset_names is not None:
                    for pname in policyset_names:
                        if pname in ngfwpolicyset_name_id.keys():
                            policset_ids.append(ngfwpolicyset_name_id[pname])

                stack["policyset_ids"] = policset_ids

    return stack


def translate_set(setdata, setid, set_type, action):
    ############################################################################
    # Translate Set - NAT
    ############################################################################
    if set_type == NAT:
        if action == ID2N:
            if setdata is not None:
                #
                # Destination Zone Rule Order
                #
                destination_zone_policyrule_order = setdata.get("destination_zone_policyrule_order", None)
                if destination_zone_policyrule_order is not None:
                    rulenames_dest = []
                    for ruleid in destination_zone_policyrule_order:
                        if (setid, ruleid) in natpolicyrule_id_name.keys():
                            rulenames_dest.append(natpolicyrule_id_name[(setid, ruleid)])

                    setdata["destination_zone_policyrule_order"] = rulenames_dest

                #
                # Source Zone Rule Order
                #
                source_zone_policyrule_order = setdata.get("source_zone_policyrule_order", None)
                if source_zone_policyrule_order is not None:
                    rulenames_src = []
                    for ruleid in source_zone_policyrule_order:
                        if (setid, ruleid) in natpolicyrule_id_name.keys():
                            rulenames_src.append(natpolicyrule_id_name[(setid, ruleid)])

                    setdata["source_zone_policyrule_order"] = rulenames_src

        elif action == N2ID:
            if setdata is not None:
                #
                # Destination Zone Rule Order
                #
                destination_zone_policyrule_order = setdata.get("destination_zone_policyrule_order", None)
                if destination_zone_policyrule_order is not None:
                    ruleids_dest = []
                    for rulename in destination_zone_policyrule_order:
                        if (setid, rulename) in natpolicyrule_name_id.keys():
                            ruleids_dest.append(natpolicyrule_name_id[(setid, rulename)])

                    setdata["destination_zone_policyrule_order"] = ruleids_dest

                #
                # Source Zone Rule Order
                #
                source_zone_policyrule_order = setdata.get("source_zone_policyrule_order", None)
                if source_zone_policyrule_order is not None:
                    ruleids_src = []
                    for rulename in source_zone_policyrule_order:
                        if (setid, rulename) in natpolicyrule_name_id.keys():
                            ruleids_src.append(natpolicyrule_name_id[(setid, rulename)])

                    setdata["source_zone_policyrule_order"] = ruleids_src

    ############################################################################
    # Translate Set - Security
    ############################################################################
    elif set_type == SECURITY:
        if action == ID2N:
            if setdata is not None:
                #
                # Policy Rule Order
                #
                policyrule_order = setdata.get("policyrule_order", None)
                if policyrule_order is not None:
                    rulenames = []
                    for ruleid in policyrule_order:
                        if (setid, ruleid) in ngfwpolicyrule_id_name.keys():
                            rulenames.append(ngfwpolicyrule_id_name[(setid, ruleid)])

                    setdata["policyrule_order"] = rulenames

        elif action == N2ID:
            if setdata is not None:
                #
                # Destination Zone Rule Order
                #
                policyrule_order = setdata.get("policyrule_order", None)
                if policyrule_order is not None:
                    ruleids = []
                    for rulename in policyrule_order:
                        if (setid, rulename) in ngfwpolicyrule_name_id.keys():
                            ruleids.append(ngfwpolicyrule_name_id[(setid, rulename)])

                    setdata["policyrule_order"] = ruleids

    return setdata


def find_diff(d1, d2, path=""):
    """
    Compare two nested dictionaries.
    Derived from https://stackoverflow.com/questions/27265939/comparing-python-dictionaries-and-nested-dictionaries
    :param d1: Dict 1
    :param d2: Dict 2
    :param path: Level
    :return:
    """
    return_str = ""
    for k in d1:
        if k not in d2:
            return_str += "{0} {1}\n".format(path, ":")
            return_str += "{0} {1}\n".format(k + " as key not in d2", "\n")
        else:
            if type(d1[k]) is dict:
                if path == "":
                    path = k
                else:
                    path = path + "->" + k
                return_str += find_diff(d1[k], d2[k], path)
            elif type(d1[k]) == list:
                find_diff(dict(zip(map(str, range(len(d1[k]))), d1[k])), dict(zip(map(str, range(len(d2[k]))), d2[k])),
                          k)
            else:
                if d1[k] != d2[k]:
                    return_str += "{0} {1}\n".format(path, ":")
                    return_str += "{0} {1} {2} {3}\n".format(" - ", k, " : ", d1[k])
                    return_str += "{0} {1} {2} {3}\n".format(" + ", k, " : ", d2[k])
    return return_str



def compareconf(origconf, curconf):
    result = list(diff(origconf, curconf))
    resources_updated = []
    for item in result:
        if isinstance(item[1], str):
            if "." in item[1]:
                tmp = item[1].split(".")

                if tmp[0] not in resources_updated:
                    resources_updated.append(tmp[0])
            else:
                if item[1] not in resources_updated:
                    if item[1] == '':
                        continue
                    resources_updated.append(item[1])

        elif isinstance(item[1], list):
            if item[1][0] not in resources_updated:
                resources_updated.append(item[1][0])

    return resources_updated


def extractfromyaml(loaded_config, config_type):
    if config_type not in loaded_config.keys():
        print("No configs found for {}. Skipping..".format(config_type))
        return None
    ############################################################################
    # Path
    ############################################################################
    if config_type == NETWORK_POLICY_STACKS:
        stackconfig_clean = {}
        stackconfigs = copy.deepcopy(loaded_config.get(NETWORK_POLICY_STACKS, None))
        for stackdata in stackconfigs:
            stack_key = list(stackdata.keys())[0]
            stack_config = stackdata[stack_key]
            stack_config["name"] = stack_key
            stackconfig_clean[stack_key] = stack_config

        return stackconfig_clean

    elif config_type == NETWORK_POLICY_SETS:
        setconfig_clean = {}
        setconfigs = copy.deepcopy(loaded_config.get(NETWORK_POLICY_SETS, None))
        for setdata in setconfigs:
            set_key = list(setdata.keys())[0]
            set_config = setdata[set_key]
            set_config["name"] = set_key
            setconfig_clean[set_key] = set_config

        return setconfig_clean

    elif config_type == NETWORK_POLICY_RULES:
        ruleconfig_clean = {}
        ruleconfigs = copy.deepcopy(loaded_config.get(NETWORK_POLICY_RULES, None))
        for ruledata in ruleconfigs:
            rule_key = list(ruledata.keys())[0]
            rule_config = ruledata[rule_key]
            rule_config["name"] = rule_key
            ruleconfig_clean[rule_key] = rule_config

        return ruleconfig_clean

    ############################################################################
    # QoS
    ############################################################################
    elif config_type == PRIORITY_POLICY_STACKS:
        stackconfig_clean = {}
        stackconfigs = copy.deepcopy(loaded_config.get(PRIORITY_POLICY_STACKS, None))
        for stackdata in stackconfigs:
            stack_key = list(stackdata.keys())[0]
            stack_config = stackdata[stack_key]
            stack_config["name"] = stack_key
            stackconfig_clean[stack_key] = stack_config

        return stackconfig_clean

    elif config_type == PRIORITY_POLICY_SETS:
        setconfig_clean = {}
        setconfigs = copy.deepcopy(loaded_config.get(PRIORITY_POLICY_SETS, None))
        for setdata in setconfigs:
            set_key = list(setdata.keys())[0]
            set_config = setdata[set_key]
            set_config["name"] = set_key
            setconfig_clean[set_key] = set_config

        return setconfig_clean

    elif config_type == PRIORITY_POLICY_RULES:
        ruleconfig_clean = {}
        ruleconfigs = copy.deepcopy(loaded_config.get(PRIORITY_POLICY_RULES, None))
        for ruledata in ruleconfigs:
            rule_key = list(ruledata.keys())[0]
            rule_config = ruledata[rule_key]
            rule_config["name"] = rule_key
            ruleconfig_clean[rule_key] = rule_config

        return ruleconfig_clean

    ############################################################################
    # NAT
    ############################################################################
    elif config_type == NAT_POLICY_STACKS:
        stackconfig_clean = {}
        stackconfigs = copy.deepcopy(loaded_config.get(NAT_POLICY_STACKS, None))
        for stackdata in stackconfigs:
            stack_key = list(stackdata.keys())[0]
            stack_config = stackdata[stack_key]
            stack_config["name"] = stack_key
            stackconfig_clean[stack_key] = stack_config

        return stackconfig_clean

    elif config_type == NAT_POLICY_SETS:
        setconfig_clean = {}
        setconfigs = copy.deepcopy(loaded_config.get(NAT_POLICY_SETS, None))
        for setdata in setconfigs:
            set_key = list(setdata.keys())[0]
            set_config = setdata[set_key]
            set_config["name"] = set_key
            setconfig_clean[set_key] = set_config

        return setconfig_clean

    elif config_type == NAT_POLICY_RULES:
        ruleconfig_clean = {}
        ruleconfigs = copy.deepcopy(loaded_config.get(NAT_POLICY_RULES, None))
        for ruledata in ruleconfigs:
            rule_key = list(ruledata.keys())[0]
            rule_config = ruledata[rule_key]
            rule_config["name"] = rule_key
            ruleconfig_clean[rule_key] = rule_config

        return ruleconfig_clean

    ############################################################################
    # Security
    ############################################################################
    elif config_type == SECURITY_POLICY_STACKS:
        stackconfig_clean = {}
        stackconfigs = copy.deepcopy(loaded_config.get(SECURITY_POLICY_STACKS, None))
        for stackdata in stackconfigs:
            stack_key = list(stackdata.keys())[0]
            stack_config = stackdata[stack_key]
            stack_config["name"] = stack_key
            stackconfig_clean[stack_key] = stack_config

        return stackconfig_clean

    elif config_type == SECURITY_POLICY_SETS:
        setconfig_clean = {}
        setconfigs = copy.deepcopy(loaded_config.get(SECURITY_POLICY_SETS, None))
        for setdata in setconfigs:
            set_key = list(setdata.keys())[0]
            set_config = setdata[set_key]
            set_config["name"] = set_key
            setconfig_clean[set_key] = set_config

        return setconfig_clean

    elif config_type == SECURITY_POLICY_RULES:
        ruleconfig_clean = {}
        ruleconfigs = copy.deepcopy(loaded_config.get(SECURITY_POLICY_RULES, None))
        for ruledata in ruleconfigs:
            rule_key = list(ruledata.keys())[0]
            rule_config = ruledata[rule_key]
            rule_config["name"] = rule_key
            ruleconfig_clean[rule_key] = rule_config

        return ruleconfig_clean
    ############################################################################
    # Performance
    ############################################################################
    elif config_type in ["perfmgmtpolicysets", "perfmgmtpolicysetstacks"]:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(config_type, []))
        for data in configs:
            if not data: continue
            # Extract the first key as the name and its value as the config body
            name_key = list(data.keys())[0]
            config_body = data[name_key]
            config_body["name"] = name_key
            config_clean[name_key] = config_body

        return config_clean

#
# Function to update payload with contents of YAML for PUT operation
#
def update_payload(source, dest):
    for key in source.keys():
        dest[key] = source[key]

    return dest


#
# Function to convert [] to None - finddiff issue
#
def update_rule(rule_config):
    ruleconfig = copy.deepcopy(rule_config)
    paths_allowed = ruleconfig.get("paths_allowed", None)
    for item in paths_allowed.keys():
        if paths_allowed[item] is None:
            continue

        elif len(paths_allowed[item]) == 0:
            paths_allowed[item] = None
            ruleconfig["paths_allowed"] = paths_allowed
        else:
            continue

    return ruleconfig


def update_stack(stack_config):
    stackconfig = copy.deepcopy(stack_config)
    policyset_ids = stackconfig.get("policyset_ids", None)
    if len(policyset_ids) == 0:
        stackconfig["policyset_ids"] = None

    return stackconfig


#
# Update Path Policy, Rules & Stack Configs
#
def push_policy_path(cgx_session, loaded_config):
    ############################################################################
    # Path Set
    ############################################################################
    pathsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_POLICY_SETS)
    for pathsetname in pathsetconfig_yaml.keys():

        set_yaml = pathsetconfig_yaml[pathsetname]
        if pathsetname in nwpolicyset_name_config.keys():
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=NETWORK_POLICY_RULES)
            if NETWORK_POLICY_RULES in set_yaml.keys():
                del set_yaml[NETWORK_POLICY_RULES]

            set_ctrl = nwpolicyset_name_config[pathsetname]
            confdelta = compareconf(set_yaml, set_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # Path Set - Update
                ############################################################################
                data = update_payload(set_yaml, set_ctrl)
                resp = cgx_session.put.networkpolicysets(networkpolicyset_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated Path Set: {}".format(pathsetname))
                else:
                    print("ERR: Could not update Path Set: {}".format(pathsetname))
                    print(resp.cgx_content)

            else:
                ############################################################################
                # Path Set - No Changes detected
                ############################################################################
                print("No Changes to Path Set: {}".format(pathsetname))

            ############################################################################
            # Path Rules
            ############################################################################
            rules_ctrl = {}
            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=set_ctrl["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                for rule in ruleslist:
                    rules_ctrl[rule["name"]] = rule
            else:
                print("ERR: Could not retrieve rules for Path Policy Set: {}".format(pathsetname))
                print(resp.cgx_content)

            for rulename in rules_yaml.keys():
                rule_yaml = rules_yaml[rulename]
                rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=PATH)
                rule_data_yaml = update_rule(rule_data_yaml)

                if rulename in rules_ctrl.keys():
                    rule_ctrl = rules_ctrl[rulename]
                    rulediff = compareconf(rule_data_yaml, rule_ctrl)
                    if len(rulediff) > 0:
                        ############################################################################
                        # Path Rules - Update
                        ############################################################################
                        ruledata = update_payload(rule_data_yaml, rule_ctrl)
                        resp = cgx_session.put.networkpolicyrules(networkpolicyset_id=set_ctrl["id"], networkpolicyrule_id=ruledata["id"], data=ruledata)
                        if resp.cgx_status:
                            print("\tUpdated Rule: {}".format(rulename))
                        else:
                            print("ERR: Could not update Rule: {}".format(rulename))
                            print(resp.cgx_content)
                    else:
                        ############################################################################
                        # Path Rules - No Changes detected
                        ############################################################################
                        print("\tNo Changes to Rule: {}".format(rulename))

                else:
                    ############################################################################
                    # Path Rules - New Create
                    ############################################################################
                    resp = cgx_session.post.networkpolicyrules(networkpolicyset_id=set_ctrl["id"], data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        print(resp.cgx_content) # This fixes the NameError

            ############################################################################
            # Path Rules - Delete
            ############################################################################
            for rulename in rules_ctrl.keys():
                if rulename not in rules_yaml.keys():
                    data = rules_ctrl[rulename]
                    resp = cgx_session.delete.networkpolicyrules(networkpolicyset_id=set_ctrl["id"], networkpolicyrule_id=data["id"])
                    if resp.cgx_status:
                        print("\tDeleted Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not delete Rule: {}".format(rulename))
                        print(resp.cgx_content)

        else:
            ############################################################################
            # Path Set - New Create
            ############################################################################
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=NETWORK_POLICY_RULES)
            if NETWORK_POLICY_RULES in set_yaml.keys():
                del set_yaml[NETWORK_POLICY_RULES]

            resp = cgx_session.post.networkpolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created Path Set: {}".format(pathsetname))
                set_id = resp.cgx_content.get("id", None)
                nwpolicyset_id_name[set_id] = pathsetname
                nwpolicyset_name_id[pathsetname] = set_id
                for rulename in rules_yaml.keys():
                    rule_yaml = rules_yaml[rulename]
                    rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=PATH)
                    rule_data_yaml = update_rule(rule_data_yaml)

                    resp = cgx_session.post.networkpolicyrules(networkpolicyset_id=set_id, data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        print(resp.cgx_content)


            else:
                print("ERR: Could not create Path Set: {}".format(pathsetname))
                print(resp.cgx_content)


    ############################################################################
    # Path Stack
    ############################################################################
    pathstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_POLICY_STACKS)
    for pathstackname in pathstacktconfig_yaml.keys():

        stack_yaml = pathstacktconfig_yaml[pathstackname]
        # --- THE 3-LINE FIX FOR PATH STACKS ---
        # Force the script to use the Name so translate_stack fetches the fresh ID
        expected_name = pathstackname.replace(" (Simple)", "") + " Default Rule Policy Set (Simple)"
        stack_yaml["defaultrule_policyset_id"] = expected_name
        #
        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=PATH)
        stack_data_yaml = update_stack(stack_data_yaml)
        if pathstackname in nwpolicystack_name_config.keys():
            stack_ctrl = nwpolicystack_name_config[pathstackname]

            confdelta = compareconf(stack_data_yaml, stack_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # Path Stack - Update
                ############################################################################
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.networkpolicysetstacks(networkpolicysetstack_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated Path Stack: {} ".format(pathstackname))
                else:
                    print("ERR: Could not update Path Stack: {}".format(pathstackname))
                    print(resp.cgx_content)

            else:
                ############################################################################
                # Path Stack - No Changes detected
                ############################################################################
                print("No Changes to Path Stack: {}".format(pathstackname))

        else:
            ############################################################################
            # Path Stack - New Create
            ############################################################################
            resp = cgx_session.post.networkpolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status:
                    print("Created Path Stack: {}".format(pathstackname))
            else:
                print("ERR: Could not create Path Stack: {}".format(pathstackname))
                print(resp.cgx_content)

    ############################################################################
    # Path Stack - Delete
    ############################################################################
    for pathstackname in nwpolicystack_name_config.keys():
        if pathstackname not in pathstacktconfig_yaml.keys():
            data = nwpolicystack_name_config[pathstackname]
            resp = cgx_session.delete.networkpolicysetstacks(networkpolicysetstack_id=data["id"])
            if resp.cgx_status:
                print("Deleted Path Stack: {}".format(pathstackname))
            else:
                print("ERR: Could not delete Path Stack: {}".format(pathstackname))
                print(resp.cgx_content)

    ############################################################################
    # Path Set - Delete
    ############################################################################
    for pathsetname in nwpolicyset_name_config.keys():
        if pathsetname not in pathsetconfig_yaml.keys():
            data = nwpolicyset_name_config[pathsetname]
            resp = cgx_session.delete.networkpolicysets(networkpolicyset_id=data["id"])
            if resp.cgx_status:
                print("Deleted Path Set: {}".format(pathsetname))
            else:
                print("ERR: Could not delete Path Set: {}".format(pathsetname))
                print(resp.cgx_content)

    return

#
# Update QoS Policy, Rules & Stack Configs

def push_policy_qos(cgx_session, loaded_config):
    ############################################################################
    # QoS Set
    ############################################################################
    qossetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=PRIORITY_POLICY_SETS)
    for qossetname in qossetconfig_yaml.keys():

        set_yaml = qossetconfig_yaml[qossetname]
        if qossetname in qospolicyset_name_config.keys():
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=PRIORITY_POLICY_RULES)
            if PRIORITY_POLICY_RULES in set_yaml.keys():
                del set_yaml[PRIORITY_POLICY_RULES]

            set_ctrl = qospolicyset_name_config[qossetname]
            confdelta = compareconf(set_yaml, set_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # QoS Set - Update
                ############################################################################
                data = update_payload(set_yaml, set_ctrl)
                resp = cgx_session.put.prioritypolicysets(prioritypolicyset_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated QoS Set: {}".format(qossetname))
                else:
                    print("ERR: Could not update QoS Set: {}".format(qossetname))
                    print(resp.cgx_content)

            else:
                ############################################################################
                # QoS Set - No Changes detected
                ############################################################################
                print("No Changes to QoS Set: {}".format(qossetname))

            ############################################################################
            # QoS Rules
            ############################################################################
            rules_ctrl = {}
            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=set_ctrl["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                for rule in ruleslist:
                    rules_ctrl[rule["name"]] = rule
            else:
                print("ERR: Could not retrieve rules for Priority Policy Set: {}".format(qossetname))
                print(resp.cgx_content)

            for rulename in rules_yaml.keys():
                rule_yaml = rules_yaml[rulename]
                rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=QOS)

                if rulename in rules_ctrl.keys():
                    rule_ctrl = rules_ctrl[rulename]
                    rulediff = compareconf(rule_data_yaml, rule_ctrl)
                    if len(rulediff) > 0:
                        ############################################################################
                        # QoS Rules - Update
                        ############################################################################
                        ruledata = update_payload(rule_data_yaml, rule_ctrl)
                        resp = cgx_session.put.prioritypolicyrules(prioritypolicyset_id=set_ctrl["id"], prioritypolicyrule_id=ruledata["id"], data=ruledata)
                        if resp.cgx_status:
                            print("\tUpdated Rule: {}".format(rulename))
                        else:
                            print("ERR: Could not update Rule: {}".format(rulename))
                            print(resp.cgx_content)
                    else:
                        ############################################################################
                        # QoS Rules - No Changes detected
                        ############################################################################
                        print("\tNo Changes to Rule: {}".format(rulename))

                else:
                    ############################################################################
                    # QoS Rules - New Create
                    ############################################################################
                    resp = cgx_session.post.prioritypolicyrules(prioritypolicyset_id=set_ctrl["id"], data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        print(resp.cgx_content)

            ############################################################################
            # QoS Rules - Delete
            ############################################################################
            for rulename in rules_ctrl.keys():
                if rulename not in rules_yaml.keys():
                    data = rules_ctrl[rulename]
                    resp = cgx_session.delete.prioritypolicyrules(prioritypolicyset_id=set_ctrl["id"], prioritypolicyrule_id=data["id"])
                    if resp.cgx_status:
                        print("\tDeleted Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not delete Rule: {}".format(rulename))
                        print(resp.cgx_content)

        else:
            ############################################################################
            # QoS Set - New Create
            ############################################################################
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=PRIORITY_POLICY_RULES)
            if PRIORITY_POLICY_RULES in set_yaml.keys():
                del set_yaml[PRIORITY_POLICY_RULES]

            resp = cgx_session.post.prioritypolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created QoS Set: {}".format(qossetname))
                set_id = resp.cgx_content.get("id", None)
                qospolicyset_id_name[set_id] = qossetname
                qospolicyset_name_id[qossetname] = set_id
                template = resp.cgx_content.get("template", None)
                if template:
                    ############################################################################
                    # If a set is created from template, 37 rules are auto created
                    # Retrieve rules from the set and compare with YAML for updates
                    ############################################################################
                    rules_ctrl = {}
                    resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=set_id)
                    if resp.cgx_status:
                        ruleslist = resp.cgx_content.get("items", None)
                        for rule in ruleslist:
                            rules_ctrl[rule["name"]] = rule
                    else:
                        print("ERR: Could not retrieve rules for Priority Policy Set: {}".format(qossetname))
                        print(resp.cgx_content)

                    for rulename in rules_yaml.keys():
                        rule_yaml = rules_yaml[rulename]
                        rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=QOS)

                        if rulename in rules_ctrl.keys():
                            rule_ctrl = rules_ctrl[rulename]
                            rulediff = compareconf(rule_data_yaml, rule_ctrl)
                            if len(rulediff) > 0:
                                ############################################################################
                                # QoS Rules - Update
                                ############################################################################
                                ruledata = update_payload(rule_data_yaml, rule_ctrl)
                                resp = cgx_session.put.prioritypolicyrules(prioritypolicyset_id=set_id,
                                                                           prioritypolicyrule_id=ruledata["id"],
                                                                           data=ruledata)
                                if resp.cgx_status:
                                    print("\tUpdated Rule: {}".format(rulename))
                                else:
                                    print("ERR: Could not update Rule: {}".format(rulename))
                                    print(resp.cgx_content)
                            else:
                                ############################################################################
                                # QoS Rules - No Changes detected
                                ############################################################################
                                print("\tNo Changes to Rule: {}".format(rulename))

                        else:
                            ############################################################################
                            # QoS Rules - New Create
                            ############################################################################
                            resp = cgx_session.post.prioritypolicyrules(prioritypolicyset_id=set_id,
                                                                        data=rule_data_yaml)
                            if resp.cgx_status:
                                print("\tCreated Rule: {}".format(rulename))
                            else:
                                print("ERR: Could not create Rule: {}".format(rulename))
                                print(resp.cgx_content)

                    ############################################################################
                    # QoS Rules - Delete
                    ############################################################################
                    for rulename in rules_ctrl.keys():
                        if rulename not in rules_yaml.keys():
                            data = rules_ctrl[rulename]
                            resp = cgx_session.delete.prioritypolicyrules(prioritypolicyset_id=set_id,
                                                                          prioritypolicyrule_id=data["id"])
                            if resp.cgx_status:
                                print("\tDeleted Rule: {}".format(rulename))
                            else:
                                print("ERR: Could not delete Rule: {}".format(rulename))
                                print(resp.cgx_content)

                else:
                    ############################################################################
                    # QoS Rules - Create
                    ############################################################################
                    for rulename in rules_yaml.keys():
                        rule_yaml = rules_yaml[rulename]
                        rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=QOS)

                        resp = cgx_session.post.prioritypolicyrules(prioritypolicyset_id=set_id, data=rule_data_yaml)
                        if resp.cgx_status:
                            print("\tCreated Rule: {}".format(rulename))
                        else:
                            print("ERR: Could not create Rule: {}".format(rulename))
                            print(resp.cgx_content)

            else:
                print("ERR: Could not create QoS Set: {}".format(qossetname))
                print(resp.cgx_content)

    ############################################################################
    # QoS Stack
    ############################################################################
    qosstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=PRIORITY_POLICY_STACKS)
    for qosstackname in qosstacktconfig_yaml.keys():

        stack_yaml = qosstacktconfig_yaml[qosstackname]

        # --- ADD THESE 3 LINES ---
        # Overwrite the dead YAML ID with the exact string NAME of the Default Rule Set.
        # This forces 'translate_stack' to fetch the brand new ID for us.
        expected_name = qosstackname.replace(" (Simple)", "") + " Default Rule Policy Set (Simple)"
        stack_yaml["defaultrule_policyset_id"] = expected_name
        # -------------------------

        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=QOS)
        stack_data_yaml = update_stack(stack_data_yaml)
        # --- ADD THESE DEBUG PRINTS HERE ---
        print("\n[DEBUG] Pushing Stack: {}".format(qosstackname))
        print("  -> Default Policy Set ID: {}".format(stack_data_yaml.get("defaultrule_policyset_id")))
        print("  -> Policy Set List IDs: {}".format(stack_data_yaml.get("policyset_ids")))
        if qosstackname in qospolicystack_name_config.keys():
            stack_ctrl = qospolicystack_name_config[qosstackname]

            confdelta = compareconf(stack_data_yaml, stack_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # QoS Stack - Update
                ############################################################################
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.prioritypolicysetstacks(prioritypolicysetstack_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated QoS Stack: {} ".format(qosstackname))
                else:
                    print("ERR: Could not update QoS Stack: {}".format(qosstackname))
                    print(resp.cgx_content)

            else:
                ############################################################################
                # QoS Stack - No Changes detected
                ############################################################################
                print("No Changes to QoS Stack: {}".format(qosstackname))

        else:
            ############################################################################
            # QoS Stack - New Create
            ############################################################################
            resp = cgx_session.post.prioritypolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status:
                    print("Created QoS Stack: {}".format(qosstackname))
            else:
                print("ERR: Could not create QoS Stack: {}".format(qosstackname))
                print(resp.cgx_content)

    ############################################################################
    # QoS Stack - Delete
    ############################################################################
    for qosstackname in qospolicystack_name_config.keys():
        if qosstackname not in qosstacktconfig_yaml.keys():
            data = qospolicystack_name_config[qosstackname]
            # --- ADD THIS 1 LINE ---
            # If the cloud says this is a system default, skip deleting it!
            if data.get("default_policysetstack") is True: continue
            resp = cgx_session.delete.prioritypolicysetstacks(prioritypolicysetstack_id=data["id"])
            if resp.cgx_status:
                print("Deleted QoS Stack: {}".format(qosstackname))
            else:
                print("ERR: Could not delete QoS Stack: {}".format(qosstackname))
                print(resp.cgx_content)

    ############################################################################
    # QoS Set - Delete
    ############################################################################
    for qossetname in qospolicyset_name_config.keys():
        if qossetname not in qossetconfig_yaml.keys():
            data = qospolicyset_name_config[qossetname]
            # --- ADD THIS 1 LINE ---
            if data.get("defaultrule_policyset") is True: continue
            resp = cgx_session.delete.prioritypolicysets(prioritypolicyset_id=data["id"])
            if resp.cgx_status:
                print("Deleted QoS Set: {}".format(qossetname))
            else:
                print("ERR: Could not delete QoS Set: {}".format(qossetname))
                print(resp.cgx_content)
    return


### Update Security Policy, Rules, Stack Configs
def push_policy_security(cgx_session, loaded_config):
    ngfwsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_POLICY_SETS)
    
    ############################################################################
    # 1. Security Set - Create & Update
    ############################################################################
    for ngfwsetname in ngfwsetconfig_yaml.keys():
        set_yaml = ngfwsetconfig_yaml[ngfwsetname]
        
        # Extract rules and remove from set_yaml to avoid PUT/POST payload errors
        rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=SECURITY_POLICY_RULES)
        if SECURITY_POLICY_RULES in set_yaml.keys():
            del set_yaml[SECURITY_POLICY_RULES]

        if ngfwsetname in ngfwpolicyset_name_config.keys():
            # --- EXISTING SET LOGIC ---
            set_ctrl = ngfwpolicyset_name_config[ngfwsetname]
            
            # Sync Rules for existing set
            rules_ctrl = {}
            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"])
            if resp.cgx_status:
                for rule in resp.cgx_content.get("items", []):
                    rules_ctrl[rule["name"]] = rule

            for rulename in rules_yaml.keys():
                rule_data_yaml = translate_rule(rule=rules_yaml[rulename], action=N2ID, rule_type=SECURITY)
                if rulename in rules_ctrl.keys():
                    rule_ctrl = rules_ctrl[rulename]
                    if len(compareconf(rule_data_yaml, rule_ctrl)) > 0:
                        ruledata = update_payload(rule_data_yaml, rule_ctrl)
                        r_resp = cgx_session.put.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"], ngfwsecuritypolicyrule_id=ruledata["id"], data=ruledata)
                        if r_resp.cgx_status: print("\tUpdated Rule: {}".format(rulename))
                else:
                    r_resp = cgx_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"], data=rule_data_yaml)
                    if r_resp.cgx_status: print("\tCreated Rule: {}".format(rulename))

            # Delete Orphaned Rules
            for rulename in rules_ctrl.keys():
                if rulename not in rules_yaml.keys():
                    cgx_session.delete.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"], ngfwsecuritypolicyrule_id=rules_ctrl[rulename]["id"])
                    print("\tDeleted Rule: {}".format(rulename))

            # Sync Set Attributes
            set_data_yaml = translate_set(setdata=set_yaml, setid=set_ctrl["id"], set_type=SECURITY, action=N2ID)
            if "ngfwsecuritypolicyrules" in set_data_yaml: del set_data_yaml["ngfwsecuritypolicyrules"]
            
            is_default_set = set_data_yaml.get("defaultrule_policyset", False)
            if len(compareconf(set_data_yaml, set_ctrl)) > 0:
                data = update_payload(set_data_yaml, set_ctrl)
                if is_default_set and "policyrule_order" in data:
                    del data["policyrule_order"] # Strip order from default sets
                
                resp = cgx_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=data["id"], data=data)
                if resp.cgx_status: print("Updated Security Set: {}".format(ngfwsetname))

        else:
            # --- NEW SET LOGIC (THE FIX) ---
            policyrule_order = set_yaml.get("policyrule_order", None)
            set_yaml["policyrule_order"] = None
            policyrule_order = set_yaml.get("policyrule_order", None)
            set_yaml["policyrule_order"] = None
            
            # --- ADD THIS LINE HERE ---
            set_yaml["clone_from"] = None
            resp = cgx_session.post.ngfwsecuritypolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created Security Set: {}".format(ngfwsetname))
                set_id = resp.cgx_content.get("id", None)
                
                # MEMORY UPDATE: Save new ID so Stack can find it!
                ngfwpolicyset_id_name[set_id] = ngfwsetname
                ngfwpolicyset_name_id[ngfwsetname] = set_id
                
                # AUTO-RULE HANDLER: Fetch rules the API just created automatically
                rules_ctrl = {}
                r_resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_id)
                if r_resp.cgx_status:
                    for rule in r_resp.cgx_content.get("items", []):
                        rules_ctrl[rule["name"]] = rule

                ngfwrule_name_id = {}
                for rulename in rules_yaml.keys():
                    rule_data_yaml = translate_rule(rule=rules_yaml[rulename], action=N2ID, rule_type=SECURITY)
                    
                    # If rule already exists (auto-generated), PUT. Otherwise, POST.
                    if rulename in rules_ctrl:
                        ruledata = update_payload(rule_data_yaml, rules_ctrl[rulename])
                        resp_rule = cgx_session.put.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_id, ngfwsecuritypolicyrule_id=ruledata["id"], data=ruledata)
                        if resp_rule.cgx_status:
                            print("\tUpdated Auto-Rule: {}".format(rulename))
                            ngfwrule_name_id[rulename] = ruledata["id"]
                    else:
                        resp_rule = cgx_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_id, data=rule_data_yaml)
                        if resp_rule.cgx_status:
                            print("\tCreated Rule: {}".format(rulename))
                            ngfwrule_name_id[rulename] = resp_rule.cgx_content.get("id", None)
                        else:
                            print("\tERR: Failed to create Rule {}: {}".format(rulename, resp_rule.cgx_content))

                # Finalize Order
                if policyrule_order:
                    ruleids = [ngfwrule_name_id[rname] for rname in policyrule_order if rname in ngfwrule_name_id]
                    cgx_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=set_id, data={"id": set_id, "policyrule_order": ruleids})
            else:
                print("ERR: Could not create Security Set {}: {}".format(ngfwsetname, resp.cgx_content))

    ############################################################################
    # 2. Security Stack - ID Swap & Create
    ############################################################################
    
    ngfwstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_POLICY_STACKS)
    for nfgwstackname in ngfwstacktconfig_yaml.keys():
        stack_yaml = ngfwstacktconfig_yaml[nfgwstackname]

        # ID SWAP: Force translator to use the Name, so it fetches the live UUID
        expected_name = nfgwstackname.replace(" (Simple)", "") + " Default Rule Policy Set (Simple)"
        stack_yaml["defaultrule_policyset_id"] = expected_name

        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=SECURITY)
        stack_data_yaml = update_stack(stack_data_yaml)

        if nfgwstackname in ngfwpolicystack_name_config.keys():
            stack_ctrl = ngfwpolicystack_name_config[nfgwstackname]
            if len(compareconf(stack_data_yaml, stack_ctrl)) > 0:
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=data["id"], data=data)
                if resp.cgx_status: print("Updated Security Stack: {}".format(nfgwstackname))
            else:
                print("No Changes to Security Stack: {}".format(nfgwstackname))
        else:
            resp = cgx_session.post.ngfwsecuritypolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status:
                print("Created Security Stack: {}".format(nfgwstackname))
            else:
                print("ERR: Could not create Security Stack {}: {}".format(nfgwstackname, resp.cgx_content))

    ############################################################################
    # 3. Cleanup - With Safety Shields
    ############################################################################
    for name, ctrl_data in ngfwpolicystack_name_config.items():
        if ctrl_data.get("default_policysetstack") is True: continue # SHIELD
        if name not in ngfwstacktconfig_yaml:
            cgx_session.delete.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=ctrl_data["id"])
            print("Deleted Security Stack: {}".format(name))

    for name, ctrl_data in ngfwpolicyset_name_config.items():
        if ctrl_data.get("defaultrule_policyset") is True: continue # SHIELD
        if name not in ngfwsetconfig_yaml:
            cgx_session.delete.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=ctrl_data["id"])
            print("Deleted Security Set: {}".format(name))

    return

### Update Nat - NEW
def push_policy_nat(cgx_session, loaded_config):
    # Memory maps for the ID Handshake
    fresh_id_map = {}
    natpolicyset_id_name = {}
    natpolicyset_name_id = {}

    ############################################################################
    # 1. NAT Set - Create & Update
    ############################################################################
    natsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type="natpolicysets")
    if not natsetconfig_yaml:
        print("INFO: No NAT Sets found in YAML.")
        natsetconfig_yaml = {}

    for natsetname, set_yaml in natsetconfig_yaml.items():
        # Handle rule formatting (list of dicts from the pull script)
        raw_rules = set_yaml.get("natpolicyrules", [])
        if "natpolicyrules" in set_yaml:
            del set_yaml["natpolicyrules"]
            
        if isinstance(raw_rules, dict):
            rules_yaml_list = [{k: v} for k, v in raw_rules.items()]
        else:
            rules_yaml_list = raw_rules
            
        # Extract DUAL rule orders specific to NAT
        dst_order = set_yaml.get("destination_zone_policyrule_order", [])
        src_order = set_yaml.get("source_zone_policyrule_order", [])
        set_yaml["destination_zone_policyrule_order"] = None
        set_yaml["source_zone_policyrule_order"] = None

        # GOLDEN RULE #1: The Clone Wiper
        set_yaml["clone_from"] = None

        if natsetname in natpolicyset_name_config.keys():
            # --- EXISTING SET ---
            set_ctrl = natpolicyset_name_config[natsetname]
            set_id = set_ctrl["id"]
            
            fresh_id_map[natsetname] = set_id
            natpolicyset_id_name[set_id] = natsetname
            natpolicyset_name_id[natsetname] = set_id

            if len(compareconf(set_yaml, set_ctrl)) > 0:
                data = update_payload(set_yaml, set_ctrl)
                # Strip order from payload so we don't trigger mismatch errors on PUT
                if "destination_zone_policyrule_order" in data: del data["destination_zone_policyrule_order"]
                if "source_zone_policyrule_order" in data: del data["source_zone_policyrule_order"]
                
                resp = cgx_session.put.natpolicysets(natpolicyset_id=set_id, data=data)
                if resp.cgx_status: print(f"Updated NAT Set: {natsetname}")

        else:
            # --- NEW SET ---
            resp = cgx_session.post.natpolicysets(data=set_yaml)
            if resp.cgx_status:
                print(f"Created NAT Set: {natsetname}")
                set_id = resp.cgx_content.get("id")
                
                # MEMORY UPDATE
                fresh_id_map[natsetname] = set_id
                natpolicyset_id_name[set_id] = natsetname
                natpolicyset_name_id[natsetname] = set_id
            else:
                print(f"ERR: Could not create NAT Set {natsetname}: {resp.cgx_content}")
                continue

        ############################################################################
        # NAT Rules
        ############################################################################
        # GOLDEN RULE #2: Catch Auto-Created Rules
        rules_ctrl = {}
        r_resp = cgx_session.get.natpolicyrules(natpolicyset_id=set_id)
        if r_resp.cgx_status:
            for rule in r_resp.cgx_content.get("items", []):
                rules_ctrl[rule["name"]] = rule

        nat_rule_name_id = {}
        rule_names_in_yaml = []

        for r_entry in rules_yaml_list:
            rulename = list(r_entry.keys())[0]
            rule_data = r_entry[rulename]
            rule_names_in_yaml.append(rulename)

            # Standard Translation (Zones, Prefixes)
            try:
                rule_data = translate_rule(rule=rule_data, action=N2ID, rule_type="nat")
            except:
                pass 

            if rulename in rules_ctrl:
                # RULE EXISTS: PUT
                r_ctrl = rules_ctrl[rulename]
                if len(compareconf(rule_data, r_ctrl)) > 0:
                    r_payload = update_payload(rule_data, r_ctrl)
                    resp_rule = cgx_session.put.natpolicyrules(natpolicyset_id=set_id, natpolicyrule_id=r_payload["id"], data=r_payload)
                    if resp_rule.cgx_status:
                        print(f"\tUpdated Rule: {rulename}")
                        nat_rule_name_id[rulename] = r_payload["id"]
                    else:
                        print(f"\tERR: Failed to update Rule {rulename}: {resp_rule.cgx_content}")
                else:
                    nat_rule_name_id[rulename] = r_ctrl["id"]
            else:
                # RULE MISSING: POST
                resp_rule = cgx_session.post.natpolicyrules(natpolicyset_id=set_id, data=rule_data)
                if resp_rule.cgx_status:
                    print(f"\tCreated Rule: {rulename}")
                    nat_rule_name_id[rulename] = resp_rule.cgx_content.get("id")
                else:
                    print(f"\tERR: Failed to create Rule {rulename}: {resp_rule.cgx_content}")

        # Finalize DUAL Rule Order for New/Updated Sets
        if dst_order or src_order:
            valid_dst = [nat_rule_name_id[r] for r in dst_order if r in nat_rule_name_id] if dst_order else []
            valid_src = [nat_rule_name_id[r] for r in src_order if r in nat_rule_name_id] if src_order else []
            
            cgx_session.put.natpolicysets(natpolicyset_id=set_id, data={
                "id": set_id, 
                "destination_zone_policyrule_order": valid_dst,
                "source_zone_policyrule_order": valid_src
            })

        # Delete Orphaned Rules
        for rulename, rule_data in rules_ctrl.items():
            if rulename not in rule_names_in_yaml:
                cgx_session.delete.natpolicyrules(natpolicyset_id=set_id, natpolicyrule_id=rule_data["id"])
                print(f"\tDeleted Orphaned Rule: {rulename}")

    ############################################################################
    # 2. NAT Stack - ID Swap & Create
    ############################################################################
    natstackconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type="natpolicysetstacks")
    if not natstackconfig_yaml:
        natstackconfig_yaml = {}
        
    for natstackname, stack_yaml in natstackconfig_yaml.items():

        # GOLDEN RULE #3: The ID Swap (NAT Stacks ONLY use policyset_ids)
        if stack_yaml.get("policyset_ids"):
            new_ps_list = []
            for item in stack_yaml["policyset_ids"]:
                item_name = natpolicyset_id_name.get(str(item), item)
                new_ps_list.append(fresh_id_map.get(item_name, item))
            stack_yaml["policyset_ids"] = new_ps_list

        try:
            stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type="nat")
            stack_data_yaml = update_stack(stack_data_yaml)
        except:
            stack_data_yaml = stack_yaml

        if natstackname in natpolicystack_name_config.keys():
            stack_ctrl = natpolicystack_name_config[natstackname]
            if len(compareconf(stack_data_yaml, stack_ctrl)) > 0:
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.natpolicysetstacks(natpolicysetstack_id=data["id"], data=data)
                if resp.cgx_status: print(f"Updated NAT Stack: {natstackname}")
            else:
                print(f"No Changes to NAT Stack: {natstackname}")
        else:
            resp = cgx_session.post.natpolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status: print(f"Created NAT Stack: {natstackname}")
            else: print(f"ERR: Could not create NAT Stack {natstackname}: {resp.cgx_content}")

    ############################################################################
    # 3. Cleanup - Safety Shields
    ############################################################################
    # GOLDEN RULE #4: Protect the Defaults
    for name, ctrl_data in natpolicystack_name_config.items():
        if ctrl_data.get("default_policysetstack") is True: continue
        if name not in natstackconfig_yaml:
            cgx_session.delete.natpolicysetstacks(natpolicysetstack_id=ctrl_data["id"])
            print(f"Deleted Orphaned NAT Stack: {name}")

    for name, ctrl_data in natpolicyset_name_config.items():
        if ctrl_data.get("defaultrule_policyset") is True: continue
        if name not in natsetconfig_yaml:
            cgx_session.delete.natpolicysets(natpolicyset_id=ctrl_data["id"])
            print(f"Deleted Orphaned NAT Set: {name}")

    return

##### PERFORMANCE POLICY - NEW
def push_policy_performance(cgx_session, loaded_config):
    # Memory maps for the ID Handshake
    fresh_id_map = {}
    perfmgmtpolicyset_id_name = {}
    perfmgmtpolicyset_name_id = {}

    ############################################################################
    # 1. Performance Set - Create & Update
    ############################################################################
    perfsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type="perfmgmtpolicysets")
    if not perfsetconfig_yaml:
        print("INFO: No Performance Sets found in YAML.")
        perfsetconfig_yaml = {}

    for perfsetname in perfsetconfig_yaml.keys():
        set_yaml = perfsetconfig_yaml[perfsetname]
        
        # YAML formatting: Extract the list of rule dicts
        rules_yaml_list = set_yaml.get("perfmgmtpolicyrules", [])
        if "perfmgmtpolicyrules" in set_yaml:
            del set_yaml["perfmgmtpolicyrules"]
            
        # Extract rule order
        rule_order = set_yaml.get("link_health_policyrule_order", None)
        set_yaml["link_health_policyrule_order"] = None

        # GOLDEN RULE #1: The Clone Wiper
        set_yaml["clone_from"] = None

        if perfsetname in perfmgmtpolicyset_name_config.keys():
            # --- EXISTING SET ---
            set_ctrl = perfmgmtpolicyset_name_config[perfsetname]
            set_id = set_ctrl["id"]
            
            fresh_id_map[perfsetname] = set_id
            perfmgmtpolicyset_id_name[set_id] = perfsetname
            perfmgmtpolicyset_name_id[perfsetname] = set_id

            if len(compareconf(set_yaml, set_ctrl)) > 0:
                data = update_payload(set_yaml, set_ctrl)
                if data.get("defaultrule_policyset") is True and "link_health_policyrule_order" in data:
                    del data["link_health_policyrule_order"]
                resp = cgx_session.put.perfmgmtpolicysets(perfmgmtpolicyset_id=set_id, data=data)
                if resp.cgx_status: print("Updated Performance Set: {}".format(perfsetname))

        else:
            # --- NEW SET ---
            resp = cgx_session.post.perfmgmtpolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created Performance Set: {}".format(perfsetname))
                set_id = resp.cgx_content.get("id")
                
                # MEMORY UPDATE
                fresh_id_map[perfsetname] = set_id
                perfmgmtpolicyset_id_name[set_id] = perfsetname
                perfmgmtpolicyset_name_id[perfsetname] = set_id
            else:
                print("ERR: Could not create Perf Set {}: {}".format(perfsetname, resp.cgx_content))
                continue

        ############################################################################
        # Performance Rules
        ############################################################################
        # GOLDEN RULE #2: Catch Auto-Created Rules (Like "Default Performance Policy Rule for All Apps")
        rules_ctrl = {}
        r_resp = cgx_session.get.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=set_id)
        if r_resp.cgx_status:
            for rule in r_resp.cgx_content.get("items", []):
                rules_ctrl[rule["name"]] = rule

        perf_rule_name_id = {}
        rule_names_in_yaml = []

        for r_entry in rules_yaml_list:
            rulename = list(r_entry.keys())[0]
            rule_data = r_entry[rulename]
            rule_names_in_yaml.append(rulename)

            # Map Threshold Profile Names -> IDs
            tp_name = rule_data.get("thresholdprofile_id")
            if tp_name and tp_name in perf_threshold_name_id:
                rule_data["thresholdprofile_id"] = perf_threshold_name_id[tp_name]

            # Use master translator for apps, etc.
            try:
                rule_data = translate_rule(rule=rule_data, action=N2ID, rule_type=PERFORMANCE)
            except:
                pass 

            if rulename in rules_ctrl:
                # RULE EXISTS: PUT
                r_ctrl = rules_ctrl[rulename]
                if len(compareconf(rule_data, r_ctrl)) > 0:
                    r_payload = update_payload(rule_data, r_ctrl)
                    resp_rule = cgx_session.put.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=set_id, perfmgmtpolicyrule_id=r_payload["id"], data=r_payload)
                    if resp_rule.cgx_status:
                        print("\tUpdated Rule: {}".format(rulename))
                        perf_rule_name_id[rulename] = r_payload["id"]
                    else:
                        print("\tERR: Failed to update Rule {}: {}".format(rulename, resp_rule.cgx_content))
                else:
                    perf_rule_name_id[rulename] = r_ctrl["id"]
            else:
                # RULE MISSING: POST
                resp_rule = cgx_session.post.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=set_id, data=rule_data)
                if resp_rule.cgx_status:
                    print("\tCreated Rule: {}".format(rulename))
                    perf_rule_name_id[rulename] = resp_rule.cgx_content.get("id")
                else:
                    print("\tERR: Failed to create Rule {}: {}".format(rulename, resp_rule.cgx_content))

        # Finalize Rule Order
        if rule_order and set_yaml.get("defaultrule_policyset") is not True:
            valid_rule_ids = [perf_rule_name_id[rname] for rname in rule_order if rname in perf_rule_name_id]
            cgx_session.put.perfmgmtpolicysets(perfmgmtpolicyset_id=set_id, data={"id": set_id, "link_health_policyrule_order": valid_rule_ids})

        # Cleanup Orphaned Rules
        for rulename, rule_data in rules_ctrl.items():
            if rulename not in rule_names_in_yaml:
                cgx_session.delete.perfmgmtpolicysets_perfmgmtpolicyrules(perfmgmtpolicyset_id=set_id, perfmgmtpolicyrule_id=rule_data["id"])
                print("\tDeleted Orphaned Rule: {}".format(rulename))

    ############################################################################
    # 2. Performance Stack - ID Swap & Create
    ############################################################################
    perfstackconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type="perfmgmtpolicysetstacks")
    if not perfstackconfig_yaml:
        perfstackconfig_yaml = {}
        
    for perfstackname in perfstackconfig_yaml.keys():
        stack_yaml = perfstackconfig_yaml[perfstackname]

        # GOLDEN RULE #3: The Shared Default Set ID Swap
        global_default_name = "Default Performance Policy Set (Simple)"
        if global_default_name in fresh_id_map:
            stack_yaml["defaultrule_policyset_id"] = fresh_id_map[global_default_name]

        # Swap Custom Policy Set Lists
        if stack_yaml.get("policyset_ids"):
            new_ps_list = []
            for item in stack_yaml["policyset_ids"]:
                item_name = perfmgmtpolicyset_id_name.get(str(item), item)
                new_ps_list.append(fresh_id_map.get(item_name, item))
            stack_yaml["policyset_ids"] = new_ps_list

        try:
            stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=PERFORMANCE)
            stack_data_yaml = update_stack(stack_data_yaml)
        except:
            stack_data_yaml = stack_yaml

        if perfstackname in perfmgmtpolicystack_name_config.keys():
            stack_ctrl = perfmgmtpolicystack_name_config[perfstackname]
            if len(compareconf(stack_data_yaml, stack_ctrl)) > 0:
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.perfmgmtpolicysetstacks(perfmgmtpolicysetstack_id=data["id"], data=data)
                if resp.cgx_status: print("Updated Performance Stack: {}".format(perfstackname))
            else:
                print("No Changes to Performance Stack: {}".format(perfstackname))
        else:
            resp = cgx_session.post.perfmgmtpolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status: print("Created Performance Stack: {}".format(perfstackname))
            else: print("ERR: Could not create Perf Stack {}: {}".format(perfstackname, resp.cgx_content))

    ############################################################################
    # 3. Cleanup - Safety Shields
    ############################################################################
    # GOLDEN RULE #4: Protect the Defaults
    for name, ctrl_data in perfmgmtpolicystack_name_config.items():
        if ctrl_data.get("default_policysetstack") is True: continue
        if name not in perfstackconfig_yaml:
            cgx_session.delete.perfmgmtpolicysetstacks(perfmgmtpolicysetstack_id=ctrl_data["id"])
            print("Deleted Orphaned Performance Stack: {}".format(name))

    for name, ctrl_data in perfmgmtpolicyset_name_config.items():
        if ctrl_data.get("defaultrule_policyset") is True: continue
        if name not in perfsetconfig_yaml:
            cgx_session.delete.perfmgmtpolicysets(perfmgmtpolicyset_id=ctrl_data["id"])
            print("Deleted Orphaned Performance Set: {}".format(name))

    return


def go():
    ############################################################################
    # Begin Script, parse arguments.
    ############################################################################
    print("*******************************************"
          "\n{} [{}]\n{}\n"
          "*******************************************".format(SCRIPT_NAME, version, datetime.datetime.utcnow()))
    # Parse arguments
    parser = argparse.ArgumentParser(description="{0}.".format(SCRIPT_NAME))

    # Allow Controller modification and debug level sets.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. "
                                       "C-Prod: https://api.elcapitan.cloudgenix.com",
                                  default=None)

    # Commandline for entering PCM info
    policy_group = parser.add_argument_group('Policy Properties',
                                           'Information shared here will be used to query policies')
    policy_group.add_argument("--policytype", "-PT", help="Policy Type. Allowed values: path, qos, nat, security, all",
                              default=None)
    policy_group.add_argument("--filename","-F", help="File name. Provide the entire path", type=str,
                             default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    policytype = args['policytype']
    filename = args["filename"]

    if policytype is None:
        print("ERR: Please provide policytype")
        sys.exit()
    else:
        # --- ADD PERFORMANCE TO THIS LIST ---
        if policytype not in [PATH, QOS, NAT, SECURITY, PERFORMANCE, ALL]:
            print("ERR: Unsupported policy type")
            sys.exit()

    
    print("Tenant Info: {} [{}]".format(cgx_session.tenant_name, cgx_session.tenant_id))
    ############################################################################
    # Export data from YAML
    ############################################################################
    print("INFO: Extracting data from {}".format(filename))
    with open(filename, 'r') as datafile:
        loaded_config = yaml.safe_load(datafile)

    ############################################################################
    # Push Config
    ############################################################################
    ############################################################################
    # Create Translation Dicts
    ############################################################################

    if policytype == PATH:
        print("INFO: Building PATH Translation Dicts")
        create_global_dicts_path(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_path(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == QOS:
        print("INFO: Building QOS Translation Dicts")
        create_global_dicts_qos(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_qos(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == NAT:
        print("INFO: Building NAT Translation Dicts")
        create_global_dicts_nat(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_nat(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == SECURITY:
        print("INFO: Building SEC Translation Dicts")
        create_global_dicts_security(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_security(cgx_session=cgx_session, loaded_config=loaded_config)
    elif policytype == PERFORMANCE:
        print("INFO: Building PERF Translation Dicts")
        create_global_dicts_performance(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_performance(cgx_session=cgx_session, loaded_config=loaded_config)
    elif policytype == ALL:
        print("INFO: Building Translation Dicts")
        create_global_dicts_all(cgx_session=cgx_session)
        push_policy_path(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_qos(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_nat(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_security(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_performance(cgx_session=cgx_session, loaded_config=loaded_config) # <-- Added this!


if __name__ == "__main__":
    go()

