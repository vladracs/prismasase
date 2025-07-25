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


N2ID = "n2id"
ID2N = "id2n"

PATH = "path"
QOS = "qos"
NAT = "nat"
SECURITY = "security"
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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)
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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NW Policy Sets")
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)


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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)
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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve NW Policy Sets")
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)
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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)
    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        cloudgenix.jd_detailed(resp)


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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
        cloudgenix.jd_detailed(resp)

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
                    cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

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
                            cloudgenix.jd_detailed(resp)
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
                        cloudgenix.jd_detailed(resp)

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
                        cloudgenix.jd_detailed(resp)

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
                        cloudgenix.jd_detailed(resp)


            else:
                print("ERR: Could not create Path Set: {}".format(pathsetname))
                cloudgenix.jd_detailed(resp)


    ############################################################################
    # Path Stack
    ############################################################################
    pathstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_POLICY_STACKS)
    for pathstackname in pathstacktconfig_yaml.keys():

        stack_yaml = pathstacktconfig_yaml[pathstackname]
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
                    cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

    return


#
# Update QoS Policy, Rules & Stack Configs
#
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
                    cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

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
                            cloudgenix.jd_detailed(resp)
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
                        cloudgenix.jd_detailed(resp)

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
                        cloudgenix.jd_detailed(resp)

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
                        cloudgenix.jd_detailed(resp)

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
                                    cloudgenix.jd_detailed(resp)
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
                                cloudgenix.jd_detailed(resp)

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
                                cloudgenix.jd_detailed(resp)

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
                            cloudgenix.jd_detailed(resp)

            else:
                print("ERR: Could not create QoS Set: {}".format(qossetname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # QoS Stack
    ############################################################################
    qosstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=PRIORITY_POLICY_STACKS)
    for qosstackname in qosstacktconfig_yaml.keys():

        stack_yaml = qosstacktconfig_yaml[qosstackname]
        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=QOS)
        stack_data_yaml = update_stack(stack_data_yaml)
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
                    cloudgenix.jd_detailed(resp)

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
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # QoS Stack - Delete
    ############################################################################
    for qosstackname in qospolicystack_name_config.keys():
        if qosstackname not in qosstacktconfig_yaml.keys():
            data = qospolicystack_name_config[qosstackname]
            resp = cgx_session.delete.prioritypolicysetstacks(prioritypolicysetstack_id=data["id"])
            if resp.cgx_status:
                print("Deleted QoS Stack: {}".format(qosstackname))
            else:
                print("ERR: Could not delete QoS Stack: {}".format(qosstackname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # QoS Set - Delete
    ############################################################################
    for qossetname in qospolicyset_name_config.keys():
        if qossetname not in qossetconfig_yaml.keys():
            data = qospolicyset_name_config[qossetname]
            resp = cgx_session.delete.prioritypolicysets(prioritypolicyset_id=data["id"])
            if resp.cgx_status:
                print("Deleted QoS Set: {}".format(qossetname))
            else:
                print("ERR: Could not delete QoS Set: {}".format(qossetname))
                cloudgenix.jd_detailed(resp)
    return


def push_policy_nat(cgx_session, loaded_config):
    natsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_POLICY_SETS)
    ############################################################################
    # NAT Set
    ############################################################################
    for natsetname in natsetconfig_yaml.keys():
        set_yaml = natsetconfig_yaml[natsetname]
        if natsetname in natpolicyset_name_config.keys():
            set_ctrl = natpolicyset_name_config[natsetname]
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=NAT_POLICY_RULES)
            if NAT_POLICY_RULES in set_yaml.keys():
                del set_yaml[NAT_POLICY_RULES]

            ############################################################################
            # NAT Rules
            ############################################################################
            rules_ctrl = {}
            resp = cgx_session.get.natpolicyrules(natpolicyset_id=set_ctrl["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                for rule in ruleslist:
                    rules_ctrl[rule["name"]] = rule
            else:
                print("ERR: Could not retrieve rules for NAT Policy Set: {}".format(natsetname))
                cloudgenix.jd_detailed(resp)

            for rulename in rules_yaml.keys():
                rule_yaml = rules_yaml[rulename]
                rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=NAT)

                if rulename in rules_ctrl.keys():
                    rule_ctrl = rules_ctrl[rulename]
                    rulediff = compareconf(rule_data_yaml, rule_ctrl)
                    if len(rulediff) > 0:
                        ############################################################################
                        # NAT Rules - Update
                        ############################################################################
                        ruledata = update_payload(rule_data_yaml, rule_ctrl)
                        resp = cgx_session.put.natpolicyrules(natpolicyset_id=set_ctrl["id"], natpolicyrule_id=ruledata["id"],
                                                      data=ruledata)
                        if resp.cgx_status:
                            print("\tUpdated Rule: {}".format(rulename))
                        else:
                            print("ERR: Could not update Rule: {}".format(rulename))
                            cloudgenix.jd_detailed(resp)
                    else:
                        ############################################################################
                        # NAT Rules - No Changes detected
                        ############################################################################
                        print("\tNo Changes to Rule: {}".format(rulename))

                else:
                    ############################################################################
                    # NAT Rules - New Create
                    ############################################################################
                    resp = cgx_session.post.natpolicyrules(natpolicyset_id=set_ctrl["id"], data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                        rid = resp.cgx_content.get("id", None)
                        natpolicyrule_id_name[(set_ctrl["id"], rid)] = rule_data_yaml["name"]
                        natpolicyrule_name_id[(set_ctrl["id"], rule_data_yaml["name"])] = rid

                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

            ############################################################################
            # NAT Rules - Delete
            # - Remove from Policy Set rules order list
            # - Delete rule
            ############################################################################
            for rulename in rules_ctrl.keys():
                if rulename not in rules_yaml.keys():
                    data = rules_ctrl[rulename]

                    resp = cgx_session.get.natpolicysets(natpolicyset_id=set_ctrl["id"])
                    if resp.cgx_status:
                        poldata = resp.cgx_content
                        if poldata["destination_zone_policyrule_order"] is not None:
                            if data["id"] in poldata["destination_zone_policyrule_order"]:
                                poldata["destination_zone_policyrule_order"].remove(data["id"])

                        if poldata["source_zone_policyrule_order"] is not None:
                            if data["id"] in poldata["source_zone_policyrule_order"]:
                                poldata["source_zone_policyrule_order"].remove(data["id"])

                        resp = cgx_session.put.natpolicysets(natpolicyset_id=set_ctrl["id"], data=poldata)
                        if resp.cgx_status:
                            print("\tUpdated Policy rule order")
                        else:
                            print("ERR: Could not update rule order. Rule may not be deleted")
                            cloudgenix.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve NAT Policy Sets. Rule may not be deleted")
                        cloudgenix.jd_detailed(resp)

                    resp = cgx_session.delete.natpolicyrules(natpolicyset_id=set_ctrl["id"], natpolicyrule_id=data["id"])
                    if resp.cgx_status:
                        print("\tDeleted Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not delete Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

            set_data_yaml = translate_set(setdata=set_yaml, setid=set_ctrl["id"], set_type=NAT, action=N2ID)
            confdelta = compareconf(set_data_yaml, set_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # NAT Set - Update
                ############################################################################
                data = update_payload(set_data_yaml, set_ctrl)
                resp = cgx_session.put.natpolicysets(natpolicyset_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated NAT Set: {}".format(natsetname))
                else:
                    print("ERR: Could not update NAT Set: {}".format(natsetname))
                    cloudgenix.jd_detailed(resp)

            else:
                ############################################################################
                # NAT Set - No Changes detected
                ############################################################################
                print("No Changes to NAT Set: {}".format(natsetname))


        else:
            ############################################################################
            # NAT Set - New Create
            ############################################################################
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=NAT_POLICY_RULES)
            if NAT_POLICY_RULES in set_yaml.keys():
                del set_yaml[NAT_POLICY_RULES]

            destination_zone_policyrule_order = set_yaml.get("destination_zone_policyrule_order", None)
            source_zone_policyrule_order = set_yaml.get("source_zone_policyrule_order", None)

            set_yaml["destination_zone_policyrule_order"] = None
            set_yaml["source_zone_policyrule_order"] = None

            resp = cgx_session.post.natpolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created NAT Set: {}".format(natsetname))
                set_id = resp.cgx_content.get("id", None)
                natpolicyset_id_name[set_id] = natsetname
                natpolicyset_name_id[natsetname] = set_id
                natrule_name_id = {}
                for rulename in rules_yaml.keys():
                    rule_yaml = rules_yaml[rulename]
                    rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=NAT)

                    ############################################################################
                    # NAT Set - Create new rules
                    ############################################################################
                    resp = cgx_session.post.natpolicyrules(natpolicyset_id=set_id, data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                        natrule_name_id[rulename] = resp.cgx_content.get("id", None)

                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

                ############################################################################
                # NAT Set - Update Policy Order
                ############################################################################
                destids = []
                srcids = []
                if destination_zone_policyrule_order is not None:
                    for rname in destination_zone_policyrule_order:
                        destids.append(natrule_name_id[rname])

                if source_zone_policyrule_order is not None:
                    for rname in source_zone_policyrule_order:
                        srcids.append(natrule_name_id[rname])

                if (len(destids) > 0) or (len(srcids) > 0):
                    resp = cgx_session.get.natpolicysets(natpolicyset_id=set_id)
                    if resp.cgx_status:
                        payload = resp.cgx_content
                        payload["destination_zone_policyrule_order"] = destids
                        payload["source_zone_policyrule_order"] = srcids

                        resp = cgx_session.put.natpolicysets(natpolicyset_id=set_id, data=payload)
                        if resp.cgx_status:
                            print("Updated NAT Set: {}".format(natsetname))
                        else:
                            print("ERR: Could not update rule order for NAT Set: {}".format(natsetname))
                            cloudgenix.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve NAT Set: {}. Rule order not updated".format(natsetname))
                        cloudgenix.jd_detailed(resp)

            else:
                print("ERR: Could not create NAT Set: {}".format(natsetname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT Stack
    ############################################################################
    natstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_POLICY_STACKS)
    for natstackname in natstacktconfig_yaml.keys():

        stack_yaml = natstacktconfig_yaml[natstackname]
        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=NAT)
        stack_data_yaml = update_stack(stack_data_yaml)
        if natstackname in natpolicystack_name_config.keys():
            stack_ctrl = natpolicystack_name_config[natstackname]

            confdelta = compareconf(stack_data_yaml, stack_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # NAT Stack - Update
                ############################################################################
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.natpolicysetstacks(natpolicysetstack_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated NAT Stack: {} ".format(natstackname))
                else:
                    print("ERR: Could not update NAT Stack: {}".format(natstackname))
                    cloudgenix.jd_detailed(resp)

            else:
                ############################################################################
                # NAT Stack - No Changes detected
                ############################################################################
                print("No Changes to NAT Stack: {}".format(natstackname))

        else:
            ############################################################################
            # NAT Stack - New Create
            ############################################################################
            resp = cgx_session.post.natpolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status:
                print("Created NAT Stack: {}".format(natstackname))
            else:
                print("ERR: Could not create NAT Stack: {}".format(natstackname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT Stack - Delete
    ############################################################################
    for natstackname in natpolicystack_name_config.keys():
        if natstackname not in natstacktconfig_yaml.keys():
            data = natpolicystack_name_config[natstackname]
            resp = cgx_session.delete.natpolicysetstacks(natpolicysetstack_id=data["id"])
            if resp.cgx_status:
                print("Deleted NAT Stack: {}".format(natstackname))
            else:
                print("ERR: Could not delete NAT Stack: {}".format(natstackname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT Set - Delete
    ############################################################################
    for natsetname in natpolicyset_name_config.keys():
        if natsetname not in natsetconfig_yaml.keys():
            data = natpolicyset_name_config[natsetname]
            resp = cgx_session.delete.natpolicysets(natpolicyset_id=data["id"])
            if resp.cgx_status:
                print("Deleted NAT Set: {}".format(natsetname))
            else:
                print("ERR: Could not delete NAT Set: {}".format(natsetname))
                cloudgenix.jd_detailed(resp)

    return


def push_policy_security(cgx_session, loaded_config):
    ngfwsetconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_POLICY_SETS)
    ############################################################################
    # Security Set
    ############################################################################
    for ngfwsetname in ngfwsetconfig_yaml.keys():
        set_yaml = ngfwsetconfig_yaml[ngfwsetname]
        if ngfwsetname in ngfwpolicyset_name_config.keys():
            set_ctrl = ngfwpolicyset_name_config[ngfwsetname]
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=SECURITY_POLICY_RULES)
            if SECURITY_POLICY_RULES in set_yaml.keys():
                del set_yaml[SECURITY_POLICY_RULES]

            ############################################################################
            # Security Rules
            ############################################################################
            rules_ctrl = {}
            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"])
            if resp.cgx_status:
                ruleslist = resp.cgx_content.get("items", None)
                for rule in ruleslist:
                    rules_ctrl[rule["name"]] = rule
            else:
                print("ERR: Could not retrieve rules for Security Policy Set: {}".format(ngfwsetname))
                cloudgenix.jd_detailed(resp)

            for rulename in rules_yaml.keys():
                rule_yaml = rules_yaml[rulename]
                rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=SECURITY)

                if rulename in rules_ctrl.keys():
                    rule_ctrl = rules_ctrl[rulename]
                    rulediff = compareconf(rule_data_yaml, rule_ctrl)
                    if len(rulediff) > 0:
                        ############################################################################
                        # Security Rules - Update
                        ############################################################################
                        ruledata = update_payload(rule_data_yaml, rule_ctrl)
                        resp = cgx_session.put.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"],
                                                                       ngfwsecuritypolicyrule_id=ruledata["id"],
                                                                       data=ruledata)
                        if resp.cgx_status:
                            print("\tUpdated Rule: {}".format(rulename))
                        else:
                            print("ERR: Could not update Rule: {}".format(rulename))
                            cloudgenix.jd_detailed(resp)
                    else:
                        ############################################################################
                        # Security Rules - No Changes detected
                        ############################################################################
                        print("\tNo Changes to Rule: {}".format(rulename))

                else:
                    ############################################################################
                    # Security Rules - New Create
                    ############################################################################
                    resp = cgx_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"],
                                                                    data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                        rid = resp.cgx_content.get("id", None)
                        ngfwpolicyrule_id_name[(set_ctrl["id"], rid)] = rule_data_yaml["name"]
                        ngfwpolicyrule_name_id[(set_ctrl["id"], rule_data_yaml["name"])] = rid

                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

            ############################################################################
            # Security Rules - Delete
            # - Remove from Policy Set rules order list
            # - Delete rule
            ############################################################################
            for rulename in rules_ctrl.keys():
                if rulename not in rules_yaml.keys():
                    data = rules_ctrl[rulename]

                    resp = cgx_session.delete.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_ctrl["id"],
                                                                      ngfwsecuritypolicyrule_id=data["id"])
                    if resp.cgx_status:
                        print("\tDeleted Rule: {}".format(rulename))
                    else:
                        print("ERR: Could not delete Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

                    resp = cgx_session.get.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=set_ctrl["id"])
                    if resp.cgx_status:
                        poldata = resp.cgx_content
                        if poldata["policyrule_order"] is not None:
                            if data["id"] in poldata["policyrule_order"]:
                                poldata["policyrule_order"].remove(data["id"])

                        resp = cgx_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=set_ctrl["id"],
                                                                      data=poldata)
                        if resp.cgx_status:
                            print("\tUpdated Policy rule order")
                        else:
                            print("ERR: Could not update rule order. Rule may not be deleted")
                            cloudgenix.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve Security Policy Sets. Rule may not be deleted")
                        cloudgenix.jd_detailed(resp)

            set_data_yaml = translate_set(setdata=set_yaml, setid=set_ctrl["id"], set_type=SECURITY, action=N2ID)
            confdelta = compareconf(set_data_yaml, set_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # Security Set - Update
                ############################################################################
                data = update_payload(set_data_yaml, set_ctrl)
                resp = cgx_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated Security Set: {}".format(ngfwsetname))
                else:
                    print("ERR: Could not update Security Set: {}".format(ngfwsetname))
                    cloudgenix.jd_detailed(resp)

            else:
                ############################################################################
                # Security Set - No Changes detected
                ############################################################################
                print("No Changes to Security Set: {}".format(ngfwsetname))


        else:
            ############################################################################
            # Security Set - New Create
            ############################################################################
            rules_yaml = extractfromyaml(loaded_config=set_yaml, config_type=SECURITY_POLICY_RULES)
            if SECURITY_POLICY_RULES in set_yaml.keys():
                del set_yaml[SECURITY_POLICY_RULES]

            policyrule_order = set_yaml.get("policyrule_order", None)

            set_yaml["policyrule_order"] = None

            resp = cgx_session.post.ngfwsecuritypolicysets(data=set_yaml)
            if resp.cgx_status:
                print("Created Security Set: {}".format(ngfwsetname))
                set_id = resp.cgx_content.get("id", None)
                ngfwpolicyset_id_name[set_id] = ngfwsetname
                ngfwpolicyset_name_id[ngfwsetname] = set_id
                ngfwrule_name_id = {}
                for rulename in rules_yaml.keys():
                    rule_yaml = rules_yaml[rulename]
                    rule_data_yaml = translate_rule(rule=rule_yaml, action=N2ID, rule_type=SECURITY)

                    ############################################################################
                    # Security Set - Create new rules
                    ############################################################################
                    resp = cgx_session.post.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=set_id,
                                                                    data=rule_data_yaml)
                    if resp.cgx_status:
                        print("\tCreated Rule: {}".format(rulename))
                        ngfwrule_name_id[rulename] = resp.cgx_content.get("id", None)

                    else:
                        print("ERR: Could not create Rule: {}".format(rulename))
                        cloudgenix.jd_detailed(resp)

                ############################################################################
                # Security Set - Update Policy Order
                ############################################################################
                ruleids = []
                if policyrule_order is not None:
                    for rname in policyrule_order:
                        ruleids.append(ngfwrule_name_id[rname])

                if (len(ruleids) > 0):
                    resp = cgx_session.get.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=set_id)
                    if resp.cgx_status:
                        payload = resp.cgx_content
                        payload["policyrule_order"] = ruleids

                        resp = cgx_session.put.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=set_id, data=payload)
                        if resp.cgx_status:
                            print("Updated Security Set: {}".format(ngfwsetname))
                        else:
                            print("ERR: Could not update rule order for Security Set: {}".format(ngfwsetname))
                            cloudgenix.jd_detailed(resp)
                    else:
                        print("ERR: Could not retrieve Security Set: {}. Rule order not updated".format(ngfwsetname))
                        cloudgenix.jd_detailed(resp)

            else:
                print("ERR: Could not create Security Set: {}".format(ngfwsetname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # Security Stack
    ############################################################################
    ngfwstacktconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_POLICY_STACKS)
    for nfgwstackname in ngfwstacktconfig_yaml.keys():

        stack_yaml = ngfwstacktconfig_yaml[nfgwstackname]
        stack_data_yaml = translate_stack(stack=stack_yaml, action=N2ID, stack_type=SECURITY)
        stack_data_yaml = update_stack(stack_data_yaml)
        if nfgwstackname in ngfwpolicystack_name_config.keys():
            stack_ctrl = ngfwpolicystack_name_config[nfgwstackname]

            confdelta = compareconf(stack_data_yaml, stack_ctrl)
            if len(confdelta) > 0:
                ############################################################################
                # Security Stack - Update
                ############################################################################
                data = update_payload(stack_data_yaml, stack_ctrl)
                resp = cgx_session.put.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=data["id"], data=data)
                if resp.cgx_status:
                    print("Updated Security Stack: {} ".format(nfgwstackname))
                else:
                    print("ERR: Could not update Security Stack: {}".format(nfgwstackname))
                    cloudgenix.jd_detailed(resp)

            else:
                ############################################################################
                # Security Stack - No Changes detected
                ############################################################################
                print("No Changes to Security Stack: {}".format(nfgwstackname))

        else:
            ############################################################################
            # Security Stack - New Create
            ############################################################################
            resp = cgx_session.post.ngfwsecuritypolicysetstacks(data=stack_data_yaml)
            if resp.cgx_status:
                print("Created Security Stack: {}".format(nfgwstackname))
            else:
                print("ERR: Could not create Security Stack: {}".format(nfgwstackname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # Security Stack - Delete
    ############################################################################
    for nfgwstackname in ngfwpolicystack_name_config.keys():
        if nfgwstackname not in ngfwstacktconfig_yaml.keys():
            data = ngfwpolicystack_name_config[nfgwstackname]
            resp = cgx_session.delete.ngfwsecuritypolicysetstacks(ngfwsecuritypolicysetstack_id=data["id"])
            if resp.cgx_status:
                print("Deleted Security Stack: {}".format(nfgwstackname))
            else:
                print("ERR: Could not delete Security Stack: {}".format(nfgwstackname))
                cloudgenix.jd_detailed(resp)

    ############################################################################
    # Security Set - Delete
    ############################################################################
    for ngfwsetname in ngfwpolicyset_name_config.keys():
        if ngfwsetname not in ngfwsetconfig_yaml.keys():
            data = ngfwpolicyset_name_config[ngfwsetname]
            resp = cgx_session.delete.ngfwsecuritypolicysets(ngfwsecuritypolicyset_id=data["id"])
            if resp.cgx_status:
                print("Deleted Security Set: {}".format(ngfwsetname))
            else:
                print("ERR: Could not delete Security Set: {}".format(ngfwsetname))
                cloudgenix.jd_detailed(resp)

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
        if policytype not in [PATH, QOS, NAT, SECURITY, ALL]:
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
        print("INFO: Building Translation Dicts")
        create_global_dicts_path(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_path(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == QOS:
        print("INFO: Building Translation Dicts")
        create_global_dicts_qos(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_qos(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == NAT:
        print("INFO: Building Translation Dicts")
        create_global_dicts_nat(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_nat(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == SECURITY:
        print("INFO: Building Translation Dicts")
        create_global_dicts_security(cgx_session=cgx_session)
        print("INFO: Reviewing YAML Configuration for updates")
        push_policy_security(cgx_session=cgx_session, loaded_config=loaded_config)

    elif policytype == ALL:
        print("INFO: Building Translation Dicts")
        create_global_dicts_all(cgx_session=cgx_session)
        push_policy_path(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_qos(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_nat(cgx_session=cgx_session, loaded_config=loaded_config)
        push_policy_security(cgx_session=cgx_session, loaded_config=loaded_config)


if __name__ == "__main__":
    go()

