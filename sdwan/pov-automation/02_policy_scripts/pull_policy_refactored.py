#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Script to pull Prisma SD-WAN Policies configuration into a YAML file

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
    from prismasdwan_settings import CLOUDGENIX_AUTH_TOKEN
except ImportError:
    # will get caught below.
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

#
# Service Account Details
#
try:
    from prismasase_settings import PRISMASASE_CLIENT_ID, PRISMASASE_CLIENT_SECRET, PRISMASASE_TSG_ID
    import prisma_sase

except ImportError:

    # will get caught below
    PRISMASASE_CLIENT_ID = None
    PRISMASASE_CLIENT_SECRET = None
    PRISMASASE_TSG_ID = None


# Authenticate with new Prisma SASE SDK
sdk = API()
sdk.interactive.login_secret(
    client_id=PRISMASASE_CLIENT_ID,
    client_secret=PRISMASASE_CLIENT_SECRET,
    tsg_id=PRISMASASE_TSG_ID
)
cgx_session = sdk



# Version for reference
__version__ = "1.0.1"
version = __version__

__author__ = "Tanushree K <tkamath@paloaltonetworks.com>"
__email__ = "tkamath@paloaltonetworks.com"
SCRIPT_NAME = "Policy Tool: Pull Policy"

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

CONFIG = {}

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
    # Translate Stack - Security
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


def pull_policy_path(cgx_session, config_file, reset_config):
    global CONFIG
    stack_name_config = {}
    resp = cgx_session.get.networkpolicysetstacks()
    if resp.cgx_status:
        pathstacks = resp.cgx_content.get("items", None)
        for pathstack in pathstacks:
            pathstackname = pathstack["name"]
            clean_pathstack = cleandata(pathstack)
            translate_stack(stack=clean_pathstack, stack_type=PATH, action=ID2N)
            stack_name_config[pathstackname] = clean_pathstack
    else:
        print("ERR: Could not retrieve Network Policy Stacks")
        cloudgenix.jd_detailed(resp)

    if reset_config:
        CONFIG = {}

    CONFIG[NETWORK_POLICY_STACKS] = [{stackname: stack_name_config[stackname]} for stackname in
                                     stack_name_config.keys()]

    set_name_config = {}
    resp = cgx_session.get.networkpolicysets()
    if resp.cgx_status:
        pathpolicysets = resp.cgx_content.get("items", None)
        for pathset in pathpolicysets:
            pathsetname = pathset["name"]

            rule_name_config = {}
            resp = cgx_session.get.networkpolicyrules(networkpolicyset_id=pathset["id"])
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rulename = rule["name"]
                    clean_rule = cleandata(rule)
                    translate_rule(rule=clean_rule, rule_type=PATH, action=ID2N)
                    rule_name_config[rulename] = clean_rule

            else:
                print("ERR: Could not retrieve rules")
                cloudgenix.jd_detailed(resp)

            clean_pathset = cleandata(pathset)
            pathset[NETWORK_POLICY_RULES] = [{rname: rule_name_config[rname]} for rname in rule_name_config.keys()]
            set_name_config[pathsetname] = clean_pathset

    else:
        print("ERR: Could not retrieve Path Policy Sets")
        cloudgenix.jd_detailed(resp)

    CONFIG[NETWORK_POLICY_SETS] = [{setname: set_name_config[setname]} for setname in set_name_config.keys()]

    config_yml = open(config_file, "w")
    yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)

    return


def pull_policy_qos(cgx_session, config_file, reset_config):
    global CONFIG
    stack_name_config = {}
    resp = cgx_session.get.prioritypolicysetstacks()
    if resp.cgx_status:
        qosstacks = resp.cgx_content.get("items", None)
        for qosstack in qosstacks:
            qosstackname = qosstack["name"]
            clean_qosstack = cleandata(qosstack)
            translate_stack(stack=clean_qosstack, stack_type=QOS, action=ID2N)
            stack_name_config[qosstackname] = clean_qosstack
    else:
        print("ERR: Could not retrieve QOS Policy Stacks")
        cloudgenix.jd_detailed(resp)

    if reset_config:
        CONFIG = {}

    CONFIG[PRIORITY_POLICY_STACKS] = [{stackname: stack_name_config[stackname]} for stackname in
                                      stack_name_config.keys()]

    set_name_config = {}
    resp = cgx_session.get.prioritypolicysets()
    if resp.cgx_status:
        qospolicysets = resp.cgx_content.get("items", None)
        for qosset in qospolicysets:
            qossetname = qosset["name"]

            rule_name_config = {}
            resp = cgx_session.get.prioritypolicyrules(prioritypolicyset_id=qosset["id"])
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rulename = rule["name"]
                    clean_rule = cleandata(rule)
                    translate_rule(rule=clean_rule, rule_type=QOS, action=ID2N)
                    rule_name_config[rulename] = clean_rule

            else:
                print("ERR: Could not retrieve rules")
                cloudgenix.jd_detailed(resp)

            clean_qosset = cleandata(qosset)
            qosset[PRIORITY_POLICY_RULES] = [{rname: rule_name_config[rname]} for rname in rule_name_config.keys()]
            set_name_config[qossetname] = clean_qosset

    else:
        print("ERR: Could not retrieve QoS Policy Sets")
        cloudgenix.jd_detailed(resp)

    CONFIG[PRIORITY_POLICY_SETS] = [{setname: set_name_config[setname]} for setname in set_name_config.keys()]

    config_yml = open(config_file, "w")
    yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)

    return


def pull_policy_nat(cgx_session, config_file, reset_config):
    global CONFIG

    stack_name_config={}
    resp = cgx_session.get.natpolicysetstacks()
    if resp.cgx_status:
        natstacks = resp.cgx_content.get("items", None)
        for natstack in natstacks:
            natstackname = natstack["name"]
            clean_natstack = cleandata(natstack)
            translate_stack(stack=clean_natstack, stack_type=NAT, action=ID2N)
            stack_name_config[natstackname] = clean_natstack
    else:
        print("ERR: Could not retrieve NAT Policy Stacks")
        cloudgenix.jd_detailed(resp)

    if reset_config:
        CONFIG = {}

    CONFIG[NAT_POLICY_STACKS] = [{stackname: stack_name_config[stackname]} for stackname in stack_name_config.keys()]


    set_name_config={}
    resp = cgx_session.get.natpolicysets()
    if resp.cgx_status:
        natpolicysets = resp.cgx_content.get("items", None)
        for natset in natpolicysets:
            natsetname = natset["name"]

            rule_name_config={}
            resp = cgx_session.get.natpolicyrules(natpolicyset_id=natset["id"])
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rulename = rule["name"]
                    clean_rule = cleandata(rule)
                    translate_rule(rule=clean_rule, rule_type=NAT, action=ID2N)
                    rule_name_config[rulename] = clean_rule

            else:
                print("ERR: Could not retrieve rules")
                cloudgenix.jd_detailed(resp)

            setid = natset["id"]
            clean_natset = cleandata(natset)
            translate_set(setdata=clean_natset, setid=setid, set_type=NAT, action=ID2N)
            natset[NAT_POLICY_RULES] = [{rname:rule_name_config[rname]} for rname in rule_name_config.keys()]
            set_name_config[natsetname] = clean_natset

    else:
        print("ERR: Could not retrieve NAT Policy Sets")
        cloudgenix.jd_detailed(resp)

    CONFIG[NAT_POLICY_SETS] = [{setname: set_name_config[setname]} for setname in set_name_config.keys()]

    config_yml = open(config_file, "w")
    yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)

    return


def pull_policy_security(cgx_session, config_file, reset_config):
    global CONFIG

    stack_name_config = {}
    resp = cgx_session.get.ngfwsecuritypolicysetstacks()
    if resp.cgx_status:
        ngfwstacks = resp.cgx_content.get("items", None)
        for ngfwstack in ngfwstacks:
            ngfwstackname = ngfwstack["name"]
            clean_ngfwstack = cleandata(ngfwstack)
            translate_stack(stack=clean_ngfwstack, stack_type=SECURITY, action=ID2N)
            stack_name_config[ngfwstackname] = clean_ngfwstack
    else:
        print("ERR: Could not retrieve Security Policy Stacks")
        cloudgenix.jd_detailed(resp)

    if reset_config:
        CONFIG = {}

    CONFIG[SECURITY_POLICY_STACKS] = [{stackname: stack_name_config[stackname]} for stackname in
                                      stack_name_config.keys()]

    set_name_config = {}
    resp = cgx_session.get.ngfwsecuritypolicysets()
    if resp.cgx_status:
        ngfwpolicysets = resp.cgx_content.get("items", None)
        for ngfwset in ngfwpolicysets:
            ngfwsetname = ngfwset["name"]

            rule_name_config = {}
            resp = cgx_session.get.ngfwsecuritypolicyrules(ngfwsecuritypolicyset_id=ngfwset["id"])
            if resp.cgx_status:
                rules = resp.cgx_content.get("items", None)

                for rule in rules:
                    rulename = rule["name"]
                    clean_rule = cleandata(rule)
                    translate_rule(rule=clean_rule, rule_type=SECURITY, action=ID2N)
                    rule_name_config[rulename] = clean_rule

            else:
                print("ERR: Could not retrieve rules")
                cloudgenix.jd_detailed(resp)

            setid = ngfwset["id"]
            clean_ngfwset = cleandata(ngfwset)
            translate_set(setdata=clean_ngfwset, setid=setid, set_type=SECURITY, action=ID2N)
            ngfwset[SECURITY_POLICY_RULES] = [{rname: rule_name_config[rname]} for rname in rule_name_config.keys()]
            set_name_config[ngfwsetname] = clean_ngfwset

    else:
        print("ERR: Could not retrieve Security Policy Sets")
        cloudgenix.jd_detailed(resp)

    CONFIG[SECURITY_POLICY_SETS] = [{setname: set_name_config[setname]} for setname in set_name_config.keys()]

    config_yml = open(config_file, "w")
    yaml.safe_dump(CONFIG, config_yml, default_flow_style=False)

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
                              default="PATH")
    policy_group.add_argument("--output", help="Output file name", type=str,
                             default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    
    policytype = args['policytype'].strip().lower()
    print(f"DEBUG: Parsed policy_type = {policytype}")
    if policytype is None:
        print("ERR: Please provide policy type")
        sys.exit()

    elif policytype not in [PATH, QOS, NAT, SECURITY, ALL]:
        print("ERR: Unsupported policy type")
        sys.exit()

    filename = args["output"]
    filename_path = filename_qos = filename_nat = filename_security = None

    allfile = True
    if filename is None:
        allfile = False
        if policytype == ALL:
            filename_path = "./path_policyconfig.yml"
            filename_qos = "./qos_policyconfig.yml"
            filename_nat = "./nat_policyconfig.yml"
            filename_security = "./security_policyconfig.yml"

        else:
            filename = "./{}_policyconfig.yml".format(policytype)

    ############################################################################
    # Instantiate API & Login
    ############################################################################
    cgx_session = None
    if (CLOUDGENIX_AUTH_TOKEN):
        cgx_session = cloudgenix.API(controller=args["controller"], ssl_verify=False)
        cgx_session.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if cgx_session.tenant_id is None:
            print("ERR: AUTH_TOKEN login failure. Please provide a valid token.")
            sys.exit()

    elif PRISMASASE_CLIENT_ID and PRISMASASE_CLIENT_SECRET and PRISMASASE_TSG_ID:
        cgx_session = prisma_sase.API(ssl_verify=False)
        cgx_session.interactive.login_secret(client_id=PRISMASASE_CLIENT_ID, client_secret=PRISMASASE_CLIENT_SECRET, tsg_id=PRISMASASE_TSG_ID)
        if cgx_session.tenant_id is None:
            print("ERR: Service Account login failure. Please provide a valid Service Account.")
            sys.exit()

    else:
        print("ERR: No credentials provided. Please provide valid credentials in the prismasdwan_settings.py file. Exiting.")
        sys.exit()

    print("Tenant Info: {} [{}]".format(cgx_session.tenant_name, cgx_session.tenant_id))
    ############################################################################
    # Create Translation Dicts & Pull Policy
    ############################################################################
    if policytype == PATH:
        print("INFO: Building translation dicts")
        create_global_dicts_path(cgx_session=cgx_session)
        pull_policy_path(cgx_session=cgx_session, config_file=filename, reset_config=False)
        print("INFO: Path Policy Configuration saved in file: {}".format(filename))


    elif policytype == QOS:
        print("INFO: Building translation dicts")
        create_global_dicts_qos(cgx_session=cgx_session)
        pull_policy_qos(cgx_session=cgx_session, config_file=filename, reset_config=False)
        print("INFO: QoS Policy Configuration saved in file: {}".format(filename))


    elif policytype == NAT:
        print("INFO: Building translation dicts")
        create_global_dicts_nat(cgx_session=cgx_session)
        pull_policy_nat(cgx_session=cgx_session, config_file=filename, reset_config=False)
        print("INFO: NAT Policy Configuration saved in file: {}".format(filename))


    elif policytype == SECURITY:
        print("INFO: Building translation dicts")
        create_global_dicts_security(cgx_session=cgx_session)
        pull_policy_security(cgx_session=cgx_session, config_file=filename, reset_config=False)
        print("INFO: Security Policy Configuration saved in file: {}".format(filename))


    elif policytype == ALL:
        print("INFO: Building translation dicts")
        create_global_dicts_all(cgx_session=cgx_session)
        if allfile:
            pull_policy_path(cgx_session=cgx_session, config_file=filename, reset_config=False)
            pull_policy_qos(cgx_session=cgx_session, config_file=filename, reset_config=False)
            pull_policy_nat(cgx_session=cgx_session, config_file=filename, reset_config=False)
            pull_policy_security(cgx_session=cgx_session, config_file=filename, reset_config=False)
            print("INFO: Policy Configuration saved in file: {}".format(filename))

        else:
            pull_policy_path(cgx_session=cgx_session, config_file=filename_path, reset_config=True)
            print("INFO: Path Policy Configuration saved in file: {}".format(filename_path))

            pull_policy_qos(cgx_session=cgx_session, config_file=filename_qos, reset_config=True)
            print("INFO: QoS Policy Configuration saved in file: {}".format(filename_qos))

            pull_policy_nat(cgx_session=cgx_session, config_file=filename_nat, reset_config=True)
            print("INFO: NAT Policy Configuration saved in file: {}".format(filename_nat))

            pull_policy_security(cgx_session=cgx_session, config_file=filename_security, reset_config=True)
            print("INFO: Security Policy Configuration saved in file: {}".format(filename_security))


if __name__ == "__main__":
    go()

