#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Refactored script to push Resources used in Prisma SD-WAN Policies
This YAML file can be generated using pull_resources.py script.

**Version:** 1.0.0b4
**Author:** Tanushree K
**Email:** tkamath@paloaltonetworks.com
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
SCRIPT_NAME = "Policy Tool: Push Resources"

DELETE_KEYS = ["_created_on_utc", "_debug", "_error", "_etag",
               "_info", "_schema", "_updated_on_utc", "_warning",
               "_request_id", "_content_length", "_status_code",
               "name", "id", "display_name"]

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
servicelabel_id_name = {}
servicelabel_name_id = {}

# QoS
qosglobalprefix_id_name = {}
qosglobalprefix_name_id = {}
qoslocalprefix_id_name = {}
qoslocalprefix_name_id = {}

# NAT
natglobalprefix_id_name = {}
natglobalprefix_name_id = {}
natlocalprefix_id_name = {}
natlocalprefix_name_id = {}
natzone_id_name = {}
natzone_name_id = {}
natpool_id_name = {}
natpool_name_id = {}

# Security
ngfwglobalprefix_id_name = {}
ngfwglobalprefix_name_id = {}
ngfwlocalprefix_id_name = {}
ngfwlocalprefix_name_id = {}
seczone_id_name = {}
seczone_name_id = {}


N2ID = "n2id"
ID2N = "id2n"


# App translation Dicts
globalpf_id_name = {}
globalpf_name_id = {}
localpf_id_name = {}
localpf_name_id = {}

# Common resources
CUSTOM_APPDEFS = "appdefs"
NETWORK_CONTEXTS = "networkcontexts"
GLOBAL_PREFIX_FILTERS = "globalprefixfilters"
LOCAL_PREFIX_FILTERS = "localprefixfilters"

# Path
NETWORK_GLOBAL_PREFIXES = "networkpolicyglobalprefixes"
NETWORK_LOCAL_PREFIXES = "networkpolicylocalprefixes_t"
WANINTERFACE_LABELS = "waninterfacelabels"
SERVICE_LABELS = "servicelabels"

# QoS
PRIORITY_GLOBAL_PREFIXES = "prioritypolicyglobalprefixes"
PRIORITY_LOCAL_PREFIXES = "prioritypolicylocalprefixes_t"

# NAT
NAT_GLOBAL_PREFIXES = "natglobalprefixes"
NAT_LOCAL_PREFIXES = "natlocalprefixes_t"
NAT_ZONES = "natzones"
NAT_POLICY_POOL = "natpolicypools"

# Security
SECURITY_GLOBAL_PREFIXES = "ngfwsecuritypolicyglobalprefixes"
SECURITY_LOCAL_PREFIXES = "ngfwsecuritypolicylocalprefixes_t"
SECURITY_ZONES = "securityzones"


# Config Dicts
app_name_config = {}
nwcontext_name_config={}
nwglobalprefix_name_config = {}
nwlocalprefix_name_config = {}
label_name_config = {}
servicelabel_name_config = {}
qosglobalprefix_name_config = {}
qoslocalprefix_name_config = {}
natzone_name_config = {}
natpool_name_config = {}
natglobalprefix_name_config = {}
natlocalprefix_name_config = {}
ngfwglobalprefix_name_config = {}
ngfwlocalprefix_name_config = {}
seczone_name_config = {}
globalpf_name_config = {}
localpf_name_config = {}


def create_global_dicts(cgx_session):
    #
    # Global Prefix Filters - AppDefs
    #
    resp = cgx_session.get.globalprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            globalpf_id_name[item["id"]] = item["name"]
            globalpf_name_id[item["name"]] = item["id"]
            globalpf_name_config[item["name"]] = item
    else:
        print("ERR: Could not retrieve Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    #
    # Local Prefix Filters - AppDefs
    #
    resp = cgx_session.get.localprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            localpf_id_name[item["id"]] = item["name"]
            localpf_name_id[item["name"]] = item["id"]
            localpf_name_config[item["name"]] = item
    else:
        print("ERR: Could not retrieve Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    #
    # AppDefs
    #
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            app_id_name[item["id"]] = item["display_name"]
            app_name_id[item["display_name"]] = item["id"]
            if item["app_type"] == "custom":
                app_name_config[item["display_name"]] = item

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
            nwcontext_name_config[item["name"]] = item
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
            nwglobalprefix_name_config[item["name"]] = item
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
            nwlocalprefix_name_config[item["name"]] = item

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
            label_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve WAN Interface Labels")
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
            servicelabel_name_config[item["name"]] = item

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
            qosglobalprefix_name_config[item["name"]] = item

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
            qoslocalprefix_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve QoS Local Prefix Filters")
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
            natzone_name_config[item["name"]] = item

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
            natpool_name_config[item["name"]] = item

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
            natglobalprefix_name_config[item["name"]] = item

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
            natlocalprefix_name_config[item["name"]] = item
    else:
        print("ERR: Could not retrieve NAT Local Prefix Filters")
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
            ngfwglobalprefix_name_config[item["name"]] = item

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
            ngfwlocalprefix_name_config[item["name"]] = item

    else:
        print("ERR: Could not retrieve Security Local Prefix Filters")
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
            seczone_name_config[item["name"]] = item


    else:
        print("ERR: Could not retrieve Security Zones")
        cloudgenix.jd_detailed(resp)

    return


def translate_app(data, action):

    ##################################################
    # Translate Appdef
    ##################################################

    if action == ID2N:
        if data is not None:
            #
            # TCP Rules
            #
            tcp_rules = data.get("tcp_rules", [])
            if tcp_rules is not None:
                tcp_rules_names = []
                for tcprule in tcp_rules:

                    #
                    # Server Filters
                    #
                    server_filters = tcprule.get("server_filters", [])
                    if server_filters is not None:
                        server_filters_names = []
                        for item in server_filters:
                            if item in globalpf_id_name.keys():
                                server_filters_names.append(globalpf_id_name[item])

                            if item in localpf_id_name.keys():
                                server_filters_names.append(localpf_id_name[item])

                        tcprule["server_filters"] = server_filters_names


                    #
                    # Client Filters
                    #
                    client_filters = tcprule.get("client_filters", [])
                    if client_filters is not None:
                        client_filters_names = []
                        for item in client_filters:
                            if item in globalpf_id_name.keys():
                                client_filters_names.append(globalpf_id_name[item])

                            if item in localpf_id_name.keys():
                                client_filters_names.append(localpf_id_name[item])

                        tcprule["client_filters"] = client_filters_names

                    tcp_rules_names.append(tcprule)

                data["tcp_rules"] = tcp_rules_names

            #
            # UDP Rules
            #
            udp_rules = data.get("udp_rules", [])
            if udp_rules is not None:
                upd_rules_names = []
                for udprule in udp_rules:

                    #
                    # UDP Filters
                    #
                    udp_filters = udprule.get("udp_filters", [])
                    if udp_filters is not None:
                        udp_filters_names = []
                        for item in udp_filters:
                            if item in globalpf_id_name.keys():
                                udp_filters_names.append(globalpf_id_name[item])

                            if item in localpf_id_name.keys():
                                udp_filters_names.append(localpf_id_name[item])

                        udprule["udp_filters"] = udp_filters_names

                        upd_rules_names.append(udprule)

                data["udp_rules"] = upd_rules_names


            #
            # IP Rules
            #
            ip_rules = data.get("ip_rules", [])
            if ip_rules is not None:
                ip_rules_names = []
                for iprule in ip_rules:
                    #
                    # SRC Filters
                    #
                    src_filters = iprule.get("src_filters", [])
                    if src_filters is not None:
                        src_filters_names = []
                        for item in src_filters:
                            if item in globalpf_id_name.keys():
                                src_filters_names.append(globalpf_id_name[item])

                            if item in localpf_id_name.keys():
                                src_filters_names.append(localpf_id_name[item])

                        iprule["src_filters"] = src_filters_names

                    #
                    # DEST Filters
                    #
                    dest_filters = iprule.get("dest_filters", [])
                    if dest_filters is not None:
                        dest_filters_names = []
                        for item in dest_filters:
                            if item in globalpf_id_name.keys():
                                dest_filters_names.append(globalpf_id_name[item])

                            if item in localpf_id_name.keys():
                                dest_filters_names.append(localpf_id_name[item])

                        iprule["dest_filters"] = dest_filters_names

                    ip_rules_names.append(iprule)

                data["ip_rules"] = ip_rules_names

    elif action == N2ID:
        if data is not None:
            #
            # TCP Rules
            #
            tcp_rules = data.get("tcp_rules", [])
            if tcp_rules is not None:
                tcp_rules_ids = []
                for tcprule in tcp_rules:

                    #
                    # Server Filters
                    #
                    server_filters = tcprule.get("server_filters", [])
                    if server_filters is not None:
                        server_filters_ids = []
                        for item in server_filters:
                            if item in globalpf_name_id.keys():
                                server_filters_ids.append(globalpf_name_id[item])

                            if item in localpf_name_id.keys():
                                server_filters_ids.append(localpf_name_id[item])

                        tcprule["server_filters"] = server_filters_ids

                    #
                    # Client Filters
                    #
                    client_filters = tcprule.get("client_filters", [])
                    if client_filters is not None:
                        client_filters_ids = []
                        for item in client_filters:
                            if item in globalpf_name_id.keys():
                                client_filters_ids.append(globalpf_name_id[item])

                            if item in localpf_name_id.keys():
                                client_filters_ids.append(localpf_name_id[item])

                        tcprule["client_filters"] = client_filters_ids

                    tcp_rules_ids.append(tcprule)

                data["tcp_rules"] = tcp_rules_ids

            #
            # UDP Rules
            #
            udp_rules = data.get("udp_rules", [])
            if udp_rules is not None:
                upd_rules_ids = []
                for udprule in udp_rules:

                    #
                    # UDP Filters
                    #
                    udp_filters = udprule.get("udp_filters", [])
                    if udp_filters is not None:
                        udp_filters_ids = []
                        for item in udp_filters:
                            if item in globalpf_name_id.keys():
                                udp_filters_ids.append(globalpf_name_id[item])

                            if item in localpf_name_id.keys():
                                udp_filters_ids.append(localpf_name_id[item])

                        udprule["udp_filters"] = udp_filters_ids

                        upd_rules_ids.append(udprule)

                data["udp_rules"] = upd_rules_ids

            #
            # IP Rules
            #
            ip_rules = data.get("ip_rules", [])
            if ip_rules is not None:
                ip_rules_ids = []
                for iprule in ip_rules:
                    #
                    # SRC Filters
                    #
                    src_filters = iprule.get("src_filters", [])
                    if src_filters is not None:
                        src_filters_ids = []
                        for item in src_filters:
                            if item in globalpf_name_id.keys():
                                src_filters_ids.append(globalpf_name_id[item])

                            if item in localpf_name_id.keys():
                                src_filters_ids.append(localpf_name_id[item])

                        iprule["src_filters"] = src_filters_ids

                    #
                    # DEST Filters
                    #
                    dest_filters = iprule.get("dest_filters", [])
                    if dest_filters is not None:
                        dest_filters_ids = []
                        for item in dest_filters:
                            if item in globalpf_name_id.keys():
                                dest_filters_ids.append(globalpf_name_id[item])

                            if item in localpf_name_id.keys():
                                dest_filters_ids.append(localpf_name_id[item])

                        iprule["dest_filters"] = dest_filters_ids

                    ip_rules_ids.append(iprule)

                data["ip_rules"] = ip_rules_ids

    return data


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
    if config_type == CUSTOM_APPDEFS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(CUSTOM_APPDEFS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["display_name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NETWORK_CONTEXTS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NETWORK_CONTEXTS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == GLOBAL_PREFIX_FILTERS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(GLOBAL_PREFIX_FILTERS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == LOCAL_PREFIX_FILTERS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(LOCAL_PREFIX_FILTERS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean


    elif config_type == NETWORK_GLOBAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NETWORK_GLOBAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == WANINTERFACE_LABELS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(WANINTERFACE_LABELS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NETWORK_LOCAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NETWORK_LOCAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == SERVICE_LABELS:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(SERVICE_LABELS, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == PRIORITY_GLOBAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(PRIORITY_GLOBAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == PRIORITY_LOCAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(PRIORITY_LOCAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NAT_GLOBAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NAT_GLOBAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NAT_LOCAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NAT_LOCAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NAT_ZONES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NAT_ZONES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == NAT_POLICY_POOL:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(NAT_POLICY_POOL, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == SECURITY_GLOBAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(SECURITY_GLOBAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == SECURITY_LOCAL_PREFIXES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(SECURITY_LOCAL_PREFIXES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean

    elif config_type == SECURITY_ZONES:
        config_clean = {}
        configs = copy.deepcopy(loaded_config.get(SECURITY_ZONES, None))
        for data in configs:
            key = list(data.keys())[0]
            config = data[key]
            config["name"] = key
            config_clean[key] = config

        return config_clean


#
# Function to update payload with contents of YAML for PUT operation
#
def update_payload(source, dest):
    for key in source.keys():
        dest[key] = source[key]

    return dest


# Common resources
CUSTOM_APPDEFS = "appdefs"

def push_resources(cgx_session, loaded_config):
    ############################################################################
    # SERVICE_LABELS
    ############################################################################
    servicelabelconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SERVICE_LABELS)
    if servicelabelconfig_yaml is not None:
        for yaml_key in servicelabelconfig_yaml.keys():
            yaml_data = servicelabelconfig_yaml[yaml_key]
            if yaml_key in servicelabel_name_config.keys():
                ctrl_data = servicelabel_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # SERVICE_LABELS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.servicelabels(servicelabel_id=data["id"],
                                                         data=data)
                    if resp.cgx_status:
                        print("Updated Service Label: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Service Label: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # SERVICE_LABELS - No Changes detected
                    ############################################################################
                    print("No Changes to Service Label: {}".format(yaml_key))


            else:
                ############################################################################
                # SERVICE_LABELS - New Create
                ############################################################################

                resp = cgx_session.post.servicelabels(data=yaml_data)
                if resp.cgx_status:
                    print("Created Service Label: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    servicelabel_id_name[resource_id] = yaml_key
                    servicelabel_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Service Label: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # SERVICE_LABELS - Delete
        ############################################################################
        for ctrl_key in servicelabel_name_config.keys():
            if ctrl_key not in servicelabelconfig_yaml.keys():
                data = servicelabel_name_config[ctrl_key]
                resp = cgx_session.delete.servicelabels(servicelabel_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Service Label: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Service Label: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)
    ############################################################################
    # NETWORK_CONTEXTS
    ############################################################################
    nwcontextconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_CONTEXTS)
    if nwcontextconfig_yaml is not None:
        for yaml_key in nwcontextconfig_yaml.keys():
            yaml_data = nwcontextconfig_yaml[yaml_key]
            if yaml_key in nwcontext_name_config.keys():
                ctrl_data = nwcontext_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NETWORK_CONTEXTS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.networkcontexts(networkcontext_id=data["id"],
                                                           data=data)
                    if resp.cgx_status:
                        print("Updated Network Context: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Network Context: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NETWORK_CONTEXTS - No Changes detected
                    ############################################################################
                    print("No Changes to Network Context: {}".format(yaml_key))


            else:
                ############################################################################
                # NETWORK_CONTEXTS - New Create
                ############################################################################

                resp = cgx_session.post.networkcontexts(data=yaml_data)
                if resp.cgx_status:
                    print("Created Network Context: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    nwcontext_id_name[resource_id] = yaml_key
                    nwcontext_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Network Context: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NETWORK_CONTEXTS - Delete
        ############################################################################
        for ctrl_key in nwcontext_name_config.keys():
            if ctrl_key not in nwcontextconfig_yaml.keys():
                data = nwcontext_name_config[ctrl_key]
                resp = cgx_session.delete.networkcontexts(networkcontext_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Network Context: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Network Context: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # WANINTERFACE_LABELS
    ############################################################################
    labelconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=WANINTERFACE_LABELS)
    if labelconfig_yaml is not None:
        for yaml_key in labelconfig_yaml.keys():
            yaml_data = labelconfig_yaml[yaml_key]
            if yaml_key in label_name_config.keys():
                ctrl_data = label_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # WANINTERFACE_LABELS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.waninterfacelabels(waninterfacelabel_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Label: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Label: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # WANINTERFACE_LABELS - No Changes detected
                    ############################################################################
                    print("No Changes to Label: {}".format(yaml_key))

    ############################################################################
    # GLOBAL_PREFIX_FILTERS
    ############################################################################
    globalpfconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=GLOBAL_PREFIX_FILTERS)
    if globalpfconfig_yaml is not None:
        for yaml_key in globalpfconfig_yaml.keys():
            yaml_data = globalpfconfig_yaml[yaml_key]
            if yaml_key in globalpf_name_config.keys():
                ctrl_data = globalpf_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # GLOBAL_PREFIX_FILTERS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.globalprefixfilters(globalprefixfilter_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Global Prefix Filter: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Global Prefix Filter: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # GLOBAL_PREFIX_FILTERS - No Changes detected
                    ############################################################################
                    print("No Changes to Global Prefix Filter: {}".format(yaml_key))


            else:
                ############################################################################
                # GLOBAL_PREFIX_FILTERS - New Create
                ############################################################################

                resp = cgx_session.post.globalprefixfilters(data=yaml_data)
                if resp.cgx_status:
                    print("Created Global Prefix Filter: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    globalpf_id_name[resource_id] = yaml_key
                    globalpf_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Global Prefix Filter: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # GLOBAL_PREFIX_FILTERS - Delete
        ############################################################################
        for ctrl_key in globalpf_name_config.keys():
            if ctrl_key not in globalpfconfig_yaml.keys():
                data = globalpf_name_config[ctrl_key]
                resp = cgx_session.delete.globalprefixfilters(globalprefixfilter_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Global Prefix Filter: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Global Prefix Filter: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # LOCAL_PREFIX_FILTERS
    ############################################################################
    localpfconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=LOCAL_PREFIX_FILTERS)
    if localpfconfig_yaml is not None:
        for yaml_key in localpfconfig_yaml.keys():
            yaml_data = localpfconfig_yaml[yaml_key]
            if yaml_key in localpf_name_config.keys():
                ctrl_data = localpf_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # LOCAL_PREFIX_FILTERS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.localprefixfilters(localprefixfilter_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated local Prefix Filter: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update local Prefix Filter: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # LOCAL_PREFIX_FILTERS - No Changes detected
                    ############################################################################
                    print("No Changes to local Prefix Filter: {}".format(yaml_key))


            else:
                ############################################################################
                # LOCAL_PREFIX_FILTERS - New Create
                ############################################################################

                resp = cgx_session.post.localprefixfilters(data=yaml_data)
                if resp.cgx_status:
                    print("Created local Prefix Filter: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    localpf_id_name[resource_id] = yaml_key
                    localpf_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create local Prefix Filter: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # LOCAL_PREFIX_FILTERS - Delete
        ############################################################################
        for ctrl_key in localpf_name_config.keys():
            if ctrl_key not in localpfconfig_yaml.keys():
                data = localpf_name_config[ctrl_key]
                resp = cgx_session.delete.localprefixfilters(localprefixfilter_id=data["id"])
                if resp.cgx_status:
                    print("Deleted local Prefix Filter: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete local Prefix Filter: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # CUSTOM_APPDEFS
    ############################################################################
    appconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=CUSTOM_APPDEFS)
    if appconfig_yaml is not None:
        for yaml_key in appconfig_yaml.keys():
            yaml_data = appconfig_yaml[yaml_key]
            yaml_data = translate_app(data=yaml_data, action=N2ID)
            if yaml_key in app_name_config.keys():
                ctrl_data = app_name_config[yaml_key]
                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # CUSTOM_APPDEFS - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.appdefs(appdef_id=data["id"],
                                                   data=data)
                    if resp.cgx_status:
                        print("Updated Custom App: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Custom App: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # CUSTOM_APPDEFS - No Changes detected
                    ############################################################################
                    print("No Changes to Custom App: {}".format(yaml_key))


            else:
                ############################################################################
                # CUSTOM_APPDEFS - New Create
                ############################################################################

                resp = cgx_session.post.appdefs(data=yaml_data)
                if resp.cgx_status:
                    print("Created Custom App: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    app_id_name[resource_id] = yaml_key
                    app_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Custom App: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # CUSTOM_APPDEFS - Delete
        ############################################################################
        for ctrl_key in app_name_config.keys():
            if ctrl_key not in appconfig_yaml.keys():
                data = app_name_config[ctrl_key]
                resp = cgx_session.delete.appdefs(appdef_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Custom App: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Custom App: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # SECURITY_GLOBAL_PREFIXES
    ############################################################################
    ngfwglobalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_GLOBAL_PREFIXES)
    if ngfwglobalprefixconfig_yaml is not None:
        for yaml_key in ngfwglobalprefixconfig_yaml.keys():
            yaml_data = ngfwglobalprefixconfig_yaml[yaml_key]
            if yaml_key in ngfwglobalprefix_name_config.keys():
                ctrl_data = ngfwglobalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # SECURITY_GLOBAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.ngfwsecuritypolicyglobalprefixes(ngfwsecuritypolicyglobalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Security Global Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Security Global Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # SECURITY_GLOBAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to Security Global Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # SECURITY_GLOBAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.ngfwsecuritypolicyglobalprefixes(data=yaml_data)
                if resp.cgx_status:
                    print("Created Security Global Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    ngfwglobalprefix_id_name[resource_id] = yaml_key
                    ngfwglobalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Security Global Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # SECURITY_GLOBAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in ngfwglobalprefix_name_config.keys():
            if ctrl_key not in ngfwglobalprefixconfig_yaml.keys():
                data = ngfwglobalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.ngfwsecuritypolicyglobalprefixes(ngfwsecuritypolicyglobalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Security Global Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Security Global Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # SECURITY_LOCAL_PREFIXES
    ############################################################################
    ngfwlocalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_LOCAL_PREFIXES)
    if ngfwlocalprefixconfig_yaml is not None:
        for yaml_key in ngfwlocalprefixconfig_yaml.keys():
            yaml_data = ngfwlocalprefixconfig_yaml[yaml_key]
            if yaml_key in ngfwlocalprefix_name_config.keys():
                ctrl_data = ngfwlocalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # SECURITY_LOCAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.ngfwsecuritypolicylocalprefixes_t(ngfwsecuritypolicylocalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Security local Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Security local Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # SECURITY_LOCAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to Security local Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # SECURITY_LOCAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.ngfwsecuritypolicylocalprefixes_t(data=yaml_data)
                if resp.cgx_status:
                    print("Created Security local Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    ngfwlocalprefix_id_name[resource_id] = yaml_key
                    ngfwlocalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Security local Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # SECURITY_LOCAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in ngfwlocalprefix_name_config.keys():
            if ctrl_key not in ngfwlocalprefixconfig_yaml.keys():
                data = ngfwlocalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.ngfwsecuritypolicylocalprefixes_t(ngfwsecuritypolicylocalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Security local Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Security local Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # SECURITY_ZONES
    ############################################################################
    securityzoneconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=SECURITY_ZONES)
    if securityzoneconfig_yaml is not None:
        for yaml_key in securityzoneconfig_yaml.keys():
            yaml_data = securityzoneconfig_yaml[yaml_key]
            if yaml_key in seczone_name_config.keys():
                ctrl_data = seczone_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # SECURITY_ZONES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.securityzones(securityzone_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Security Zone: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Security Zone: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # SECURITY_ZONES - No Changes detected
                    ############################################################################
                    print("No Changes to Security Zone: {}".format(yaml_key))


            else:
                ############################################################################
                # SECURITY_ZONES - New Create
                ############################################################################

                resp = cgx_session.post.securityzones(data=yaml_data)
                if resp.cgx_status:
                    print("Created Security Zone: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    seczone_id_name[resource_id] = yaml_key
                    seczone_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Security Zone: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # SECURITY_ZONES - Delete
        ############################################################################
        for ctrl_key in seczone_name_config.keys():
            if ctrl_key not in securityzoneconfig_yaml.keys():
                data = seczone_name_config[ctrl_key]
                resp = cgx_session.delete.securityzones(securityzone_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Security Zone: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Security Zone: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT_GLOBAL_PREFIXES
    ############################################################################
    natglobalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_GLOBAL_PREFIXES)
    if natglobalprefixconfig_yaml is not None:
        for yaml_key in natglobalprefixconfig_yaml.keys():
            yaml_data = natglobalprefixconfig_yaml[yaml_key]
            if yaml_key in natglobalprefix_name_config.keys():
                ctrl_data = natglobalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NAT_GLOBAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.natglobalprefixes(natglobalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated nat global Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update nat global Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NAT_GLOBAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to nat global Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # NAT_GLOBAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.natglobalprefixes(data=yaml_data)
                if resp.cgx_status:
                    print("Created nat global Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    natglobalprefix_id_name[resource_id] = yaml_key
                    natglobalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create nat global Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NAT_GLOBAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in natglobalprefix_name_config.keys():
            if ctrl_key not in natglobalprefixconfig_yaml.keys():
                data = natglobalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.natglobalprefixes(natglobalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted nat global Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete nat global Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT_LOCAL_PREFIXES
    ############################################################################
    natlocalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_LOCAL_PREFIXES)
    if natlocalprefixconfig_yaml is not None:
        for yaml_key in natlocalprefixconfig_yaml.keys():
            yaml_data = natlocalprefixconfig_yaml[yaml_key]
            if yaml_key in natlocalprefix_name_config.keys():
                ctrl_data = natlocalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NAT_LOCAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.natlocalprefixes_t(natlocalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated nat local Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update nat local Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NAT_LOCAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to nat local Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # NAT_LOCAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.natlocalprefixes_t(data=yaml_data)
                if resp.cgx_status:
                    print("Created nat local Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    natlocalprefix_id_name[resource_id] = yaml_key
                    natlocalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create nat local Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NAT_LOCAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in natlocalprefix_name_config.keys():
            if ctrl_key not in natlocalprefixconfig_yaml.keys():
                data = natlocalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.natlocalprefixes_t(natlocalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted nat local Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete nat local Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT_ZONES
    ############################################################################
    natzoneconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_ZONES)
    if natzoneconfig_yaml is not None:
        for yaml_key in natzoneconfig_yaml.keys():
            yaml_data = natzoneconfig_yaml[yaml_key]
            if yaml_key in natzone_name_config.keys():
                ctrl_data = natzone_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NAT_ZONES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.natzones(natzone_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated nat zone: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update nat zone: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NAT_ZONES - No Changes detected
                    ############################################################################
                    print("No Changes to nat zone: {}".format(yaml_key))

            else:
                ############################################################################
                # NAT_ZONES - New Create
                ############################################################################

                resp = cgx_session.post.natzones(data=yaml_data)
                if resp.cgx_status:
                    print("Created nat zone: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    natzone_id_name[resource_id] = yaml_key
                    natzone_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create nat zone: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NAT_ZONES - Delete
        ############################################################################
        for ctrl_key in natzone_name_config.keys():
            if ctrl_key not in natzoneconfig_yaml.keys():
                data = natzone_name_config[ctrl_key]
                resp = cgx_session.delete.natzones(natzone_id=data["id"])
                if resp.cgx_status:
                    print("Deleted nat zone: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete nat zone: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NAT_POLICY_POOL
    ############################################################################
    natpoolconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NAT_POLICY_POOL)
    if natpoolconfig_yaml is not None:
        for yaml_key in natpoolconfig_yaml.keys():
            yaml_data = natpoolconfig_yaml[yaml_key]
            if yaml_key in natpool_name_config.keys():
                ctrl_data = natpool_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NAT_POLICY_POOL - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.natpolicypools(natpolicypool_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated nat pool: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update nat pool: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NAT_POLICY_POOL - No Changes detected
                    ############################################################################
                    print("No Changes to nat pool: {}".format(yaml_key))


            else:
                ############################################################################
                # NAT_POLICY_POOL - New Create
                ############################################################################

                resp = cgx_session.post.natpolicypools(data=yaml_data)
                if resp.cgx_status:
                    print("Created nat pool: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    natpool_id_name[resource_id] = yaml_key
                    natpool_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create nat pool: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NAT_POLICY_POOL - Delete
        ############################################################################
        for ctrl_key in natpool_name_config.keys():
            if ctrl_key not in natpoolconfig_yaml.keys():
                data = natpool_name_config[ctrl_key]
                resp = cgx_session.delete.natpolicypools(natpolicypool_id=data["id"])
                if resp.cgx_status:
                    print("Deleted nat pool: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete nat pool: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # PRIORITY_GLOBAL_PREFIXES
    ############################################################################
    qosglobalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=PRIORITY_GLOBAL_PREFIXES)
    if qosglobalprefixconfig_yaml is not None:
        for yaml_key in qosglobalprefixconfig_yaml.keys():
            yaml_data = qosglobalprefixconfig_yaml[yaml_key]
            if yaml_key in qosglobalprefix_name_config.keys():
                ctrl_data = qosglobalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # PRIORITY_GLOBAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.prioritypolicyglobalprefixes(prioritypolicyglobalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated QoS global Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update QoS global Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # PRIORITY_GLOBAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to QoS global Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # PRIORITY_GLOBAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.prioritypolicyglobalprefixes(data=yaml_data)
                if resp.cgx_status:
                    print("Created QoS global Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    qosglobalprefix_id_name[resource_id] = yaml_key
                    qosglobalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create QoS global Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # PRIORITY_GLOBAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in qosglobalprefix_name_config.keys():
            if ctrl_key not in qosglobalprefixconfig_yaml.keys():
                data = qosglobalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.prioritypolicyglobalprefixes(prioritypolicyglobalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted QoS global Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete QoS global Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)
    ############################################################################
    # PRIORITY_LOCAL_PREFIXES
    ############################################################################
    qoslocalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=PRIORITY_LOCAL_PREFIXES)
    if qoslocalprefixconfig_yaml is not None:
        for yaml_key in qoslocalprefixconfig_yaml.keys():
            yaml_data = qoslocalprefixconfig_yaml[yaml_key]
            if yaml_key in qoslocalprefix_name_config.keys():
                ctrl_data = qoslocalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # PRIORITY_LOCAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.prioritypolicylocalprefixes_t(prioritypolicylocalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated QoS local Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update QoS local Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # PRIORITY_LOCAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to QoS local Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # PRIORITY_LOCAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.prioritypolicylocalprefixes_t(data=yaml_data)
                if resp.cgx_status:
                    print("Created QoS local Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    qoslocalprefix_id_name[resource_id] = yaml_key
                    qoslocalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create QoS local Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # PRIORITY_LOCAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in qoslocalprefix_name_config.keys():
            if ctrl_key not in qoslocalprefixconfig_yaml.keys():
                data = qoslocalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.prioritypolicylocalprefixes_t(prioritypolicylocalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted QoS local Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete QoS local Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NETWORK_GLOBAL_PREFIXES
    ############################################################################
    nwglobalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_GLOBAL_PREFIXES)
    if nwglobalprefixconfig_yaml is not None:
        for yaml_key in nwglobalprefixconfig_yaml.keys():
            yaml_data = nwglobalprefixconfig_yaml[yaml_key]
            if yaml_key in nwglobalprefix_name_config.keys():
                ctrl_data = nwglobalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NETWORK_GLOBAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.networkpolicyglobalprefixes(networkpolicyglobalprefix_id=data["id"], data=data)
                    if resp.cgx_status:
                        print("Updated Path Global Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Path Global Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NETWORK_GLOBAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to Path Global Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # NETWORK_GLOBAL_PREFIXES - New Create
                ############################################################################


                resp = cgx_session.post.networkpolicyglobalprefixes(data=yaml_data)
                if resp.cgx_status:
                    print("Created Path Global Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    nwglobalprefix_id_name[resource_id] = yaml_key
                    nwglobalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Path Global Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NETWORK_GLOBAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in nwglobalprefix_name_config.keys():
            if ctrl_key not in nwglobalprefixconfig_yaml.keys():
                data = nwglobalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.networkpolicyglobalprefixes(networkpolicyglobalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Path Global Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Path Global Prefix: {}".format(ctrl_key))
                    cloudgenix.jd_detailed(resp)

    ############################################################################
    # NETWORK_LOCAL_PREFIXES
    ############################################################################
    nwlocalprefixconfig_yaml = extractfromyaml(loaded_config=loaded_config, config_type=NETWORK_LOCAL_PREFIXES)
    if nwlocalprefixconfig_yaml is not None:
        for yaml_key in nwlocalprefixconfig_yaml.keys():
            yaml_data = nwlocalprefixconfig_yaml[yaml_key]
            if yaml_key in nwlocalprefix_name_config.keys():
                ctrl_data = nwlocalprefix_name_config[yaml_key]

                confdelta = compareconf(yaml_data, ctrl_data)
                if len(confdelta) > 0:
                    ############################################################################
                    # NETWORK_LOCAL_PREFIXES - Update
                    ############################################################################
                    data = update_payload(yaml_data, ctrl_data)
                    resp = cgx_session.put.networkpolicylocalprefixes_t(networkpolicylocalprefix_id=data["id"],
                                                                       data=data)
                    if resp.cgx_status:
                        print("Updated Path Local Prefix: {}".format(yaml_key))
                    else:
                        print("ERR: Could not update Path Local Prefix: {}".format(yaml_key))
                        cloudgenix.jd_detailed(resp)

                else:
                    ############################################################################
                    # NETWORK_LOCAL_PREFIXES - No Changes detected
                    ############################################################################
                    print("No Changes to Path Local Prefix: {}".format(yaml_key))


            else:
                ############################################################################
                # NETWORK_LOCAL_PREFIXES - New Create
                ############################################################################

                resp = cgx_session.post.networkpolicylocalprefixes_t(data=yaml_data)
                if resp.cgx_status:
                    print("Created Path Local Prefix: {}".format(yaml_key))
                    resource_id = resp.cgx_content.get("id", None)
                    nwglobalprefix_id_name[resource_id] = yaml_key
                    nwglobalprefix_name_id[yaml_key] = resource_id

                else:
                    print("ERR: Could not create Path Local Prefix: {}".format(yaml_key))
                    cloudgenix.jd_detailed(resp)

        ############################################################################
        # NETWORK_LOCAL_PREFIXES - Delete
        ############################################################################
        for ctrl_key in nwlocalprefix_name_config.keys():
            if ctrl_key not in nwlocalprefixconfig_yaml.keys():
                data = nwlocalprefix_name_config[ctrl_key]
                resp = cgx_session.delete.networkpolicylocalprefixes_t(networkpolicylocalprefix_id=data["id"])
                if resp.cgx_status:
                    print("Deleted Path Local Prefix: {}".format(ctrl_key))
                else:
                    print("ERR: Could not delete Path Local Prefix: {}".format(ctrl_key))
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

    # Commandline for entering resource info
    resource_group = parser.add_argument_group('Resource Properties',
                                           'Information shared here will be used to configure resources')

    resource_group.add_argument("--filename","-F", help="File name. Provide the entire path", type=str,
                             default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    filename = args["filename"]



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
    print("INFO: Building Translation Dicts")
    create_global_dicts(cgx_session=cgx_session)
    print("INFO: Reviewing YAML Configuration for updates")
    push_resources(cgx_session=cgx_session, loaded_config=loaded_config)


if __name__ == "__main__":
    go()