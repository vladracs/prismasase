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
__version__ = "1.0.0b4"
version = __version__

__author__ = "Tanushree K <tkamath@paloaltonetworks.com>"
__email__ = "tkamath@paloaltonetworks.com"
SCRIPT_NAME = "Policy Tool: Pull Resources"

DELETE_KEYS = ["_created_on_utc", "_debug", "_error", "_etag",
               "_info", "_schema", "_updated_on_utc", "_warning",
               "_request_id", "_content_length", "_status_code",
               "name", "id", "display_name"]


# Enums for translation
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

CONFIG = {}

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



def pull_resources(cgx_session, config_file):
    global CONFIG

    ########################################################
    # Common Resources
    ########################################################
    #
    # Global Prefix Filters - AppDefs
    #
    globalpf_name_config = {}
    resp = cgx_session.get.globalprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            globalpf_id_name[item["id"]] = item["name"]
            globalpf_name_id[item["name"]] = item["id"]
            data = cleandata(item)
            globalpf_name_config[name] = data
    else:
        print("ERR: Could not retrieve Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[GLOBAL_PREFIX_FILTERS] = [{name: globalpf_name_config[name]} for name in globalpf_name_config.keys()]

    #
    # Local Prefix Filters - AppDefs
    #
    localpf_name_config = {}
    resp = cgx_session.get.localprefixfilters()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            localpf_id_name[item["id"]] = item["name"]
            localpf_name_id[item["name"]] = item["id"]
            data = cleandata(item)
            localpf_name_config[name] = data
    else:
        print("ERR: Could not retrieve Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[LOCAL_PREFIX_FILTERS] = [{name: localpf_name_config[name]} for name in localpf_name_config.keys()]

    #
    # Custom AppDefs
    #
    app_name_config = {}
    resp = cgx_session.get.appdefs()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            if item["app_type"] == "custom":
                name = item["display_name"]
                data = cleandata(item)
                data = translate_app(data=data, action=ID2N)
                app_name_config[name] = data
    else:
        print("ERR: Could not retrieve appdefs")
        cloudgenix.jd_detailed(resp)

    CONFIG[CUSTOM_APPDEFS] = [{name: app_name_config[name]} for name in app_name_config.keys()]

    #
    # NW Context
    #
    nwcontext_name_config={}
    resp = cgx_session.get.networkcontexts()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            nwcontext_name_config[name] = data

    else:
        print("ERR: Could not retrieve NW Contexts")
        cloudgenix.jd_detailed(resp)

    CONFIG[NETWORK_CONTEXTS] = [{name: nwcontext_name_config[name]} for name in nwcontext_name_config.keys()]

    ########################################################
    # Security Resources
    ########################################################
    #
    # NGFW Global Prefix
    #
    ngfwglobalprefix_name_config = {}
    resp = cgx_session.get.ngfwsecuritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            ngfwglobalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve Security Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[SECURITY_GLOBAL_PREFIXES] = [{name: ngfwglobalprefix_name_config[name]} for name in ngfwglobalprefix_name_config.keys()]

    #
    # NGFW Local Prefix
    #
    ngfwlocalprefix_name_config = {}
    resp = cgx_session.get.ngfwsecuritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            ngfwlocalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve Security Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[SECURITY_LOCAL_PREFIXES] = [{name: ngfwlocalprefix_name_config[name]} for name in ngfwlocalprefix_name_config.keys()]


    #
    # Security Zones
    #
    securityzone_name_config = {}
    resp = cgx_session.get.securityzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            securityzone_name_config[name] = data

    else:
        print("ERR: Could not retrieve Security Zones")
        cloudgenix.jd_detailed(resp)

    CONFIG[SECURITY_ZONES] = [{name: securityzone_name_config[name]} for name in securityzone_name_config.keys()]

    ########################################################
    # NAT Resources
    ########################################################
    #
    # NAT Zone
    #
    natzone_name_config = {}
    resp = cgx_session.get.natzones()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            natzone_name_config[name] = data

    else:
        print("ERR: Could not retrieve NAT Zones")
        cloudgenix.jd_detailed(resp)

    CONFIG[NAT_ZONES] = [{name: natzone_name_config[name]} for name in natzone_name_config.keys()]


    #
    # NAT Pool
    #
    natpool_name_config = {}
    resp = cgx_session.get.natpolicypools()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            natpool_name_config[name] = data

    else:
        print("ERR: Could not retrieve NAT Pools")
        cloudgenix.jd_detailed(resp)

    CONFIG[NAT_POLICY_POOL] = [{name: natpool_name_config[name]} for name in natpool_name_config.keys()]

    #
    # NAT Global Prefix
    #
    natglobalprefix_name_config = {}
    resp = cgx_session.get.natglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            natglobalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve NAT Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[NAT_GLOBAL_PREFIXES] = [{name: natglobalprefix_name_config[name]} for name in natglobalprefix_name_config.keys()]

    #
    # NAT Local Prefix
    #
    natlocalprefix_name_config = {}
    resp = cgx_session.get.natlocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            natlocalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve NAT Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[NAT_LOCAL_PREFIXES] = [{name: natlocalprefix_name_config[name]} for name in natlocalprefix_name_config.keys()]

    ########################################################
    # QoS Resources
    ########################################################
    #
    # Qos Global Prefix
    #
    qosglobalprefix_name_config = {}
    resp = cgx_session.get.prioritypolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            qosglobalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve QoS Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[PRIORITY_GLOBAL_PREFIXES] = [{name: qosglobalprefix_name_config[name]} for name in qosglobalprefix_name_config.keys()]

    #
    # QoS Local Prefix
    #
    qoslocalprefix_name_config = {}
    resp = cgx_session.get.prioritypolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            qoslocalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve QoS Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[PRIORITY_LOCAL_PREFIXES] = [{name: qoslocalprefix_name_config[name]} for name in
                                        qoslocalprefix_name_config.keys()]

    ########################################################
    # Path Resources
    ########################################################
    #
    # Path Global Prefix
    #
    nwglobalprefix_name_config = {}
    resp = cgx_session.get.networkpolicyglobalprefixes()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            nwglobalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve Path Global Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[NETWORK_GLOBAL_PREFIXES] = [{name: nwglobalprefix_name_config[name]} for name in
                                        nwglobalprefix_name_config.keys()]

    #
    # Path Local Prefix
    #
    nwlocalprefix_name_config = {}
    resp = cgx_session.get.networkpolicylocalprefixes_t()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            nwlocalprefix_name_config[name] = data

    else:
        print("ERR: Could not retrieve Path Local Prefix Filters")
        cloudgenix.jd_detailed(resp)

    CONFIG[NETWORK_LOCAL_PREFIXES] = [{name: nwlocalprefix_name_config[name]} for name in
                                       nwlocalprefix_name_config.keys()]



    #
    # WAN Interface Labels
    #
    label_name_config = {}
    resp = cgx_session.get.waninterfacelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            label_name_config[name] = data

    else:
        print("ERR: Could not retrieve WAN Interface Labels")
        cloudgenix.jd_detailed(resp)

    CONFIG[WANINTERFACE_LABELS] = [{name: label_name_config[name]} for name in
                                      label_name_config.keys()]


    #
    # Service Labels
    #
    servicelabel_name_config = {}
    resp = cgx_session.get.servicelabels()
    if resp.cgx_status:
        itemlist = resp.cgx_content.get("items", None)
        for item in itemlist:
            name = item["name"]
            data = cleandata(item)
            servicelabel_name_config[name] = data

    else:
        print("ERR: Could not retrieve Service Labels")
        cloudgenix.jd_detailed(resp)


    CONFIG[SERVICE_LABELS] = [{name: servicelabel_name_config[name]} for name in
                                      servicelabel_name_config.keys()]
    ########################################################
    # Save to YAML
    ########################################################
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

    # Commandline for entering resource info
    resource_group = parser.add_argument_group('Resource Properties',
                                           'Information shared here will be used to query resources')

    resource_group.add_argument("--output", help="Output file name", type=str,
                             default=None)

    args = vars(parser.parse_args())

    ############################################################################
    # Parse arguments provided via CLI
    ############################################################################
    filename = args["output"]
    if filename is None:
        filename = "./resourceconfig.yml"

    print("Tenant Info: {} [{}]".format(cgx_session.tenant_name, cgx_session.tenant_id))
    ############################################################################
    # Create Translation Dicts & Pull Policy
    ############################################################################
    print("INFO: Retrieving Policy Resources")
    pull_resources(cgx_session=cgx_session, config_file=filename)

    print("INFO: Policy Configuration saved in file: {}".format(filename))


if __name__ == "__main__":
    go()