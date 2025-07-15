#!/usr/bin/env python3
import os
import json
import requests

AUTH_URL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
BASE_API_URL = "https://api.sase.paloaltonetworks.com"

def get_env_variable(name):
    value = os.getenv(name)
    if not value:
        raise ValueError(f"Environment variable {name} is not set")
    return value

def get_token():
    client_id = get_env_variable("CLIENT_ID")
    client_secret = get_env_variable("CLIENT_SECRET")
    tenant_id = get_env_variable("TENANT_ID")
    data_payload = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": f"tsg_id:{tenant_id}",
        "grant_type": "client_credentials"
    }
    response = requests.post(
        AUTH_URL,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=data_payload
    )
    response.raise_for_status()
    return response.json()["access_token"]

def get_headers(token):
    return {
        'accept': 'application/json',
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
        'X-PANW-Region': 'de'

    }

def get_profile(token):
    profile_url = f"{BASE_API_URL}/sdwan/v2.1/api/profile"
    headers = get_headers(token)
    resp = requests.get(profile_url, headers=headers)
    print("profile api status:", resp.status_code)
    #print("profile api response:", resp.text)
    return resp

def call_alarms(token):
    alarms_url = f"{BASE_API_URL}/sdwan/v3.6/api/events/query"
    alarms_payload = {
        "limit": {
            "count": 50,
            "sort_on": "time",
            "sort_order": "descending"
        },
        "dest_page": 0,
        "view": {
            "summary": False
        },
        "priority": [],
        "severity": [],
        "element_cluster_roles": [],
        "query": {
            "site": [],
            "category": [],
            "code": [],
            "correlation_id": [],
            "type": ["alarm"]
        },
        "start_time": "2025-03-01T17:18:03.662Z",
        "end_time": "2025-04-08T17:18:03.662Z"
    }
    headers = get_headers(token)
    resp = requests.post(alarms_url, headers=headers, data=json.dumps(alarms_payload))
    print("alarms api status:", resp.status_code)
    #print("alarms api response:", resp.text)
    return resp

def call_appdefs(token):
    appdefs_url = f"{BASE_API_URL}/sdwan/v2.6/api/appdefs"
    headers = get_headers(token)
    headers = get_headers(token)
    resp = requests.get(appdefs_url, headers=headers)
    apps = resp.json().get("items", [])

# ✅ Loop through and print app display names
    for app in apps:
        name = app.get("display_name")
        #if name:
            #print(name)
        #print("appdefs api status:", resp.status_code)
        #print("appdefs api response:", resp.text)
        

def call_aiops_health(token):
    aiops_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/aiops/health"
    aiops_payload = {
    "end_time": "2025-06-02T00:00:00Z",
    "filter": { "site_health": ["all"] },
    "interval": "5min",
    "start_time": "2025-06-01T00:00:00Z",
    "view": "summary"
    }
    #print("GET aiops_url = ",aiops_url)
    headers = get_headers(token)
    #print("X-PANW-Region: ",headers["X-PANW-Region"])
    resp = requests.post(aiops_url, headers=headers, data=json.dumps(aiops_payload))
    print("aiops api status:", resp.status_code)
    #print("aiops api response:", resp.text)
    return resp

def call_applicationsummary(token):
    applicationsummary_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/applicationsummary/query"

    applicationsummary_payload = json.dumps(
     {
        "start_time": "2025-07-01T00:00:00Z",
        "end_time": "2025-07-02T00:00:00Z",
        "interval": "10sec",
        "view": "duration",
        "filter": {
            # These must be valid names/IDs known to your tenant
            "app": ["1750746346793022945"],
            "site": ["1741295428037016145"]
        },
        "metrics": ["ApplicationHealthscore"]
    }   
    )


    #applicationsummary_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/applicationsummary"
    headers = get_headers(token)
    print("GET applicationsummary_url = ",applicationsummary_url)
    resp = requests.post(applicationsummary_url, headers=headers, data=json.dumps(applicationsummary_payload))
    print("applicationsummary api status:", resp.status_code)
    print("applicationsummary api response:", resp.text)
    return resp

def call_aggregatebandwidth(token):
    aggregatebandwidth_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/aggregatebandwidth/query"
    #aggregatebandwidth_url = f"{BASE_API_URL}/sdwan/monitor/v2.0/api/monitor/agg_bw_stats"
    aggregatebandwidth_payload = {
        "end_time": "2025-05-22T17:18:03.662Z",
        "interval": "1month",
        "metrics": ["AggBandwidthUsage"],
        "start_time": "2025-04-28T17:18:03.662Z",
        "view": "duration"
    }
    {
    "duration": "2024-07-29",
    "max_agg_bw": 0,
    "max_agg_bw_time": "2024-07-29",
    "site_id": "1741378371338024045"
    }
    #payload={}
    headers = get_headers(token)
    #print("GET aggregatebandwidth_url = ",aggregatebandwidth_url)
    resp = requests.post(aggregatebandwidth_url, headers=headers, data=json.dumps(aggregatebandwidth_payload))
    print("aggregatebandwidth api status:", resp.status_code)
    #print("aggregatebandwidth api response:", resp.text)
    return resp

def call_interfacestatus(token):
    interfacestatus_url = f"{BASE_API_URL}/sdwan/v2.0/api/interfaces/status/query"
    headers = get_headers(token)
    interface_status_payload = {}


    resp = requests.get(interfacestatus_url, headers=headers)
    print("interfacestatus api status:", resp.status_code)
    print("interfacestatus api response:", resp.text)
    return resp

def get_all_interfaces_status(token):
    sites_url = f"{BASE_API_URL}/sdwan/v4.11/api/sites"
    headers = get_headers(token)
    sites_response = requests.get(sites_url, headers=headers)
    
    if sites_response.status_code != 200:
        print(f"Failed to fetch sites. Status code: {sites_response.status_code}")
        print(sites_response.text)
        return

    sites = sites_response.json().get("items", [])
    print(f"Found {len(sites)} sites\n")

    for site in sites:
        site_id = site.get("id")
        site_name = site.get("name")
        if not site_id:
            continue

        # Get WAN interfaces for the site
        wan_interfaces_url = f"{BASE_API_URL}/sdwan/v2.8/api/sites/{site_id}/waninterfaces"
        wan_interfaces_response = requests.get(wan_interfaces_url, headers=headers)
        if wan_interfaces_response.status_code != 200:
            print(f"  Failed to get WAN interfaces for site {site_name} ({site_id})")
            continue

        wan_interfaces = wan_interfaces_response.json().get("items", [])
        print(f"Site: {site_name} ({site_id}) - {len(wan_interfaces)} WAN interfaces")

        for wan_interface in wan_interfaces:
            wan_interface_id = wan_interface.get("id")
            if not wan_interface_id:
                continue

            status_url = f"{BASE_API_URL}/sdwan/v2.1/api/sites/{site_id}/waninterfaces/{wan_interface_id}/status"
            status_response = requests.get(status_url, headers=headers)
            if status_response.status_code != 200:
                print(f"    Failed to get status for interface {wan_interface_id}")
                continue

            status_json = status_response.json()
            operational_status = status_json.get("operational_state", "N/A")
            print(f"    WAN Interface {wan_interface_id}: Operational Status: {operational_status}")
        print()



if __name__ == '__main__':
    tenant_id = get_env_variable("TENANT_ID")
    token = get_token()
    get_profile(token)
    #call_alarms(token)
    call_appdefs(token)
    #call_aiops_health(token)
    call_applicationsummary(token) ##still wrong payload -> TBD
    #call_aggregatebandwidth(token)
    #call_interfacestatus(token)
    #get_all_interfaces_status(token)

