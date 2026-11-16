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
import csv
import sys
import prisma_sase

def extract_active_fw(firmware_list):
    """
    Parses the firmware array and returns the fw_version 
    where 'active' is set to True.
    """
    if not isinstance(firmware_list, list):
        return "Unknown"
    for fw in firmware_list:
        if fw.get("active"):
            return fw.get("fw_version", "Unknown")
    return "Unknown"

def main():
    # Initialize the Prisma SASE SDK
    sase_session = prisma_sase.API()
    
    # Prompt for credentials/token
    print("Authenticating to Prisma SASE...")
    sase_session.interactive.login_interactive()
    
    print("Fetching Sites...")
    sites_resp = sase_session.get.sites()
    if not sites_resp.cgx_status:
        print("Error fetching sites. Check your permissions.")
        sys.exit(1)
        
    # Map site IDs to site Names for the report
    sites_map = {site["id"]: site["name"] for site in sites_resp.cgx_content.get("items", [])}
    
    print("Fetching Elements...")
    elements_resp = sase_session.get.elements()
    if not elements_resp.cgx_status:
        print("Error fetching elements.")
        sys.exit(1)
        
    elements = elements_resp.cgx_content.get("items", [])
    report_data = []
    
    print("Scanning elements for Cellular Modules... (this may take a moment)")
    for element in elements:
        site_id = element.get("site_id")
        
        # Skip unassigned elements (devices not placed in a site)
        if not site_id:
            continue 
            
        element_id = element.get("id")
        element_name = element.get("name")
        site_name = sites_map.get(site_id, "Unknown Site")
        
        # Query cellular modules for this specific element
        cell_modules_uri = f"/sdwan/v2.1/api/elements/{element_id}/cellular_modules"
        cell_resp = sase_session.rest_call(method="GET", uri=cell_modules_uri)
        
        # If the element has cellular modules, loop through them
        if cell_resp.cgx_status and "items" in cell_resp.cgx_content:
            for module in cell_resp.cgx_content["items"]:
                module_id = module.get("id")
                
                # Fetch the detailed status using the endpoint you provided
                status_uri = f"/sdwan/v2.1/api/elements/{element_id}/cellular_modules/{module_id}/status"
                status_resp = sase_session.rest_call(method="GET", uri=status_uri)
                
                if status_resp.cgx_status:
                    status = status_resp.cgx_content
                    
                    # Parse nested dictionaries safely
                    net_state = status.get("network_state", {})
                    freq_band = net_state.get("frequency_band", "")
                    
                    # Parse out the currently active firmware
                    active_fw = extract_active_fw(status.get("firmware", []))
                    
                    # Append flat data to our report
                    report_data.append({
                        "Site Name": site_name,
                        "Element Name": element_name,
                        "Model Name": status.get("model_name"),
                        "Manufacturer": status.get("manufacturer"),
                        "IMEI": status.get("imei"),
                        "Serial Number": status.get("serial_number"),
                        "Modem State": status.get("modem_state"),
                        "Carrier": status.get("carrier"),
                        "Active SIM": status.get("active_sim"),
                        "Signal Strength": status.get("signal_strength_indicator"),
                        "Network Reg State": status.get("network_registration_state"),
                        "Packet Service State": status.get("packet_service_state"),
                        "Activation State": status.get("activation_state"),
                        "Frequency Band": freq_band,
                        "Active FW Version": active_fw
                    })
                    
    if not report_data:
        print("No cellular modules found across any sites.")
        return
        
    # Write the collected data out to a CSV
    csv_filename = "cellular_modules_report.csv"
    headers = report_data[0].keys()
    
    with open(csv_filename, "w", newline="") as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=headers)
        writer.writeheader()
        writer.writerows(report_data)
        
    print(f"\nSuccess! Found {len(report_data)} cellular modules.")
    print(f"Report saved locally to: {csv_filename}")

if __name__ == "__main__":
    main()
