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
"""

import os, subprocess, argparse

# Map the -P flag to the filenames in your backup folder
POLICY_FILES = {
    "path": "01_backups/02_policies/path_policyconfig.yml",
    "qos": "01_backups/02_policies/qos_policyconfig.yml",
    "nat": "01_backups/02_policies/nat_policyconfig.yml",
    "security": "01_backups/02_policies/security_policyconfig.yml",
    "performance": "01_backups/02_policies/performance_policyconfig.yml"
}

def run_cmd(name, cmd, cwd):
    print(f"[*] Starting Restore: {name}")
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{os.getcwd()}:{env.get('PYTHONPATH', '')}"
    try:
        subprocess.run(cmd, cwd=cwd, check=True, shell=True, env=env)
        print(f"[+] {name} Success.\n")
    except Exception as e:
        print(f"[!] {name} Failed: {e}\n")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-R", "--resources", action="store_true")
    parser.add_argument("-P", "--policies", nargs='?', const='all')
    parser.add_argument("-S", "--site")
    # --- ADDED THIS LINE ---
    parser.add_argument("-F", "--filename", help="Specific YAML file to use")
    args = parser.parse_args()

    if args.resources:
        # Use provided filename or default
        fname = args.filename or "../01_backups/01_resources/latest_resources.yml"
        run_cmd("Resources", f"python3 push_resources_refactored.py --filename '{fname}'", "02_policy_scripts")

    if args.policies:
        targets = ["nat", "path", "qos", "security", "performance"] if args.policies == "all" else [args.policies]
        for p in targets:
            if p in POLICY_FILES:
                # If you provided a filename in the terminal, use it. 
                # Otherwise, use the one from the POLICY_FILES map.
                raw_path = args.filename if args.filename else f"../{POLICY_FILES[p]}"
                
                # Check if the path needs a '../' prefix (if it doesn't have one and is a relative project path)
                if args.filename and not args.filename.startswith("..") and not args.filename.startswith("/"):
                    final_path = f"../{args.filename}"
                else:
                    final_path = raw_path

                cmd = f"python3 push_policy.py -PT {p} -F '{final_path}'"
                run_cmd(f"Policy: {p}", cmd, "02_policy_scripts")

    if args.site:
        fname = args.filename or f"../01_backups/03_sites/{args.site}.yml"
        run_cmd(f"Site: {args.site}", f"python3 do_site.py --force-update '{fname}'", "03_config_tool")

if __name__ == "__main__":
    main()
