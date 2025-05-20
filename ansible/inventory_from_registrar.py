#!/usr/bin/env python3
import json
import requests
import argparse
import os
import sys
import urllib3 # For disabling SSL warnings if needed

# --- Configuration ---
# URL of your pi-registrar's /targets endpoint
# IMPORTANT: Use the hostname that is actually IN your certificate's CN or SAN.
# If your cert's CN is 'AeroScan' and you added its IP to SAN,
# and your /etc/hosts or DNS resolves 'AeroScan' to your server's IP, use 'AeroScan'.
# If you only have the IP in SAN, you might need to use the IP here,
# but then the cert must have that IP in SAN.
# For now, assuming 'AeroScan' is resolvable to your server (e.g. via /etc/hosts on it06)
# or you will use the server's actual IP that IS in the cert's SAN.
# If connecting to an IP, the cert MUST have that IP in its SAN.
# If connecting to a hostname (e.g. 'AeroScan'), the cert MUST have that hostname in CN/SAN.

# Option 1: If 'AeroScan' resolves to your server IP (10.51.33.17) on it06 machine
# And your certificate CN is 'AeroScan' OR 'AeroScan' is in SAN.
REGISTRAR_HOSTNAME_IN_CERT = "AeroScan" # The name in the certificate
REGISTRAR_URL_FOR_TARGETS = f"https://{REGISTRAR_HOSTNAME_IN_CERT}:5001/targets"

# Option 2: If you want to connect via IP directly (ensure this IP is in cert's SAN)
# SERVER_IP_IN_CERT = "10.51.33.17" # The IP address in your certificate's SAN
# REGISTRAR_URL_FOR_TARGETS = f"https://{SERVER_IP_IN_CERT}:5001/targets"

# Path to the pi-registrar's public certificate on this Ansible control node
# This file (cert.pem from Docker/config/certs/) must be copied here.
CERT_VERIFY_PATH = os.path.expanduser("~/AeroScan/ansible/config/pi_registrar_server.pem")

# API Key for accessing the registrar endpoint (currently /targets is open, but good for future)
REGISTRAR_ACCESS_API_KEY = os.environ.get("REGISTRAR_ACCESS_API_KEY")
# --- End Configuration ---

def get_inventory_from_targets():
    inventory = {
        "_meta": {"hostvars": {}},
        "pis": {"hosts": [], "vars": {
            "ansible_user": "aeroscan",
            "ansible_ssh_private_key_file": os.path.expanduser("~/.ssh/id_rsa"),
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_become": True,
            "ansible_become_method": "sudo"
        }},
        "all": {"children": ["ungrouped", "pis"]},
        "ungrouped": {}
    }
    headers = {}
    if REGISTRAR_ACCESS_API_KEY:
        # Adjust X-Api-Key header name if you implement it on /targets
        headers["X-Registrar-Targets-Api-Key"] = REGISTRAR_ACCESS_API_KEY

    verify_option = False # Default to no verification
    if REGISTRAR_URL_FOR_TARGETS.startswith("https://"):
        if os.path.exists(CERT_VERIFY_PATH):
            verify_option = CERT_VERIFY_PATH
        else:
            print(
                f"Warning: Registrar certificate for inventory ('{CERT_VERIFY_PATH}') not found. "
                "Proceeding without SSL certificate verification. THIS IS INSECURE.",
                file=sys.stderr
            )
            # Suppress only the InsecureRequestWarning
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        response = requests.get(REGISTRAR_URL_FOR_TARGETS, headers=headers, verify=verify_option, timeout=10)
        response.raise_for_status() # Will raise an HTTPError for bad responses (4xx or 5xx)
        targets_data = response.json()

        for target_group in targets_data:
            if "labels" in target_group and "pi_identifier" in target_group["labels"] and \
               "targets" in target_group and target_group["targets"]:

                pi_identifier = target_group["labels"]["pi_identifier"]
                ansible_hostname = pi_identifier.replace("-", "_").replace(".", "_") # Sanitize for Ansible

                # Target is "ip:port", we only need the IP
                ip_address_full = target_group["targets"][0]
                ip_address = ip_address_full.split(":")[0]

                inventory["pis"]["hosts"].append(ansible_hostname)
                inventory["_meta"]["hostvars"][ansible_hostname] = {
                    "ansible_host": ip_address
                }

    except requests.exceptions.SSLError as e:
        print(f"SSL Error connecting to registrar at '{REGISTRAR_URL_FOR_TARGETS}'. Cert Path: '{CERT_VERIFY_PATH}'. Error: {e}", file=sys.stderr)
        print("Ensure the URL uses a hostname/IP that is present in the server certificate's Common Name or Subject Alternative Names.", file=sys.stderr)
        print(f"If using a self-signed certificate, ensure '{CERT_VERIFY_PATH}' is the correct public certificate from the server.", file=sys.stderr)
    except requests.exceptions.ConnectionError as e:
        print(f"Connection Error: Could not connect to registrar at '{REGISTRAR_URL_FOR_TARGETS}'. Is it running? Error: {e}", file=sys.stderr)
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error fetching inventory: {e.response.status_code} {e.response.text}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching inventory from registrar: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON inventory from registrar. Status: {response.status_code}. Error: {e}. Response text: {response.text[:200]}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred in get_inventory_from_targets: {type(e).__name__} {e}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)


    return inventory

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true', help="List all groups and hosts")
    parser.add_argument('--host', type=str, help="Get all variables about a specific host")
    args = parser.parse_args()

    if args.list:
        inventory_to_print = get_inventory_from_targets()
        print(json.dumps(inventory_to_print, indent=4))
    elif args.host:
        # Ansible expects host-specific vars if it calls with --host.
        # For this dynamic inventory, all hostvars are typically in _meta from --list.
        # So, returning an empty JSON object for a single host call is usually fine,
        # as Ansible will merge it with what it got from _meta.
        print(json.dumps({})) # Or {"_meta": {"hostvars": {args.host: {}}}} if you want to be more specific
    else:
        # If called without --list or --host, it's likely an Ansible probe.
        # Exit gracefully without printing JSON that could be misinterpreted as a full, empty inventory.
        # Or, some inventory systems expect an empty JSON object {} in this case.
        # Let's try exiting, as Ansible's script plugin primarily cares about --list.
        # If Ansible's 'auto' plugin has issues with no output, then print an empty JSON object.
        # Forcing an error or no output here might make Ansible correctly identify it as a script needing --list.
        # A common practice is to return an empty JSON object if no arguments are matched.
        print(json.dumps({})) # Outputting an empty JSON object is safer for auto-detection
        sys.exit(0)
