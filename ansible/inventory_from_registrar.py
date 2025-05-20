#!/usr/bin/env python3
import json
import requests
import argparse
import os
import sys

# Configuration for accessing pi-registrar
# Assumes pi-registrar is accessible from the Ansible control node
# If Ansible runs in Docker, this would be https://pi-registrar:5000/...
# If Ansible runs on host, and pi-registrar port 5001 is mapped to host 5000 (container),
# and pi-registrar serves HTTPS on its port 5000:
REGISTRAR_URL_FOR_TARGETS = os.environ.get("REGISTRAR_TARGETS_URL", "https://localhost:5001/targets") # Example if testing from host via exposed port
# If your pi-registrar exposes a dedicated /ansible_inventory endpoint as discussed:
# REGISTRAR_URL_FOR_INVENTORY = "https://localhost:5001/ansible_inventory" # Or Docker service name if Ansible is also in Docker
# For now, let's derive inventory from the /targets endpoint for simplicity.

# Path to the pi-registrar's public certificate on this Ansible control node
# You need to copy cert.pem from Docker/config/certs/ to this location
CERT_VERIFY_PATH = os.path.expanduser("~/AeroScan/ansible/config/pi_registrar_server.pem")

# API Key for accessing the registrar endpoint (if you secured /targets or a future /ansible_inventory)
REGISTRAR_API_KEY = os.environ.get("REGISTRAR_ACCESS_API_KEY") # Example

def get_inventory_from_targets():
    inventory = {
        "_meta": {"hostvars": {}},
        "pis": {"hosts": [], "vars": {
            "ansible_user": "pi", # CHANGE if your Pi user is different
            "ansible_ssh_private_key_file": os.path.expanduser("~/.ssh/id_rsa"), # Assumes default key
            "ansible_python_interpreter": "/usr/bin/python3",
            "ansible_become": True, # Assume most operations will need sudo
            "ansible_become_method": "sudo"
            # For passwordless sudo, ensure it's set up on Pis for ansible_user
            # If not, Ansible will prompt or you need ansible_become_pass (less secure)
        }},
        "all": {"children": ["ungrouped", "pis"]},
        "ungrouped": {}
    }
    headers = {}
    if REGISTRAR_API_KEY:
        headers["X-Some-Api-Key-For-Registrar"] = REGISTRAR_API_KEY # Adjust header name as needed

    try:
        verify_option = CERT_VERIFY_PATH if os.path.exists(CERT_VERIFY_PATH) else False
        if not verify_option and REGISTRAR_URL_FOR_TARGETS.startswith("https://"):
            print("Warning: Registrar certificate for inventory not found for verification, proceeding without SSL cert validation. THIS IS INSECURE.", file=sys.stderr)
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Fetching from /targets endpoint of pi-registrar
        # This endpoint returns a list of target objects.
        # Example target object: {"targets": ["ip:port"], "labels": {"pi_identifier": "id", ...}}
        response = requests.get(REGISTRAR_URL_FOR_TARGETS, headers=headers, verify=verify_option, timeout=10)
        response.raise_for_status()
        targets_data = response.json() # Expects a list of target groups

        for target_group in targets_data:
            if "labels" in target_group and "pi_identifier" in target_group["labels"] and "targets" in target_group and target_group["targets"]:
                pi_identifier = target_group["labels"]["pi_identifier"]
                # Sanitize identifier for use as Ansible hostname
                ansible_hostname = pi_identifier.replace("-", "_").replace(".", "_")

                # Assuming target is "ip:port"
                ip_address = target_group["targets"][0].split(":")[0]

                inventory["pis"]["hosts"].append(ansible_hostname)
                inventory["_meta"]["hostvars"][ansible_hostname] = {
                    "ansible_host": ip_address
                    # Add other Pi-specific vars here if needed, fetched from labels perhaps
                }

    except requests.exceptions.SSLError as e:
        print(f"SSL Error connecting to registrar for inventory: {e}. Check cert: {CERT_VERIFY_PATH}", file=sys.stderr)
    except requests.exceptions.RequestException as e:
        print(f"Error fetching inventory from registrar: {e}", file=sys.stderr)
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON inventory from registrar: {e}. Response: {response.text[:200]}", file=sys.stderr)
    except Exception as e:
        print(f"An unexpected error occurred in get_inventory_from_targets: {e}", file=sys.stderr)

    return inventory

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--host', type=str)
    args = parser.parse_args()

    inventory_to_print = {"_meta": {"hostvars": {}}} # Default to empty on error or non-list call
    if args.list:
        inventory_to_print = get_inventory_from_targets()
    elif args.host:
        # For --host, Ansible expects vars for that specific host.
        # We can regenerate the full inventory and extract if needed, or just return empty.
        # For simplicity with --list driven inventory:
        pass # Ansible will get hostvars from _meta if populated by --list

    print(json.dumps(inventory_to_print, indent=4))
