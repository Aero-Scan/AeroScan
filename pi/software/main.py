# Complete Python script for Raspberry Pi Network Monitor with HTTP SD Reporting

import time
import subprocess
import re
import multiprocessing
from prometheus_client import start_http_server, Gauge
import speedtest
import RPi.GPIO as GPIO
import os
import base64
import requests
import urllib3

# --- Configuration ---
PROMETHEUS_PORT = 8000
PING_TARGET = "1.1.1.1"
# Primary wireless interface
WIRELESS_INTERFACE = "wlan0"
# Primary LAN interface, set to None if not used or to be ignored
LAN_INTERFACE = "eth0"
BUTTON_PIN_1 = 23
BUTTON_PIN_2 = 24

LOOP_SLEEP_INTERVAL = 0.1
# How often to run ping, scan, wireless metrics, IP check (seconds)
PING_SCAN_IP_INTERVAL = 30
# How often to start/check speedtest (seconds)
SPEEDTEST_CHECK_INTERVAL = 60

# Files for persistent data and configuration
IDENTIFIER_FILE = "/var/local/network_monitor_identifier.txt"
# Should contain full URL e.g. https://server:5001/register
REGISTRAR_CONFIG_FILE = "/var/local/network_monitor_registrar_url.txt"
# Should contain the shared API key
API_KEY_FILE = "/var/local/network_monitor_api_key.txt"

# Default Registrar URL (will be overridden by REGISTRAR_CONFIG_FILE)
DEFAULT_REGISTRAR_API_URL = "https://PLEASE_CONFIGURE_IN_FILE:5001/register"
# Initialize with default
REGISTRAR_API_URL = DEFAULT_REGISTRAR_API_URL

# Path to the server's public certificate on the Pi (for HTTPS verification)
# This file must be copied from the server (Docker host) to this Pi.
SERVER_CERT_PATH_ON_PI = "/etc/ssl/certs/pi_registrar_server.pem"

# Report to registrar every 5 minutes (heartbeat)
API_REPORT_INTERVAL = 300

# Flags to control interface binding for tests
PING_THROUGH_WIFI_ONLY = True
SPEEDTEST_THROUGH_WIFI_ONLY = True

# --- Global variable for Pi's API Key ---
# Will be loaded from API_KEY_FILE
PI_SHARED_API_KEY = None

# --- Prometheus Gauges ---
PING_RESPONSE_TIME = Gauge('network_ping_response_time_ms', 'Ping response time in ms (first packet)')
NETWORK_TTL = Gauge('network_ttl', 'Ping TTL value (first packet)')
SPEEDTEST_PING = Gauge('speedtest_ping_ms', 'Speedtest ping in ms')
DOWNLOAD_SPEED = Gauge('download_speed_mbps', 'Download speed in Mbps')
UPLOAD_SPEED = Gauge('upload_speed_mbps', 'Upload speed in Mbps')
# Note: Original SIGNAL_STRENGTH and LINK_QUALITY gauges are now superseded by
# CONNECTED_AP_SIGNAL and CONNECTED_AP_QUALITY for clarity with labeled metrics.
# If you still need the old unlabeled ones for some reason, you can reinstate them,
# but the new labeled ones are more specific to the connected AP.

# Signal strength of nearby WiFi APs (via nmcli)
WIFI_AP_SIGNAL = Gauge('wifi_ap_signal_strength_dbm', 'Signal strength of nearby WiFi APs (via nmcli)', ['ssid', 'bssid', 'channel'])
DEVICE_IDENTIFIER = Gauge('device_unique_identifier', 'Unique identifier for the device (SN-Base64Timestamp)', ['identifier'])
NETWORK_INTERFACE_INFO = Gauge('network_interface_info', 'Basic network interface information (IP Address)', ['interface', 'ip_address'])

# --- New Prometheus Gauges for Connected AP Details ---
# Stores labels of the currently connected AP for metric removal on change
# Format: { 'interface_name': {'bssid': 'xx', 'ssid': 'yy', 'channel': 'cc'}, ... }
current_ap_metric_labels = {}

# Gauge for information about the AP the interface is currently connected to
CONNECTED_AP_DETAILS = Gauge('network_interface_connected_ap_details',
                             'Details of the Access Point the interface is connected to',
                             ['interface', 'bssid', 'ssid', 'channel'])
# Gauge for signal strength of the connected AP
CONNECTED_AP_SIGNAL = Gauge('network_interface_connected_ap_signal_dbm',
                            'Signal strength (dBm) of the AP the interface is connected to',
                            ['interface', 'bssid', 'ssid'])
# Gauge for link quality of the connected AP
CONNECTED_AP_QUALITY = Gauge('network_interface_connected_ap_link_quality_percentage',
                             'Link quality (%) of the connection to the AP',
                             ['interface', 'bssid', 'ssid'])

# --- Global Variables ---
current_device_id_label = None
raspberry_pi_serial = None
buttons_currently_pressed = False
last_check_times = { "ping_scan_ip": 0, "speedtest": 0 }
speedtest_process = None
speedtest_queue = None
# Stores {interface_name: ip_address}
current_ip_labels = {}
last_api_report_time = 0
# Tracks the IP last successfully reported to the registrar
last_reported_ip_for_api = None

# --- Network Metric Functions ---
def get_ip_address_for_interface(interface_name):
    """Helper function to get current IPv4 for a specific interface."""
    if not interface_name:
        return None
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface_name],
            capture_output=True, text=True, check=True, timeout=2
        )
        ip_match = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", result.stdout)
        if ip_match:
            return ip_match.group(1)
    except Exception as e:
        # Less verbose for a helper, as this is called often
        print(f"  Could not get IP for {interface_name} (helper function): {type(e).__name__}")
    return None

def run_ping_checks(target=PING_TARGET, interface_to_use=None):
    global PING_RESPONSE_TIME, NETWORK_TTL, NETWORK_JITTER
    """
    Runs ping checks to the specified target, optionally via a specific interface.
    Updates PING_RESPONSE_TIME, NETWORK_TTL, and NETWORK_JITTER gauges.
    """
    response_time = -1
    ttl = -1
    jitter = -1

    ping_cmd_base = ["ping", "-c", "5", "-w", "5", target]
    # For logging purposes
    ping_cmd_display = " ".join(ping_cmd_base)

    if interface_to_use:
        print(f"Running ping checks to {target} via interface {interface_to_use}...")
        ping_cmd = ["ping", "-I", interface_to_use, "-c", "5", "-w", "5", target]
        ping_cmd_display = " ".join(ping_cmd)
    else:
        print(f"Running ping checks to {target} (default interface)...")
        ping_cmd = ping_cmd_base

    try:
        result = subprocess.run(ping_cmd, capture_output=True, text=True, check=True, timeout=6)
        output = result.stdout
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)
        times = list(map(float, times_matches))

        if times:
            response_time = times[0]
            # TTL might not be in all ping replies (e.g., first can be from gateway)
            if ttl_matches:
                ttl = int(ttl_matches[0])
        else:
            print(f"  Ping ({ping_cmd_display}): No replies received.")

        if len(times) >= 2:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
            jitter = sum(diffs) / len(diffs)
        elif len(times) == 1:
            # Jitter is 0 if only one reply
            jitter = 0
    except subprocess.CalledProcessError as e:
        error_detail = e.stderr.strip() if e.stderr else e.stdout.strip()
        if interface_to_use and "Cannot assign requested address" in error_detail:
            print(f"  Ping error for {target} via {interface_to_use}: Interface likely has no IP or route. {error_detail}")
        else:
            print(f"  Ping error for {target} (cmd: {ping_cmd_display}): {e}. Output: {error_detail}")
    except subprocess.TimeoutExpired:
        print(f"  Ping command timed out for {target} (cmd: {ping_cmd_display})")
    except FileNotFoundError:
        print("  Error: 'ping' command not found.")
    except Exception as e:
        print(f"  Unexpected error in run_ping_checks (cmd: {ping_cmd_display}): {e}")

    PING_RESPONSE_TIME.set(response_time)
    NETWORK_TTL.set(ttl)
    NETWORK_JITTER.set(jitter)

def unescape_nmcli_field(field_value):
    """Removes backslash escaping from colons in nmcli terse output fields."""
    if field_value is None:
        return None
    return field_value.replace('\\:', ':')

def update_connected_ap_metrics(interface=WIRELESS_INTERFACE):
    """
    Updates Prometheus metrics with details of the currently connected Access Point
    for the given wireless interface. Uses a combination of iwconfig and nmcli.
    """
    global current_ap_metric_labels

    if not interface:
        print(f"  Skipping connected AP metrics: No interface specified.")
        return

    print(f"Updating connected AP metrics for {interface}...")

    final_bssid = None
    final_ssid = "<NotConnected>" # Default if not found
    final_channel = "N/A"
    final_signal_dbm = -100 # Default to very low if not found/connected
    final_link_quality_percent = 0 # Default to 0 if not found/connected

    iwconfig_details = {}

    # Step 1: Use iwconfig to get BSSID, Signal Strength (dBm), Link Quality
    # These are often reliable for the current association.
    try:
        result_iwconfig = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, check=False, timeout=5 # check=False to parse output even on error
        )
        output_iwconfig = result_iwconfig.stdout

        bssid_match = re.search(r"Access Point:\s*([0-9A-Fa-f:]{17})", output_iwconfig)
        # Ensure BSSID is valid and not a placeholder for "not associated"
        if bssid_match and bssid_match.group(1).upper() not in ["NOT-ASSOCIATED", "00:00:00:00:00:00"]:
            iwconfig_details['bssid'] = bssid_match.group(1).upper()

        signal_match = re.search(r"Signal level=(-?\d+)\s*dBm", output_iwconfig)
        if signal_match:
            iwconfig_details['signal_dbm'] = int(signal_match.group(1))

        quality_match = re.search(r"Link Quality=(\d+)/(\d+)", output_iwconfig)
        if quality_match:
            q_curr, q_max = map(int, quality_match.groups())
            iwconfig_details['link_quality_percent'] = (q_curr / q_max * 100) if q_max > 0 else 0

        ssid_match_iwconfig = re.search(r'ESSID:"([^"]*)"', output_iwconfig)
        if ssid_match_iwconfig and ssid_match_iwconfig.group(1):
            iwconfig_details['ssid'] = ssid_match_iwconfig.group(1)

    except FileNotFoundError:
        print("  Error: 'iwconfig' command not found. Cannot get connected AP details via iwconfig.")
    except subprocess.TimeoutExpired:
        print(f"  iwconfig command timed out for {interface}.")
    except Exception as e:
        print(f"  Error running/parsing iwconfig for {interface}: {e}")

    # Prioritize iwconfig for these values if available
    if iwconfig_details.get('bssid'):
        final_bssid = iwconfig_details['bssid']
        if 'ssid' in iwconfig_details:
            final_ssid = iwconfig_details['ssid']
        if 'signal_dbm' in iwconfig_details:
            final_signal_dbm = iwconfig_details['signal_dbm']
        if 'link_quality_percent' in iwconfig_details:
            final_link_quality_percent = iwconfig_details['link_quality_percent']
    else:
        # If iwconfig shows not connected or fails to get BSSID, clear metrics and return.
        print(f"  {interface} not associated according to iwconfig or BSSID not found.")
        last_labels_for_interface = current_ap_metric_labels.get(interface)
        if last_labels_for_interface: # If there were previous metrics, remove them
            print(f"  Clearing metrics for previously connected AP on {interface}: {last_labels_for_interface.get('bssid')}")
            try:
                CONNECTED_AP_DETAILS.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'], last_labels_for_interface['ssid'], last_labels_for_interface['channel'])
                CONNECTED_AP_SIGNAL.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'], last_labels_for_interface['ssid'])
                CONNECTED_AP_QUALITY.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'], last_labels_for_interface['ssid'])
            except KeyError: # Ok if some labels were already gone or never set
                pass
            except Exception as e:
                print(f"  Error removing old AP metrics on disconnect: {e}")
            current_ap_metric_labels[interface] = None
        return # Exit function as we are not connected

    # Step 2: If connected (final_bssid is set from iwconfig), use nmcli to confirm/get SSID and Channel.
    # nmcli can sometimes provide a more reliable SSID and is good for channel info.
    if final_bssid:
        try:
            # Request ACTIVE, BSSID, SSID, CHAN, SIGNAL. SIGNAL is quality %
            # Using --rescan no because scan_wifi_aps_nmcli (for all APs) performs a rescan.
            nmcli_cmd = ["nmcli", "-t", "-f", "ACTIVE,BSSID,SSID,CHAN,SIGNAL", "dev", "wifi", "list", "ifname", interface, "--rescan", "no"]
            result_nmcli_list = subprocess.run(nmcli_cmd, capture_output=True, text=True, check=True, timeout=7)

            found_in_nmcli = False
            for line in result_nmcli_list.stdout.strip().splitlines():
                # nmcli terse output uses '\:' for literal colons within fields.
                # Replace '\:' with a temporary placeholder before splitting, then restore.
                placeholder = "&&COLON_PLACEHOLDER&&"
                line_with_placeholders = line.replace("\\:", placeholder)
                parts_raw = line_with_placeholders.split(':')

                # Restore placeholders to actual colons in each part
                parts = [p.replace(placeholder, ":") for p in parts_raw]

                # Expecting ACTIVE, BSSID, SSID, CHAN, SIGNAL (5 fields if SIGNAL is present)
                if len(parts) >= 4: # Need at least ACTIVE, BSSID, SSID, CHAN
                    nm_active = parts[0].strip().upper()
                    nm_bssid = parts[1].strip().upper()
                    nm_ssid = parts[2].strip()
                    nm_chan = parts[3].strip()
                    nm_signal_quality_str = None
                    if len(parts) >= 5:
                        nm_signal_quality_str = parts[4].strip()

                    if nm_active == 'YES' and nm_bssid == final_bssid:
                        if nm_ssid and nm_ssid != '--':
                            final_ssid = nm_ssid # nmcli SSID often more reliable
                        elif not nm_ssid and final_ssid == "<NotConnected>":
                            final_ssid = "<empty_ssid_nmcli>"

                        if nm_chan and nm_chan != '--':
                            final_channel = nm_chan

                        # If iwconfig didn't give signal_dbm, AND nmcli provided SIGNAL
                        if 'signal_dbm' not in iwconfig_details and nm_signal_quality_str and nm_signal_quality_str != '--':
                            try:
                                quality = int(nm_signal_quality_str)
                                if 0 <= quality <= 100:
                                    final_signal_dbm = (quality / 2.0) - 100.0 # Approximate
                                    print(f"  Used nmcli signal quality {quality}% -> approx {final_signal_dbm:.1f} dBm for {final_bssid}")
                            except ValueError:
                                print(f"  Could not parse nmcli signal quality '{nm_signal_quality_str}' to int.")

                        found_in_nmcli = True
                        break

            if not found_in_nmcli:
                print(f"  Warning: BSSID {final_bssid} (from iwconfig) not found as ACTIVE in nmcli list for {interface}.")
                # If nmcli didn't confirm, ensure we use iwconfig's SSID if available and better than default
                if final_ssid == "<NotConnected>" and iwconfig_details.get('ssid'):
                    final_ssid = iwconfig_details['ssid']
                elif final_ssid == "<NotConnected>": # If still not found by either
                    final_ssid = "<SSID_not_found_nmcli_match>"

        except FileNotFoundError:
            print(f"  Error: 'nmcli' command not found when getting connected AP details.")
        except subprocess.TimeoutExpired:
            print(f"  nmcli command for connected AP timed out for {interface}.")
        except subprocess.CalledProcessError as e:
            print(f"  Failed to run nmcli for connected AP details: {e}. Output: {e.stderr.strip()}")
        except Exception as e:
            print(f"  Error running/parsing nmcli list for connected AP details on {interface}: {e}")
            # If nmcli fails, ensure we use iwconfig's SSID if available and better than default
            if final_ssid == "<NotConnected>" and iwconfig_details.get('ssid'):
                final_ssid = iwconfig_details['ssid']
            elif final_ssid == "<NotConnected>":
                 final_ssid = "<SSID_lookup_failed_exception>"

    # ----- Prometheus Metric Update Logic -----
    last_labels_for_interface = current_ap_metric_labels.get(interface)

    if final_bssid:
        current_details_dict = {
            'interface': interface, 'bssid': final_bssid,
            'ssid': final_ssid, 'channel': final_channel
        }
        current_signal_quality_labels = {
            'interface': interface, 'bssid': final_bssid, 'ssid': final_ssid
        }

        # Check if AP has changed or if it was previously disconnected
        if not last_labels_for_interface or last_labels_for_interface.get('bssid') != final_bssid:
            if last_labels_for_interface: # It means AP changed, so remove old metrics
                print(f"  AP Changed for {interface}. Old BSSID: {last_labels_for_interface.get('bssid')}, New BSSID: {final_bssid}")
                try:
                    CONNECTED_AP_DETAILS.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'],
                                                last_labels_for_interface['ssid'], last_labels_for_interface['channel'])
                    CONNECTED_AP_SIGNAL.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'],
                                               last_labels_for_interface['ssid'])
                    CONNECTED_AP_QUALITY.remove(last_labels_for_interface['interface'], last_labels_for_interface['bssid'],
                                                last_labels_for_interface['ssid'])
                except KeyError:
                    # This can happen if a label combination was never set or already removed
                    print(f"  Note: One or more old AP metric labels for {last_labels_for_interface.get('bssid')} not found for removal.")
                except Exception as e:
                    print(f"  Error removing old AP metrics: {e}")

            CONNECTED_AP_DETAILS.labels(**current_details_dict).set(1)
            print(f"  Connected to AP on {interface}: BSSID={final_bssid}, SSID='{final_ssid}', Chan={final_channel}")

        # Always update potentially dynamic values
        CONNECTED_AP_SIGNAL.labels(**current_signal_quality_labels).set(final_signal_dbm)
        CONNECTED_AP_QUALITY.labels(**current_signal_quality_labels).set(final_link_quality_percent)

        # Store the current labels for the next check
        current_ap_metric_labels[interface] = current_details_dict
        print(f"  Metrics for {interface} -> {final_ssid} ({final_bssid}): Signal={final_signal_dbm:.1f}dBm, Quality={final_link_quality_percent:.1f}%")
    # The 'else' (not connected) part of this function was handled by the early return if iwconfig shows not associated.

def run_speedtest_child(result_queue, interface_to_use_for_source_ip=None):
    """
    Child process function that runs the speedtest.
    Optionally tries to use a specific source IP for the test.
    Puts results dictionary {'ping', 'download', 'upload'} in the queue.
    """
    result_data = {'ping': -1, 'download': -1, 'upload': -1}
    source_ip = None

    if interface_to_use_for_source_ip:
        print(f"  Attempting speedtest via interface {interface_to_use_for_source_ip}...")
        source_ip = get_ip_address_for_interface(interface_to_use_for_source_ip)
        if not source_ip:
            print(f"  Warning: Could not get IP for interface {interface_to_use_for_source_ip}. Speedtest will use default IP or may fail.")
        else:
            print(f"  Using source IP {source_ip} (from {interface_to_use_for_source_ip}) for speedtest.")
    else:
        print("  Attempting speedtest using default OS IP selection...")

    try:
        print("  Starting speedtest process...")
        # Use secure=True for HTTPS for speedtest.net servers
        st_args = {"secure": True}
        if source_ip:
            st_args["source_address"] = source_ip

        st = speedtest.Speedtest(**st_args)
        st.get_best_server()
        d_bps = st.download()
        u_bps = st.upload()
        result_data['download'] = d_bps / 1e6 if d_bps is not None else -1
        result_data['upload'] = u_bps / 1e6 if u_bps is not None else -1
        results_dict = st.results.dict()
        # Ping from speedtest server
        result_data['ping'] = results_dict.get('ping', -1)
        print(f"  Speedtest Finished (Source IP used: {source_ip if source_ip else 'Default OS choice'}): "
              f"Ping={result_data['ping']:.2f} ms, "
              f"Download={result_data['download']:.2f} Mbps, "
              f"Upload={result_data['upload']:.2f} Mbps")
    except speedtest.ConfigRetrievalError as e:
        print(f"  Speedtest ConfigRetrievalError (DNS/connectivity issue to speedtest.net config): {e}")
    except speedtest.NoMatchedServers as e:
        print(f"  Speedtest NoMatchedServers (could be due to source IP or network restrictions): {e}")
    # Catch other speedtest-specific errors
    except speedtest.SpeedtestException as e:
        print(f"  Speedtest library failed: {e}")
    # Catch any other unexpected errors
    except Exception as e:
        print(f"  Speedtest process failed unexpectedly: {e}")
    finally:
        result_queue.put(result_data)

def get_nmcli_header_map(header_line_content):
    """
    Creates a map of column names to indices from nmcli header line for AP scanning.
    Assumes the relevant data columns (BSSID, SSID etc.) appear after any IN-USE marker/column.
    """
    temp_header = header_line_content.strip()
    # If "IN-USE" is the first distinct field, remove it to align with data parsing
    # This regex removes the first non-whitespace sequence and the spaces after it.
    if temp_header.upper().startswith("IN-USE"):
        temp_header = re.sub(r"^\S+\s+", "", temp_header, count=1)

    headers_raw = re.split(r'\s{2,}', temp_header)
    header_map = {name.upper().strip(): i for i, name in enumerate(headers_raw)}

    required_data_headers = ["BSSID", "SSID", "CHAN", "SIGNAL"]
    missing = [h for h in required_data_headers if h not in header_map]
    if missing:
        print(f"  Error: nmcli AP scan header (after IN-USE strip) missing required fields: {missing}.")
        print(f"  Original header: '{header_line_content}', Processed for map: '{temp_header}', Map: {header_map}")
        return None
    return header_map

def parse_nmcli_wifi_line(line_content, header_map):
    """
    Parses a single data line of 'nmcli dev wifi list' output for AP scanning.
    """
    ap = {}
    line_to_parse = line_content.strip()

    # If line starts with '*', it's the IN-USE AP; strip the '*' and leading space(s)
    # to align its structure with other lines for consistent splitting.
    if line_to_parse.startswith("*"):
        line_to_parse = re.sub(r"^\*\s+", "", line_to_parse, count=1)

    parts = re.split(r'\s{2,}', line_to_parse)

    try:
        def get_part(field_name):
            idx = header_map.get(field_name.upper())
            if idx is not None and idx < len(parts):
                return parts[idx]
            return None

        ap['bssid'] = get_part("BSSID")
        ap['ssid'] = get_part("SSID")
        ap['channel'] = get_part("CHAN")
        signal_quality_str = get_part("SIGNAL")

        if signal_quality_str and signal_quality_str != '--':
            quality = int(signal_quality_str)
            if 0 <= quality <= 100:
                # Approximate conversion from quality (0-100) to dBm
                ap['signal_dbm'] = (quality / 2.0) - 100.0
            else:
                # Invalid quality
                ap['signal_dbm'] = -101
        else:
            # Missing signal quality
            ap['signal_dbm'] = -102

        current_ssid = ap.get('ssid')
        if current_ssid == '--' or not current_ssid:
            ap['ssid'] = '<hidden_or_empty>'

        # Validate essential fields before returning
        if not ap.get('bssid') or not ap.get('channel') or 'signal_dbm' not in ap:
            return None
    except (IndexError, ValueError) as e:
        return None
    return ap

def scan_wifi_aps_nmcli(interface=WIRELESS_INTERFACE):
    """Scans for all nearby WiFi APs using nmcli and updates Prometheus metrics."""
    if not interface:
        print("  Skipping nmcli WiFi scan: No wireless interface configured.")
        WIFI_AP_SIGNAL.clear() # Clear previous metrics if not scanning
        return

    print(f"Scanning for ALL nearby WiFi APs on {interface} using nmcli...")
    aps = []

    rescan_cmd = ["nmcli", "dev", "wifi", "rescan", "ifname", interface]
    try:
        print(f"  Triggering Wi-Fi rescan on {interface} for AP list...")
        # Using check=False as rescan might return non-zero if no *new* APs found or if busy.
        subprocess.run(rescan_cmd, capture_output=True, text=True, check=False, timeout=10)
        print(f"  Rescan command sent. Waiting a moment for APs to appear...")
        time.sleep(4) # Adjust sleep time as needed for your environment
    except subprocess.TimeoutExpired:
        print(f"  nmcli rescan command timed out for {interface}.")
    except FileNotFoundError:
        print("  Error: 'nmcli' command not found for rescan.")
        WIFI_AP_SIGNAL.clear()
        return
    except Exception as e:
        print(f"  Unexpected error during nmcli rescan for AP list: {e}")

    list_cmd = ["nmcli", "dev", "wifi", "list", "ifname", interface]
    output_lines = [] # Initialize in case subprocess fails before assignment
    header_map = None
    try:
        result = subprocess.run(list_cmd, capture_output=True, text=True, check=True, timeout=15)
        output_lines = result.stdout.strip().splitlines()

        if not output_lines:
            print("  nmcli AP list output is empty after rescan.")
            WIFI_AP_SIGNAL.clear()
            return

        header_line_content = output_lines[0]
        data_lines_start_index = 1

        header_map = get_nmcli_header_map(header_line_content)
        if not header_map:
            WIFI_AP_SIGNAL.clear()
            print("  Failed to get header map from nmcli AP list output.")
            return

        for line_content in output_lines[data_lines_start_index:]:
            ap_data = parse_nmcli_wifi_line(line_content, header_map)
            if ap_data:
                aps.append(ap_data)

    except subprocess.TimeoutExpired:
        print(f"  nmcli AP list command timed out for {interface}")
    except subprocess.CalledProcessError as e:
        print(f"  Failed to run nmcli AP list: {e}. Output: {e.stderr.strip()}")
    except FileNotFoundError:
        print("  Error: 'nmcli' command not found for AP listing.")
    except Exception as e:
        print(f"  Error during WiFi AP list with nmcli: {e}")

    WIFI_AP_SIGNAL.clear()
    reported_bssids = set()
    valid_aps_count = 0

    if not aps and output_lines and header_map:
        print("  Warning: nmcli returned AP data, but no APs were successfully parsed.")
    elif not aps:
        print("  No AP data collected from nmcli AP scan.")

    for ap_dict_item in aps:
        if ap_dict_item.get('bssid') and ap_dict_item['bssid'] not in reported_bssids:
            try:
                # Ensure all necessary keys exist (parse_nmcli_wifi_line should ensure this)
                if not all(k in ap_dict_item for k in ('ssid', 'bssid', 'channel', 'signal_dbm')):
                    continue

                sanitized_ssid = re.sub(r'[^a-zA-Z0-9_:]', '_', ap_dict_item['ssid'])
                if not sanitized_ssid:
                    sanitized_ssid = "_invalid_ssid_chars_"

                WIFI_AP_SIGNAL.labels(
                    ssid=sanitized_ssid, bssid=ap_dict_item['bssid'], channel=str(ap_dict_item['channel'])
                ).set(ap_dict_item['signal_dbm'])
                reported_bssids.add(ap_dict_item['bssid'])
                valid_aps_count += 1
            except Exception as label_err:
                print(f"  Error setting label for AP {ap_dict_item.get('ssid','N/A')}. Error: {label_err}")

    print(f"  nmcli AP scan: Found and processed {valid_aps_count} unique nearby APs after rescan.")
    if not valid_aps_count and len(output_lines) > 1 : # If we had output lines but processed none
        print("  No APs were successfully processed into metrics, though nmcli AP list output was present.")


def update_device_ip(interface_to_check):
    """Gets the device's IPv4 address for the specified interface and updates Prometheus."""
    global current_ip_labels
    # Skip if interface name is None or empty
    if not interface_to_check:
        return

    print(f"Checking IP address for {interface_to_check}...")
    current_ip_for_this_interface = None
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface_to_check],
            capture_output=True, text=True, check=True, timeout=3
        )
        ip_match = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", result.stdout)
        if ip_match:
            current_ip_for_this_interface = ip_match.group(1)
            print(f"  Found IP for {interface_to_check}: {current_ip_for_this_interface}")
        else:
            print(f"  No IPv4 address found for {interface_to_check}.")
    except FileNotFoundError:
        print(f"  Error: 'ip' command not found (checking {interface_to_check}).")
    except subprocess.TimeoutExpired:
        print(f"  'ip addr show' command timed out for {interface_to_check}")
    except subprocess.CalledProcessError:
        # This can happen if the interface doesn't exist or is down
        print(f"  Failed to get IP for {interface_to_check} (interface might be down/not exist).")
    except Exception as e:
        print(f"  Error getting IP address for {interface_to_check}: {e}")

    last_known_ip = current_ip_labels.get(interface_to_check)
    if current_ip_for_this_interface != last_known_ip:
        if last_known_ip:
            try:
                NETWORK_INTERFACE_INFO.remove(interface_to_check, last_known_ip)
                print(f"  Removed old IP label: {interface_to_check} / {last_known_ip}")
            except KeyError:
                # This is okay if the label didn't exist for some reason
                pass
            except Exception as e:
                print(f"  Error removing old IP label {interface_to_check} / {last_known_ip}: {e}")
        if current_ip_for_this_interface:
            try:
                NETWORK_INTERFACE_INFO.labels(interface=interface_to_check, ip_address=current_ip_for_this_interface).set(1)
                current_ip_labels[interface_to_check] = current_ip_for_this_interface
                print(f"  Set new IP label: {interface_to_check} / {current_ip_for_this_interface}")
            except Exception as e:
                print(f"  Error setting new IP label {interface_to_check} / {current_ip_for_this_interface}: {e}")
                # If setting failed, remove from internal state too to keep them in sync
                if interface_to_check in current_ip_labels:
                    del current_ip_labels[interface_to_check]
        else: # No IP found for this interface now
             if interface_to_check in current_ip_labels:
                 del current_ip_labels[interface_to_check] # Ensure it's removed from internal state

# --- Identifier Functions ---
def get_raspberry_pi_serial():
    """Attempts to read the Raspberry Pi's unique serial number from /proc/cpuinfo."""
    global raspberry_pi_serial
    if raspberry_pi_serial: # Cache the serial after first read
        return raspberry_pi_serial
    serial = "UnknownSN"
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    serial_match = re.search(r":\s*([0-9a-fA-F]+)$", line)
                    if serial_match:
                        serial = serial_match.group(1)
                        break # Found it
    except Exception as e:
        print(f"  Warning: Could not read serial number from /proc/cpuinfo: {e}")
    raspberry_pi_serial = serial
    if serial == "UnknownSN":
        print("  Warning: Could not determine Raspberry Pi serial number.")
    return raspberry_pi_serial

def generate_new_identifier():
    """Generates a unique identifier using Serial and current timestamp (Base64 encoded)."""
    serial = get_raspberry_pi_serial()
    timestamp_int = int(time.time())
    # Use URL-safe base64 encoding for the timestamp part, remove padding
    timestamp_b64 = base64.urlsafe_b64encode(timestamp_int.to_bytes(8, byteorder='big')).rstrip(b'=').decode('utf-8')
    new_identifier = f"{serial}-{timestamp_b64}"
    print(f"  Generated new identifier: {new_identifier}")
    return new_identifier

def save_identifier(identifier):
    """Saves the generated identifier to a file."""
    try:
        # Ensure the directory exists
        os.makedirs(os.path.dirname(IDENTIFIER_FILE), exist_ok=True)
        with open(IDENTIFIER_FILE, 'w') as f:
            f.write(identifier)
        print(f"  Identifier saved to {IDENTIFIER_FILE}")
        return True
    except Exception as e:
        print(f"  ERROR: Could not write identifier file {IDENTIFIER_FILE}: {e}")
        return False

def load_identifier():
    """Loads the identifier from the file if it exists."""
    if os.path.exists(IDENTIFIER_FILE):
        try:
            with open(IDENTIFIER_FILE, 'r') as f:
                identifier = f.read().strip()
            if identifier:
                print(f"  Loaded identifier from {IDENTIFIER_FILE}: {identifier}")
                return identifier
        except Exception as e:
            print(f"  Error reading identifier file {IDENTIFIER_FILE}: {e}")
    print(f"  Identifier file {IDENTIFIER_FILE} not found or empty.")
    return None

def update_prometheus_identifier(new_identifier):
    """Updates the Prometheus gauge for the device identifier."""
    global current_device_id_label
    old_label_to_remove = current_device_id_label
    print(f"  Updating Prometheus identifier metric to: {new_identifier}")
    try:
        DEVICE_IDENTIFIER.labels(identifier=new_identifier).set(1)
        # Update global state *after* success
        current_device_id_label = new_identifier
    except Exception as e:
        print(f"  ERROR setting new Prometheus identifier label '{new_identifier}': {e}")
        # Abort if we can't set the new label
        return

    # Remove the old label if it was different and existed
    if old_label_to_remove and old_label_to_remove != new_identifier:
        try:
            DEVICE_IDENTIFIER.remove(old_label_to_remove)
        except KeyError:
            # Ignore if the old label was not found (e.g., first run or after a clear)
            pass
        except Exception as e:
            print(f"  ERROR removing old Prometheus ID label '{old_label_to_remove}': {e}")

def handle_identifier_update():
    """Handles the process of generating, saving, and updating the identifier."""
    print("\n--- Generating New Identifier ---")
    new_id = generate_new_identifier()
    if save_identifier(new_id):
        # Only update Prometheus if save was successful
        update_prometheus_identifier(new_id)
    else:
        print("--- Identifier Update Failed (Could not save file) ---")
    print("--- Identifier Update Complete ---\n")

# --- GPIO Setup and Button Check ---
def setup_gpio():
    """Configures the GPIO pins for the buttons."""
    try:
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(BUTTON_PIN_1, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(BUTTON_PIN_2, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        print(f"GPIO pins {BUTTON_PIN_1} and {BUTTON_PIN_2} setup complete.")
        return True
    except Exception as e: # Catch broader errors like RuntimeError or missing library
        print(f"ERROR setting up GPIO: {e}. Requires root/sudo? RPi.GPIO installed?")
        return False

def check_buttons():
    """Checks the state of the two buttons and triggers identifier update if both pressed."""
    global buttons_currently_pressed
    try:
        button1_state = GPIO.input(BUTTON_PIN_1)
        button2_state = GPIO.input(BUTTON_PIN_2)
        # Buttons connect pin to GND, so LOW means pressed
        if button1_state == GPIO.LOW and button2_state == GPIO.LOW:
            if not buttons_currently_pressed:
                print(f"\nButton press detected (Pins {BUTTON_PIN_1} & {BUTTON_PIN_2})!")
                handle_identifier_update()
                # Set flag to prevent repeated triggers while buttons are held down
                buttons_currently_pressed = True
        # Reset flag only when *both* buttons are released
        elif button1_state == GPIO.HIGH and button2_state == GPIO.HIGH:
             if buttons_currently_pressed:
                 print("Buttons released.")
                 buttons_currently_pressed = False
    except RuntimeError:
        print("Error reading GPIO state. Check permissions/hardware.")
    except Exception as e:
        print(f"An unexpected error occurred during button check: {e}")

# --- Configuration Loading Functions ---
def load_pi_api_key():
    """Loads the API key from API_KEY_FILE for Pi registration."""
    global PI_SHARED_API_KEY
    key = None
    if os.path.exists(API_KEY_FILE):
        try:
            with open(API_KEY_FILE, 'r') as f:
                key = f.read().strip()
            if key:
                print(f"  Successfully loaded API key from {API_KEY_FILE}.")
                PI_SHARED_API_KEY = key
            else:
                print(f"  Warning: API key file {API_KEY_FILE} is empty.")
        except Exception as e:
            print(f"  Warning: Error reading API key file {API_KEY_FILE}: {e}")
    else:
        print(f"  Warning: API key file {API_KEY_FILE} not found.")

    if not PI_SHARED_API_KEY:
        print("  CRITICAL: Pi registration API key is NOT configured. API reports will likely fail.")
        print(f"  To resolve, create the file '{API_KEY_FILE}' on this Pi")
        print(f"  and put the shared API key provided by the server setup script in it.")

def load_and_set_registrar_url():
    """
    Loads the registrar API URL from REGISTRAR_CONFIG_FILE.
    If the file exists and contains a URL, it updates the global REGISTRAR_API_URL.
    Prints warnings if the file is problematic or the final URL is a placeholder.
    """
    global REGISTRAR_API_URL
    loaded_from_file = False
    if os.path.exists(REGISTRAR_CONFIG_FILE):
        try:
            with open(REGISTRAR_CONFIG_FILE, 'r') as f:
                url_from_file = f.read().strip()
            if url_from_file:
                if not url_from_file.startswith("https://"):
                    print(f"  Warning: Registrar URL from {REGISTRAR_CONFIG_FILE} ('{url_from_file}') does not start with https://. This might cause issues.")
                REGISTRAR_API_URL = url_from_file
                loaded_from_file = True
            else:
                print(f"  Info: Registrar URL file '{REGISTRAR_CONFIG_FILE}' is empty.")
        except Exception as e:
            print(f"  Warning: Error reading registrar URL file '{REGISTRAR_CONFIG_FILE}': {e}")
    else:
        print(f"  Info: Registrar URL configuration file '{REGISTRAR_CONFIG_FILE}' not found.")

    if loaded_from_file:
        print(f"  Registrar API URL configured from file: {REGISTRAR_API_URL}")
    else:
        print(f"  Using default script-defined Registrar API URL: {REGISTRAR_API_URL}")
        print(f"  (To customize, create and populate '{REGISTRAR_CONFIG_FILE}' with the full HTTPS URL, e.g., https://server_ip:5001/register)")

    if "PLEASE_CONFIGURE_IN_FILE" in REGISTRAR_API_URL:
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        print("!!! CRITICAL WARNING: REGISTRAR_API_URL is not properly configured.        !!!")
        print(f"!!! Script is currently using a placeholder value: {REGISTRAR_API_URL}     !!!")
        print(f"!!! Please create the file '{REGISTRAR_CONFIG_FILE}' with the correct HTTPS URL. !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

# --- HTTP SD API Reporting Function ---
def report_ip_to_api(identifier, ip_address, port):
    """Sends this Pi's details (identifier, IP, port) to the registration API."""
    global last_reported_ip_for_api, PI_SHARED_API_KEY, REGISTRAR_API_URL

    if not identifier or not ip_address:
        print("  [API Report] Skipping API report: Missing identifier or IP.")
        return False
    if not PI_SHARED_API_KEY:
        print("  [API Report] Skipping API report: Pi's API key for registration is not loaded.")
        return False
    if "PLEASE_CONFIGURE_IN_FILE" in REGISTRAR_API_URL:
        print(f"  [API Report] Skipping API report: REGISTRAR_API_URL is not configured (current: {REGISTRAR_API_URL}).")
        return False
    if not REGISTRAR_API_URL.startswith("https://"):
        # This is a warning; the script will still attempt the call.
        print(f"  [API Report] Warning: REGISTRAR_API_URL ('{REGISTRAR_API_URL}') does not use HTTPS. Reporting may be insecure or fail.")

    api_endpoint = REGISTRAR_API_URL
    payload = {"identifier": identifier, "ip": ip_address, "port": port}
    headers = {"X-Pi-Register-Api-Key": PI_SHARED_API_KEY}

    # Determine SSL verification path or disable if cert not found
    verify_ssl = SERVER_CERT_PATH_ON_PI
    if not os.path.exists(verify_ssl):
        print(f"  [API Report] WARNING: Server certificate file '{SERVER_CERT_PATH_ON_PI}' not found for HTTPS verification.")
        print(f"  API calls will be made WITHOUT SSL VERIFICATION. This is INSECURE.")
        print(f"  Copy the server's public certificate (cert.pem) to this Pi at '{SERVER_CERT_PATH_ON_PI}'.")
        verify_ssl = False # Disable verification
        # Suppress InsecureRequestWarning only when verification is explicitly disabled
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        print(f"  [API Report] Attempting to report to {api_endpoint} (IP: {ip_address})")
        response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10, verify=verify_ssl)
        response.raise_for_status() # Raises HTTPError for bad responses (4xx or 5xx)
        print(f"  [API Report] Successfully reported IP {ip_address} for {identifier} (Status: {response.status_code}).")
        last_reported_ip_for_api = ip_address # Update last reported IP only on success
        return True
    except requests.exceptions.SSLError as e:
        print(f"  [API Report] ERROR: SSL Error connecting to API at {api_endpoint}. Check certificate setup.")
        print(f"  Ensure '{SERVER_CERT_PATH_ON_PI}' is the correct public cert from the server and is readable.")
        print(f"  Error details: {e}")
    except requests.exceptions.Timeout:
        print(f"  [API Report] ERROR: Timeout connecting to API at {api_endpoint}")
    except requests.exceptions.ConnectionError:
        print(f"  [API Report] ERROR: Connection error for API at {api_endpoint} (is the server reachable and port open?)")
    except requests.exceptions.HTTPError as e:
        print(f"  [API Report] ERROR: HTTP Error {e.response.status_code} reporting to API: {e.response.text}")
    except requests.exceptions.RequestException as e: # Catch any other requests-related errors
        print(f"  [API Report] ERROR: General failure reporting IP to API at {api_endpoint}: {e}")
    return False

# --- Main Execution ---
def main():
    global last_check_times, speedtest_process, speedtest_queue
    global last_api_report_time, last_reported_ip_for_api, current_ip_labels

    # Check for root privileges early if needed for GPIO or other functions
    if os.geteuid() != 0:
        print("Warning: This script may require root/sudo privileges for some functions (GPIO, nmcli full scan, iwconfig).")
        time.sleep(1) # Give a moment for user to see the warning

    # Check for essential command-line tools
    essential_cmds = ["nmcli", "ip", "ping"]
    missing_cmds = [cmd for cmd in essential_cmds if subprocess.run(["which", cmd], capture_output=True, text=True).returncode != 0]
    if missing_cmds:
        for cmd in missing_cmds:
            print(f"CRITICAL ERROR: Essential command '{cmd}' not found. Please install it.")
        print("Exiting due to missing essential commands.")
        return # Exit if crucial tools are missing

    if subprocess.run(["which", "iwconfig"], capture_output=True, text=True).returncode != 0:
        print("Warning: 'iwconfig' command not found. Metrics for connected AP (Signal/Quality from iwconfig) will be unavailable.")

    # Start Prometheus client HTTP server
    try:
        start_http_server(PROMETHEUS_PORT)
        print(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")
    except Exception as e:
        print(f"FATAL: Error starting Prometheus server on port {PROMETHEUS_PORT}: {e}\nExiting.")
        return

    # Setup GPIO for buttons
    gpio_ok = setup_gpio()
    if not gpio_ok:
        print("Warning: GPIO setup failed. Button press for ID reset will be disabled.")

    # Initialize Device Identifier
    print("--- Initializing Device Identifier ---")
    initial_id = load_identifier()
    if not initial_id:
        initial_id = generate_new_identifier()
        save_identifier(initial_id) # Save the newly generated one
    update_prometheus_identifier(initial_id) # Update Prometheus gauge with loaded/new ID
    print("--- Device Identifier Initialized ---")

    # Load configurations from files
    print("--- Loading Pi API Key for Registration ---")
    load_pi_api_key()
    print("--- Loading Registrar API URL Configuration ---")
    load_and_set_registrar_url()
    print("--- Configuration Loading Complete ---")

    # Initialize timers
    now = time.time()
    # Stagger initial checks slightly
    last_check_times["ping_scan_ip"] = now - PING_SCAN_IP_INTERVAL - 5
    last_check_times["speedtest"] = now - SPEEDTEST_CHECK_INTERVAL - 10
    last_api_report_time = 0 # Force initial API report attempt

    print("--- Starting Monitoring Loop ---")
    try:
        while True:
            current_time = time.time()

            if gpio_ok:
                check_buttons()

            # Perform scheduled network checks
            if current_time - last_check_times["ping_scan_ip"] >= PING_SCAN_IP_INTERVAL:
                print(f"\n--- Running Scheduled Checks (Interval: {PING_SCAN_IP_INTERVAL}s) ---")

                ping_interface_arg = WIRELESS_INTERFACE if PING_THROUGH_WIFI_ONLY else None
                run_ping_checks(target=PING_TARGET, interface_to_use=ping_interface_arg)

                # Update metrics for the currently connected AP
                update_connected_ap_metrics(WIRELESS_INTERFACE)

                # Scan for all nearby APs
                scan_wifi_aps_nmcli(WIRELESS_INTERFACE)

                # Update IP addresses for monitored interfaces
                update_device_ip(WIRELESS_INTERFACE)
                if LAN_INTERFACE: # Only if LAN_INTERFACE is configured
                    update_device_ip(LAN_INTERFACE)

                last_check_times["ping_scan_ip"] = current_time
                print("--- Scheduled Checks Complete ---")

            # Periodic API Report
            wireless_ip_for_reporting = current_ip_labels.get(WIRELESS_INTERFACE)
            identifier = current_device_id_label

            ip_changed_for_reporting = (wireless_ip_for_reporting is not None and
                                        wireless_ip_for_reporting != last_reported_ip_for_api)
            time_to_report_again = (current_time - last_api_report_time >= API_REPORT_INTERVAL)

            # Conditions to trigger an API report:
            # 1. We have an identifier.
            # 2. We have an IP for the reporting interface (e.g., wlan0).
            # 3. We have the API key loaded.
            # 4. EITHER the IP has changed OR it's time for a periodic heartbeat.
            if identifier and wireless_ip_for_reporting and PI_SHARED_API_KEY and \
               (ip_changed_for_reporting or time_to_report_again):
                 reason = "IP Changed" if ip_changed_for_reporting else "Periodic Update"
                 print(f"\n--- Reporting to Registration API (IP: {wireless_ip_for_reporting}, Reason: {reason}) ---")
                 report_ip_to_api(identifier, wireless_ip_for_reporting, PROMETHEUS_PORT)
                 last_api_report_time = current_time # Update last *attempt* time
                 print("--- API Report Attempt Complete ---")

            # Scheduled Speedtest Start
            if current_time - last_check_times["speedtest"] >= SPEEDTEST_CHECK_INTERVAL:
                if speedtest_process is None: # Run only if a speedtest is not already in progress
                    print(f"\n--- Starting New Speedtest (Interval: {SPEEDTEST_CHECK_INTERVAL}s) ---")
                    speedtest_queue = multiprocessing.Queue()
                    speedtest_interface_arg = WIRELESS_INTERFACE if SPEEDTEST_THROUGH_WIFI_ONLY else None
                    speedtest_process = multiprocessing.Process(
                        target=run_speedtest_child, args=(speedtest_queue, speedtest_interface_arg), daemon=True
                    )
                    speedtest_process.start()
                    last_check_times["speedtest"] = current_time # Record start time

            # Check for Speedtest Results (runs frequently)
            if speedtest_queue is not None:
                try:
                    result = speedtest_queue.get_nowait() # Non-blocking check
                    print("\n--- Processing Speedtest Results ---")
                    SPEEDTEST_PING.set(result.get('ping', -1))
                    DOWNLOAD_SPEED.set(result.get('download', -1))
                    UPLOAD_SPEED.set(result.get('upload', -1))

                    # Clean up the finished process
                    if speedtest_process is not None:
                        speedtest_process.join(timeout=0.5) # Give it a moment to exit cleanly
                        if speedtest_process.is_alive():
                             print("  Warning: Speedtest process did not exit cleanly after result, terminating.")
                             speedtest_process.terminate()
                             speedtest_process.join(timeout=1) # Wait for termination
                    speedtest_process = None
                    if speedtest_queue: # Close and join queue resources
                        speedtest_queue.close()
                        try:
                            speedtest_queue.join_thread() # Ensure queue feeder thread exits
                        except Exception:
                            pass # Can sometimes raise if already closed/empty
                    speedtest_queue = None
                    print("--- Speedtest Results Processed ---")

                except multiprocessing.queues.Empty: # Correct exception for empty queue
                    # Queue is empty, check if the process died unexpectedly
                    if speedtest_process and not speedtest_process.is_alive():
                         exit_code = speedtest_process.exitcode
                         print(f"\n--- Speedtest process ended unexpectedly (Exit code: {exit_code}) ---")
                         if exit_code is None: # Process might be a zombie
                            try:
                                speedtest_process.terminate() # Try to terminate
                                speedtest_process.join(timeout=0.1) # Brief wait
                            except Exception:
                                pass # Ignore errors during cleanup
                         else: # Already exited
                            speedtest_process.join(timeout=0) # Ensure resources are released

                         speedtest_process = None
                         speedtest_queue = None # Ensure queue is also reset
                         # Set metrics to error state
                         SPEEDTEST_PING.set(-1)
                         DOWNLOAD_SPEED.set(-1)
                         UPLOAD_SPEED.set(-1)
                except Exception as e: # Catch other potential queue errors
                    print(f"\n--- Error processing speedtest queue: {e} ---")
                    if speedtest_process and speedtest_process.is_alive():
                        print("  Terminating running speedtest process due to queue error.")
                        speedtest_process.terminate()
                        speedtest_process.join(timeout=1)
                    speedtest_process = None
                    speedtest_queue = None
                    # Set metrics to error state
                    SPEEDTEST_PING.set(-1)
                    DOWNLOAD_SPEED.set(-1)
                    UPLOAD_SPEED.set(-1)

            # Main Loop Sleep
            time.sleep(LOOP_SLEEP_INTERVAL)

    except KeyboardInterrupt:
        print("\nShutdown requested via KeyboardInterrupt.")
    except Exception as e:
        print(f"\nFATAL ERROR in main loop: {e}")
        import traceback
        traceback.print_exc() # Print stack trace for debugging
    finally:
        print("--- Initiating Shutdown Sequence ---")
        # Terminate speedtest process if it's still running
        if speedtest_process and speedtest_process.is_alive():
            print("Terminating active speedtest process...")
            speedtest_process.terminate()
            speedtest_process.join(timeout=2) # Wait a bit for termination
        if gpio_ok:
            print("Cleaning up GPIO...")
            GPIO.cleanup()
        print("--- Shutdown Complete ---")

if __name__ == '__main__':
    main()
