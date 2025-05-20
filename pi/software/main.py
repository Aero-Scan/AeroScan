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
import requests # For HTTP API reporting
import urllib3 # To potentially suppress InsecureRequestWarning if verify=False

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
# Signal strength of connected network in dBm (via iwconfig)
SIGNAL_STRENGTH = Gauge('signal_strength_dbm', 'Signal strength of connected network in dBm (via iwconfig)')
NETWORK_JITTER = Gauge('network_jitter_ms', 'Network jitter in ms (calculated from 5 packets)')
# Link quality of connected network in percentage (via iwconfig)
LINK_QUALITY = Gauge('link_quality_percentage', 'Link quality of connected network in percentage (via iwconfig)')
# Signal strength of nearby WiFi APs (via nmcli)
WIFI_AP_SIGNAL = Gauge('wifi_ap_signal_strength_dbm', 'Signal strength of nearby WiFi APs (via nmcli)', ['ssid', 'bssid', 'channel'])
DEVICE_IDENTIFIER = Gauge('device_unique_identifier', 'Unique identifier for the device (SN-Base64Timestamp)', ['identifier'])
NETWORK_INTERFACE_INFO = Gauge('network_interface_info', 'Basic network interface information (IP Address)', ['interface', 'ip_address'])

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
        # Less verbose for a helper
        print(f"  Could not get IP for {interface_name}: {e}")
    return None

def run_ping_checks(target=PING_TARGET, interface_to_use=None):
    response_time = -1
    ttl = -1
    jitter = -1

    ping_cmd_base = ["ping", "-c", "5", "-w", "5", target]
    # For logging
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

def update_wireless_metrics(interface=WIRELESS_INTERFACE):
    # Default to very low signal if not found
    signal_level = -100
    quality_percentage = -1
    # No wireless interface configured
    if not interface:
        return

    print(f"Checking connected wireless metrics for {interface} (iwconfig)...")
    try:
        result = subprocess.run(
            ["iwconfig", interface],
            capture_output=True, text=True, check=True, timeout=5
        )
        output = result.stdout
        link_quality_match = re.search(r"Link Quality=(\d+)/(\d+)", output)
        if link_quality_match:
            q_curr, q_max = map(int, link_quality_match.groups())
            quality_percentage = (q_curr / q_max * 100) if q_max > 0 else 0
        signal_level_match = re.search(r"Signal level=(-?\d+)\s*dBm", output)
        if signal_level_match:
            signal_level = int(signal_level_match.group(1))
        # Interface might not be wireless or not connected
        elif "Signal level" not in output:
            print(f"  No 'Signal level' found for {interface}. Is it a connected wireless interface?")

    except subprocess.CalledProcessError:
        print(f"  Failed to get iwconfig metrics for {interface} (is it up and wireless?).")
    except subprocess.TimeoutExpired:
        print(f"  iwconfig command timed out for {interface}")
    except FileNotFoundError:
        print("  Error: 'iwconfig' command not found. Is 'wireless-tools' installed?")
    except Exception as e:
        print(f"  Unexpected error in update_wireless_metrics for {interface}: {e}")

    LINK_QUALITY.set(quality_percentage)
    SIGNAL_STRENGTH.set(signal_level)

def run_speedtest_child(result_queue, interface_to_use_for_source_ip=None):
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
        # HTTPS for speedtest.net communication
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

def parse_nmcli_wifi_line(line_content, header_map):
    """
    Parses a single data line of 'nmcli dev wifi list' output.
    Line content should already have the IN-USE '*' marker removed if present.
    """
    ap = {}
    # Split on 2 or more spaces. This can be tricky if SSIDs have multiple spaces,
    # but nmcli usually pads columns well. A more robust method might use fixed widths
    # or a different nmcli output format (-t -f fields) if available and reliable.
    parts = re.split(r'\s{2,}', line_content.strip())

    try:
        # Map parts to header fields based on the header_map indices
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
                ap['signal_dbm'] = -101 # Invalid quality
        else:
            ap['signal_dbm'] = -102 # Missing signal quality

        if ap.get('ssid') == '--':
            ap['ssid'] = '<hidden_or_empty>'

        # Basic validation
        if not ap.get('bssid') or not ap.get('channel') or 'signal_dbm' not in ap:
            # print(f"  Skipping line due to missing essential fields: {line_content}")
            return None
        if not ap.get('ssid'): # SSID can be empty but should exist as a key
            ap['ssid'] = '<unknown_ssid>'


    except (IndexError, ValueError) as e:
        # print(f"  Error parsing nmcli data line: '{line_content}'. Error: {e}")
        return None

    # Ensure all required fields for Prometheus are present
    if all(k in ap for k in ('ssid', 'bssid', 'channel', 'signal_dbm')):
        return ap
    return None


def get_nmcli_header_map(header_line_content):
    """
    Creates a map of column names to indices from nmcli header line.
    Handles potential 'IN-USE' column.
    """
    # Remove leading '*' or 'IN-USE' literal from the header line if it's the first word
    if header_line_content.lstrip().startswith("IN-USE"):
        # If "IN-USE" is the first column name, process it.
        # Otherwise, if it starts with '*', strip it. This is a bit heuristic.
        # A robust way is to check if the first split part is 'IN-USE'.
        temp_headers = re.split(r'\s{2,}', header_line_content.strip())
        if temp_headers[0].upper() == "IN-USE":
            headers_raw = temp_headers
        else: # Fallback if 'IN-USE' is not the first distinct word.
            headers_raw = re.split(r'\s{2,}', header_line_content.lstrip().replace('*','',1).strip())
    else: # No 'IN-USE' or '*' at the start
        headers_raw = re.split(r'\s{2,}', header_line_content.strip())

    header_map = {}
    for i, name in enumerate(headers_raw):
        # Normalize: uppercase, remove any lingering '*' (though primary removal is above), strip
        # Special handling for "IN-USE" if it's a column name.
        # The primary fields we need (BSSID, SSID, etc.) usually don't have tricky names.
        clean_name = name.upper().replace('*','').strip()
        if clean_name: # Avoid empty strings if multiple spaces led to empty splits
             header_map[clean_name] = i

    required_headers = ["BSSID", "SSID", "CHAN", "SIGNAL"]
    missing = [h for h in required_headers if h not in header_map]
    if missing:
        print(f"  Error: nmcli header output missing one of required headers: {missing}.")
        print(f"  Raw header line processed: '{header_line_content}'")
        print(f"  Parsed headers found: {list(header_map.keys())}")
        return None
    return header_map


def scan_wifi_aps_nmcli(interface=WIRELESS_INTERFACE):
    if not interface:
        print("  Skipping nmcli WiFi scan: No wireless interface configured.")
        WIFI_AP_SIGNAL.clear() # Clear old metrics if not scanning
        return

    print(f"Scanning for WiFi APs on {interface} using nmcli...")
    aps = []

    # --- Explicitly trigger a rescan ---
    rescan_cmd = ["nmcli", "dev", "wifi", "rescan", "ifname", interface]
    try:
        print(f"  Triggering Wi-Fi rescan on {interface}...")
        # Using check=False as rescan might return non-zero if no *new* APs found or if busy.
        subprocess.run(rescan_cmd, capture_output=True, text=True, check=False, timeout=10)
        print(f"  Rescan command sent. Waiting a moment for APs to appear...")
        time.sleep(3) # Adjust as needed
    except subprocess.TimeoutExpired:
        print(f"  nmcli rescan command timed out for {interface}.")
    except FileNotFoundError:
        print("  Error: 'nmcli' command not found for rescan.")
        WIFI_AP_SIGNAL.clear()
        return
    except Exception as e:
        print(f"  Unexpected error during nmcli rescan: {e}")
    # --- End of rescan ---

    list_cmd = ["nmcli", "dev", "wifi", "list", "ifname", interface]
    header_map = None
    try:
        result = subprocess.run(list_cmd, capture_output=True, text=True, check=True, timeout=15)
        output_lines = result.stdout.strip().splitlines() # Use strip() before splitlines

        if not output_lines:
            print("  nmcli output is empty after rescan.")
            WIFI_AP_SIGNAL.clear()
            return

        # The first non-empty line is expected to be the header.
        header_line_content = output_lines[0]
        data_lines_start_index = 1

        header_map = get_nmcli_header_map(header_line_content)
        if not header_map:
            WIFI_AP_SIGNAL.clear()
            return # Error already printed by get_nmcli_header_map

        # Process data lines
        for line_content in output_lines[data_lines_start_index:]:
            # The IN-USE '*' marker is at the beginning of the line, before BSSID.
            # parse_nmcli_wifi_line expects it to be removed.
            # Or, the first column "IN-USE" might just contain '*'.
            # The current `parse_nmcli_wifi_line` handles data based on header_map.
            # We need to ensure the `line_content` passed to parse_nmcli_wifi_line
            # aligns with what `get_nmcli_header_map` indexed.

            # If the first column in header_map is "IN-USE", then parts[header_map["IN-USE"]] will get '*'.
            # The `parse_nmcli_wifi_line` doesn't explicitly use the "IN-USE" data, so it's okay.

            ap_data = parse_nmcli_wifi_line(line_content, header_map)
            if ap_data:
                aps.append(ap_data)

    except subprocess.TimeoutExpired:
        print(f"  nmcli list command timed out for {interface}")
    except subprocess.CalledProcessError as e:
        print(f"  Failed to run nmcli list on {interface}: {e}. Output: {e.stderr.strip()}")
    except FileNotFoundError:
        print("  Error: 'nmcli' command not found for listing.")
    except Exception as e:
        print(f"  Error during WiFi AP list with nmcli: {e}")

    # --- Prometheus metric update logic ---
    WIFI_AP_SIGNAL.clear()
    reported_bssids = set()
    valid_aps_count = 0
    if not aps: # If aps list is empty (e.g., due to parsing errors or no APs found)
        print("  No valid AP data parsed from nmcli scan.")

    for ap in aps:
        # `parse_nmcli_wifi_line` should ensure necessary fields are present if it returns data
        if ap.get('bssid') and ap['bssid'] not in reported_bssids:
            try:
                sanitized_ssid = re.sub(r'[^a-zA-Z0-9_:]', '_', ap['ssid'])
                # Handle cases where SSID might become empty after sanitization if it was all special chars
                if not sanitized_ssid:
                    sanitized_ssid = "_invalid_ssid_chars_"

                WIFI_AP_SIGNAL.labels(
                    ssid=sanitized_ssid,
                    bssid=ap['bssid'],
                    channel=str(ap['channel']) # Ensure channel is string
                ).set(ap['signal_dbm'])
                reported_bssids.add(ap['bssid'])
                valid_aps_count += 1
            except Exception as label_err:
                print(f"  Error setting label for AP {ap.get('ssid','N/A')} (BSSID: {ap.get('bssid','N/A')}). Error: {label_err}")
        # else:
            # print(f"  Skipping AP due to missing fields or duplicate BSSID: {ap}")

    print(f"  nmcli scan: Found and processed {valid_aps_count} unique APs after rescan.")
    if not valid_aps_count and output_lines: # If output_lines had content but no valid APs were processed
        print("  No APs were successfully processed into metrics from nmcli output.")
    elif not output_lines: # Should have been caught earlier
        print("  No APs found as nmcli output was empty.")

def update_device_ip(interface_to_check):
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
                if interface_to_check in current_ip_labels:
                    del current_ip_labels[interface_to_check]
        else:
             if interface_to_check in current_ip_labels:
                 del current_ip_labels[interface_to_check]

# --- Identifier Functions ---
def get_raspberry_pi_serial():
    global raspberry_pi_serial
    if raspberry_pi_serial:
        return raspberry_pi_serial
    serial = "UnknownSN"
    try:
        with open('/proc/cpuinfo', 'r') as f:
            for line in f:
                if line.startswith('Serial'):
                    serial_match = re.search(r":\s*([0-9a-fA-F]+)$", line)
                    if serial_match:
                        serial = serial_match.group(1)
                        break
    except Exception as e:
        print(f"  Warning: Could not read serial from /proc/cpuinfo: {e}")
    raspberry_pi_serial = serial
    return raspberry_pi_serial

def generate_new_identifier():
    serial = get_raspberry_pi_serial()
    timestamp_int = int(time.time())
    timestamp_b64 = base64.urlsafe_b64encode(timestamp_int.to_bytes(8, byteorder='big')).rstrip(b'=').decode('utf-8')
    return f"{serial}-{timestamp_b64}"

def save_identifier(identifier):
    try:
        os.makedirs(os.path.dirname(IDENTIFIER_FILE), exist_ok=True)
        with open(IDENTIFIER_FILE, 'w') as f:
            f.write(identifier)
        print(f"  Identifier saved to {IDENTIFIER_FILE}")
        return True
    except Exception as e:
        print(f"  ERROR: Could not write identifier file {IDENTIFIER_FILE}: {e}")
        return False

def load_identifier():
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
    global current_device_id_label
    old_label_to_remove = current_device_id_label
    try:
        DEVICE_IDENTIFIER.labels(identifier=new_identifier).set(1)
        current_device_id_label = new_identifier
    except Exception as e:
        print(f"  ERROR setting new Prometheus identifier label '{new_identifier}': {e}")
        return
    if old_label_to_remove and old_label_to_remove != new_identifier:
        try:
            DEVICE_IDENTIFIER.remove(old_label_to_remove)
        except KeyError:
            pass
        except Exception as e:
            print(f"  ERROR removing old Prometheus ID label '{old_label_to_remove}': {e}")

def handle_identifier_update():
    print("\n--- Generating New Identifier ---")
    new_id = generate_new_identifier()
    if save_identifier(new_id):
        update_prometheus_identifier(new_id)
    else:
        print("--- Identifier Update Failed (Could not save) ---")
    print("--- Identifier Update Complete ---\n")

# --- GPIO Setup and Button Check ---
def setup_gpio():
    try:
        GPIO.setwarnings(False)
        GPIO.setmode(GPIO.BCM)
        GPIO.setup(BUTTON_PIN_1, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        GPIO.setup(BUTTON_PIN_2, GPIO.IN, pull_up_down=GPIO.PUD_UP)
        print(f"GPIO pins {BUTTON_PIN_1} and {BUTTON_PIN_2} setup complete.")
        return True
    except Exception as e:
        print(f"ERROR setting up GPIO: {e}")
        return False

def check_buttons():
    global buttons_currently_pressed
    try:
        b1_state = GPIO.input(BUTTON_PIN_1)
        b2_state = GPIO.input(BUTTON_PIN_2)
        if b1_state == GPIO.LOW and b2_state == GPIO.LOW:
            if not buttons_currently_pressed:
                print(f"\nButton press detected (Pins {BUTTON_PIN_1} & {BUTTON_PIN_2})!")
                handle_identifier_update()
                buttons_currently_pressed = True
        elif b1_state == GPIO.HIGH and b2_state == GPIO.HIGH:
            if buttons_currently_pressed:
                print("Buttons released.")
                buttons_currently_pressed = False
    except Exception as e:
        print(f"An unexpected error occurred during button check: {e}")

# --- Configuration Loading Functions ---
def load_pi_api_key():
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
        print(f"  To resolve, create '{API_KEY_FILE}' and put the shared API key in it.")

def load_and_set_registrar_url():
    global REGISTRAR_API_URL
    loaded_from_file = False
    if os.path.exists(REGISTRAR_CONFIG_FILE):
        try:
            with open(REGISTRAR_CONFIG_FILE, 'r') as f:
                url_from_file = f.read().strip()
            if url_from_file:
                if not url_from_file.startswith("https://"):
                    print(f"  Warning: URL from {REGISTRAR_CONFIG_FILE} ('{url_from_file}') isn't HTTPS.")
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
        print(f"  (To customize, create and populate '{REGISTRAR_CONFIG_FILE}')")
    if "PLEASE_CONFIGURE_IN_FILE" in REGISTRAR_API_URL:
        print("CRITICAL WARNING: REGISTRAR_API_URL needs configuration in a file or script default.")

# --- HTTP SD API Reporting Function ---
def report_ip_to_api(identifier, ip_address, port):
    global last_reported_ip_for_api, PI_SHARED_API_KEY, REGISTRAR_API_URL

    if not identifier or not ip_address:
        print("  [API Report] Skipping: Missing identifier or IP.")
        return False
    if not PI_SHARED_API_KEY:
        print("  [API Report] Skipping: Pi's API key not loaded.")
        return False
    if "PLEASE_CONFIGURE_IN_FILE" in REGISTRAR_API_URL:
        print(f"  [API Report] Skipping: REGISTRAR_API_URL not configured.")
        return False
    if not REGISTRAR_API_URL.startswith("https://"):
        print(f"  [API Report] Warning: REGISTRAR_API_URL ('{REGISTRAR_API_URL}') not HTTPS.")

    api_endpoint = REGISTRAR_API_URL
    payload = {"identifier": identifier, "ip": ip_address, "port": port}
    headers = {"X-Pi-Register-Api-Key": PI_SHARED_API_KEY}
    verify_path = SERVER_CERT_PATH_ON_PI
    if not os.path.exists(verify_path):
        print(f"  [API Report] WARNING: Server certificate '{verify_path}' not found. HTTPS calls WITHOUT VERIFICATION (INSECURE).")
        verify_path = False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        print(f"  [API Report] Attempting to report to {api_endpoint} (IP: {ip_address})")
        response = requests.post(api_endpoint, json=payload, headers=headers, timeout=10, verify=verify_path)
        response.raise_for_status()
        print(f"  [API Report] Successfully reported (Status: {response.status_code}).")
        last_reported_ip_for_api = ip_address
        return True
    except requests.exceptions.SSLError as e:
        print(f"  [API Report] ERROR: SSL Error. Check cert '{SERVER_CERT_PATH_ON_PI}'. Details: {e}")
    except requests.exceptions.Timeout:
        print(f"  [API Report] ERROR: Timeout connecting to {api_endpoint}")
    except requests.exceptions.ConnectionError:
        print(f"  [API Report] ERROR: Connection error for {api_endpoint}")
    except requests.exceptions.HTTPError as e:
        print(f"  [API Report] ERROR: HTTP {e.response.status_code}: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"  [API Report] ERROR: General failure reporting: {e}")
    return False

# --- Main Execution ---
def main():
    global last_check_times, speedtest_process, speedtest_queue
    global last_api_report_time, last_reported_ip_for_api, current_ip_labels

    if os.geteuid() != 0:
        print("Warning: Root privileges may be required for some functions.")
        time.sleep(1)

    # Command existence checks
    for cmd_name in ["nmcli", "ip", "ping"]:
        if subprocess.run(["which", cmd_name], capture_output=True, text=True).returncode != 0:
            print(f"CRITICAL ERROR: '{cmd_name}' command not found. Essential functions will fail. Please install it.")
            # Consider exiting if essential commands are missing
    if subprocess.run(["which", "iwconfig"], capture_output=True, text=True).returncode != 0:
        print("Warning: 'iwconfig' not found. Connected AP signal (update_wireless_metrics) will fail.")

    try:
        start_http_server(PROMETHEUS_PORT)
        print(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")
    except Exception as e:
        print(f"FATAL: Error starting Prometheus server: {e}\nExiting.")
        return

    gpio_ok = setup_gpio()
    if not gpio_ok:
        print("Warning: GPIO setup failed. Button ID reset disabled.")

    print("--- Initializing Device Identifier ---")
    initial_id = load_identifier()
    if not initial_id:
        initial_id = generate_new_identifier()
        save_identifier(initial_id)
    update_prometheus_identifier(initial_id)
    print("--- Device Identifier Initialized ---")

    print("--- Loading Pi API Key for Registration ---")
    load_pi_api_key()
    print("--- Loading Registrar API URL Configuration ---")
    load_and_set_registrar_url()
    print("--- Configuration Loading Complete ---")

    now = time.time()
    last_check_times["ping_scan_ip"] = now - PING_SCAN_IP_INTERVAL - 5
    last_check_times["speedtest"] = now - SPEEDTEST_CHECK_INTERVAL - 10
    last_api_report_time = 0

    print("--- Starting Monitoring Loop ---")
    try:
        while True:
            current_time = time.time()
            if gpio_ok:
                check_buttons()

            if current_time - last_check_times["ping_scan_ip"] >= PING_SCAN_IP_INTERVAL:
                print(f"\n--- Running Scheduled Checks (Interval: {PING_SCAN_IP_INTERVAL}s) ---")
                ping_if = WIRELESS_INTERFACE if PING_THROUGH_WIFI_ONLY else None
                run_ping_checks(target=PING_TARGET, interface_to_use=ping_if)
                update_wireless_metrics(WIRELESS_INTERFACE)
                scan_wifi_aps_nmcli(WIRELESS_INTERFACE)
                update_device_ip(WIRELESS_INTERFACE)
                if LAN_INTERFACE:
                    update_device_ip(LAN_INTERFACE)
                last_check_times["ping_scan_ip"] = current_time
                print("--- Scheduled Checks Complete ---")

            wireless_ip_for_reporting = current_ip_labels.get(WIRELESS_INTERFACE)
            identifier = current_device_id_label
            ip_changed = (wireless_ip_for_reporting is not None and wireless_ip_for_reporting != last_reported_ip_for_api)
            time_to_report = (current_time - last_api_report_time >= API_REPORT_INTERVAL)

            if identifier and wireless_ip_for_reporting and PI_SHARED_API_KEY and (ip_changed or time_to_report):
                 print(f"\n--- Reporting to Registration API (IP: {wireless_ip_for_reporting}, Reason: {'IP Changed' if ip_changed else 'Periodic Update'}) ---")
                 report_ip_to_api(identifier, wireless_ip_for_reporting, PROMETHEUS_PORT)
                 last_api_report_time = current_time
                 print("--- API Report Attempt Complete ---")

            if current_time - last_check_times["speedtest"] >= SPEEDTEST_CHECK_INTERVAL:
                if speedtest_process is None:
                    print(f"\n--- Starting New Speedtest (Interval: {SPEEDTEST_CHECK_INTERVAL}s) ---")
                    speedtest_queue = multiprocessing.Queue()
                    st_if = WIRELESS_INTERFACE if SPEEDTEST_THROUGH_WIFI_ONLY else None
                    speedtest_process = multiprocessing.Process(
                        target=run_speedtest_child, args=(speedtest_queue, st_if), daemon=True
                    )
                    speedtest_process.start()
                    last_check_times["speedtest"] = current_time

            if speedtest_queue is not None:
                try:
                    result = speedtest_queue.get_nowait()
                    print("\n--- Processing Speedtest Results ---")
                    SPEEDTEST_PING.set(result.get('ping', -1))
                    DOWNLOAD_SPEED.set(result.get('download', -1))
                    UPLOAD_SPEED.set(result.get('upload', -1))
                    if speedtest_process is not None:
                        speedtest_process.join(timeout=0.5)
                        if speedtest_process.is_alive():
                            print("  Warning: Speedtest process unclean exit, terminating.")
                            speedtest_process.terminate()
                            speedtest_process.join(timeout=1)
                    speedtest_process = None
                    if speedtest_queue:
                        speedtest_queue.close()
                        try:
                            speedtest_queue.join_thread()
                        except Exception:
                            pass
                    speedtest_queue = None
                    print("--- Speedtest Results Processed ---")
                except multiprocessing.queues.Empty:
                    if speedtest_process and not speedtest_process.is_alive():
                         exit_code = speedtest_process.exitcode
                         print(f"\n--- Speedtest process ended unexpectedly (Exit: {exit_code}) ---")
                         if exit_code is None:
                             try:
                                 speedtest_process.terminate()
                                 speedtest_process.join(timeout=0.1)
                             except Exception:
                                 pass
                         else:
                             speedtest_process.join(timeout=0)
                         speedtest_process = None
                         speedtest_queue = None
                         SPEEDTEST_PING.set(-1)
                         DOWNLOAD_SPEED.set(-1)
                         UPLOAD_SPEED.set(-1)
                except Exception as e:
                    print(f"\n--- Error processing speedtest queue: {e} ---")
                    if speedtest_process and speedtest_process.is_alive():
                        print("  Terminating speedtest process due to queue error.")
                        speedtest_process.terminate()
                        speedtest_process.join(timeout=1)
                    speedtest_process = None
                    speedtest_queue = None
                    SPEEDTEST_PING.set(-1)
                    DOWNLOAD_SPEED.set(-1)
                    UPLOAD_SPEED.set(-1)
            time.sleep(LOOP_SLEEP_INTERVAL)
    except KeyboardInterrupt:
        print("\nShutdown requested via KeyboardInterrupt.")
    except Exception as e:
        print(f"\nFATAL ERROR in main loop: {e}")
        import traceback
        traceback.print_exc()
    finally:
        print("--- Initiating Shutdown Sequence ---")
        if speedtest_process and speedtest_process.is_alive():
            print("Terminating active speedtest process...")
            speedtest_process.terminate()
            speedtest_process.join(timeout=2)
        if gpio_ok:
            print("Cleaning up GPIO...")
            GPIO.cleanup()
        print("--- Shutdown Complete ---")

if __name__ == '__main__':
    main()
