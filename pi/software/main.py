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
import urllib3 # To potentially suppress InsecureRequestWarning if verify=False (NOT RECOMMENDED)

# --- Configuration ---
PROMETHEUS_PORT = 8000
PING_TARGET = "1.1.1.1"
WIRELESS_INTERFACE = "wlan0"
BUTTON_PIN_1 = 23
BUTTON_PIN_2 = 24

LOOP_SLEEP_INTERVAL = 0.1
PING_SCAN_IP_INTERVAL = 30
SPEEDTEST_CHECK_INTERVAL = 60

# Files for persistent data and configuration
IDENTIFIER_FILE = "/var/local/network_monitor_identifier.txt"
REGISTRAR_CONFIG_FILE = "/var/local/network_monitor_registrar_url.txt" # Should contain full URL e.g. https://server:5001/register
API_KEY_FILE = "/var/local/network_monitor_api_key.txt" # Should contain the shared API key

# Default Registrar URL (will be overridden by REGISTRAR_CONFIG_FILE)
# Ensure this is a valid format, even if it's a placeholder that will be overwritten.
DEFAULT_REGISTRAR_API_URL = "https://PLEASE_CONFIGURE_IN_FILE:5001/register"
REGISTRAR_API_URL = DEFAULT_REGISTRAR_API_URL # Initialize with default

# Path to the server's public certificate on the Pi (for HTTPS verification)
# This file must be copied from the server (Docker host) to this Pi.
SERVER_CERT_PATH_ON_PI = "/etc/ssl/certs/pi_registrar_server.pem"

API_REPORT_INTERVAL = 300

# --- Global variable for Pi's API Key ---
PI_SHARED_API_KEY = None # Will be loaded from API_KEY_FILE

# --- Prometheus Gauges ---
PING_RESPONSE_TIME = Gauge('network_ping_response_time_ms', 'Ping response time in ms (first packet)')
NETWORK_TTL = Gauge('network_ttl', 'Ping TTL value (first packet)')
SPEEDTEST_PING = Gauge('speedtest_ping_ms', 'Speedtest ping in ms')
DOWNLOAD_SPEED = Gauge('download_speed_mbps', 'Download speed in Mbps')
UPLOAD_SPEED = Gauge('upload_speed_mbps', 'Upload speed in Mbps')
SIGNAL_STRENGTH = Gauge('signal_strength_dbm', 'Signal strength of connected network in dBm')
NETWORK_JITTER = Gauge('network_jitter_ms', 'Network jitter in ms (calculated from 5 packets)')
LINK_QUALITY = Gauge('link_quality_percentage', 'Link quality of connected network in percentage')
WIFI_AP_SIGNAL = Gauge('wifi_ap_signal_strength_dbm', 'Signal strength of nearby WiFi APs', ['ssid', 'bssid', 'channel'])
DEVICE_IDENTIFIER = Gauge('device_unique_identifier', 'Unique identifier for the device (SN-Base64Timestamp)', ['identifier'])
NETWORK_INTERFACE_INFO = Gauge('network_interface_info', 'Basic network interface information (IP Address)', ['interface', 'ip_address'])

# --- Global Variables ---
current_device_id_label = None
raspberry_pi_serial = None
buttons_currently_pressed = False
last_check_times = { "ping_scan_ip": 0, "speedtest": 0 }
speedtest_process = None
speedtest_queue = None
current_ip_labels = {}
last_api_report_time = 0
last_reported_ip_for_api = None

# --- Network Metric Functions ---
def run_ping_checks(target=PING_TARGET):
    response_time = -1
    ttl = -1
    jitter = -1
    print(f"Running ping checks to {target}...")
    try:
        result = subprocess.run(
            ["ping", "-c", "5", "-w", "5", target],
            capture_output=True, text=True, check=True, timeout=6
        )
        output = result.stdout
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)
        times = list(map(float, times_matches))
        if times:
            response_time = times[0]
            ttl = int(ttl_matches[0]) if ttl_matches else -1
        if len(times) >= 2:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
            jitter = sum(diffs) / len(diffs)
        elif len(times) == 1:
            jitter = 0
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"  Ping error for {target}: {e}")
    except Exception as e:
        print(f"  Unexpected error in run_ping_checks: {e}")

    PING_RESPONSE_TIME.set(response_time)
    NETWORK_TTL.set(ttl)
    NETWORK_JITTER.set(jitter)
    # print(f"  Ping: RTT={response_time}, TTL={ttl}, Jitter={jitter}")


def update_wireless_metrics(interface=WIRELESS_INTERFACE):
    signal_level = -1
    quality_percentage = -1
    print(f"Checking wireless metrics for {interface}...")
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
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  iwconfig error for {interface}: {e}")
    except Exception as e:
        print(f"  Unexpected error in update_wireless_metrics: {e}")

    LINK_QUALITY.set(quality_percentage)
    SIGNAL_STRENGTH.set(signal_level)
    # print(f"  Wireless: Signal={signal_level}, Quality={quality_percentage}")


def run_speedtest_child(result_queue):
    result_data = {'ping': -1, 'download': -1, 'upload': -1}
    try:
        print("  Starting speedtest process...")
        st = speedtest.Speedtest(secure=True) # Use secure=True for HTTPS for speedtest.net servers
        st.get_best_server()
        d_bps = st.download()
        u_bps = st.upload()
        result_data['download'] = d_bps / 1e6 if d_bps is not None else -1
        result_data['upload'] = u_bps / 1e6 if u_bps is not None else -1
        results_dict = st.results.dict()
        result_data['ping'] = results_dict.get('ping', -1)
    except speedtest.SpeedtestException as e:
        print(f"  Speedtest failed: {e}")
    except Exception as e:
        print(f"  Speedtest process failed unexpectedly: {e}")
    finally:
        result_queue.put(result_data)
    # print(f"  Speedtest child finished: {result_data}")


def scan_wifi_aps(interface=WIRELESS_INTERFACE):
    print(f"Scanning for WiFi APs on {interface}...")
    aps = []
    cmd = ["iwlist", interface, "scan"]
    try:
        if os.geteuid() != 0:
            print("  Warning: 'iwlist scan' may require root privileges for full results.")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
        output = result.stdout
        current_ap = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Cell"):
                if current_ap:
                    aps.append(current_ap)
                addr_match = re.search(r"Address: (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", line)
                current_ap = {'bssid': addr_match.group(1) if addr_match else None}
            elif "ESSID:" in line:
                ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                current_ap['ssid'] = ssid_match.group(1) if ssid_match else '<hidden>'
            elif "Channel:" in line:
                channel_match = re.search(r"Channel:(\d+)", line)
                current_ap['channel'] = channel_match.group(1) if channel_match else None
            elif "Frequency:" in line and 'channel' not in current_ap:
                freq_match = re.search(r"\(Channel (\d+)\)", line)
                current_ap['channel'] = freq_match.group(1) if freq_match else None
            elif "Signal level=" in line:
                signal_match = re.search(r"Signal level=(-?\d+)\s*dBm", line)
                current_ap['signal'] = int(signal_match.group(1)) if signal_match else None
        if current_ap:
            aps.append(current_ap)
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  iwlist scan error: {e}")
    except Exception as e:
        print(f"  Unexpected error during WiFi AP scan: {e}")

    WIFI_AP_SIGNAL.clear()
    reported_aps = set()
    valid_aps_count = 0
    for ap in aps:
        if all(k in ap and ap[k] is not None for k in ('ssid', 'bssid', 'channel', 'signal')):
            label_tuple = (ap['ssid'], ap['bssid'], ap['channel'])
            if label_tuple not in reported_aps:
                try:
                    sanitized_ssid = re.sub(r'[^a-zA-Z0-9_:]', '_', ap['ssid'])
                    WIFI_AP_SIGNAL.labels(ssid=sanitized_ssid, bssid=ap['bssid'], channel=ap['channel']).set(ap['signal'])
                    reported_aps.add(label_tuple)
                    valid_aps_count += 1
                except Exception as label_err:
                    print(f"  Error setting AP label for {ap.get('ssid','N/A')}: {label_err}")
    # print(f"  Found and processed {valid_aps_count} valid APs.")


def update_device_ip(interface=WIRELESS_INTERFACE):
    global current_ip_labels
    print(f"Checking IP address for {interface}...")
    current_ip = None
    try:
        result = subprocess.run(
            ["ip", "-4", "addr", "show", interface],
            capture_output=True, text=True, check=True, timeout=3
        )
        ip_match = re.search(r"inet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/", result.stdout)
        if ip_match:
            current_ip = ip_match.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as e:
        print(f"  'ip addr show' error: {e}")
    except Exception as e:
        print(f"  Error getting IP address: {e}")

    last_known_ip = current_ip_labels.get(interface)
    if current_ip != last_known_ip:
        if last_known_ip:
            try:
                NETWORK_INTERFACE_INFO.remove(interface, last_known_ip)
            except KeyError:
                pass # OK if label didn't exist
            except Exception as e:
                print(f"  Error removing old IP label {interface}/{last_known_ip}: {e}")
        if current_ip:
            try:
                NETWORK_INTERFACE_INFO.labels(interface=interface, ip_address=current_ip).set(1)
                current_ip_labels[interface] = current_ip
            except Exception as e:
                print(f"  Error setting new IP label {interface}/{current_ip}: {e}")
                if interface in current_ip_labels: # Should be current_ip_labels, not just ip_address
                     del current_ip_labels[interface]
        else: # No current IP
             if interface in current_ip_labels:
                 del current_ip_labels[interface]
    # print(f"  IP for {interface}: {current_ip if current_ip else 'Not found'}")


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
    new_identifier = f"{serial}-{timestamp_b64}"
    return new_identifier

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
    print(f"  Identifier file not found or empty: {IDENTIFIER_FILE}")
    return None

def update_prometheus_identifier(new_identifier):
    global current_device_id_label
    old_label_to_remove = current_device_id_label
    try:
        DEVICE_IDENTIFIER.labels(identifier=new_identifier).set(1)
        current_device_id_label = new_identifier
    except Exception as e:
        print(f"  ERROR setting new Prometheus identifier label '{new_identifier}': {e}")
        return # Abort if we can't set the new label

    if old_label_to_remove and old_label_to_remove != new_identifier:
        try:
            DEVICE_IDENTIFIER.remove(old_label_to_remove)
        except KeyError:
            pass # Ignore if not found
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
    except Exception as e: # Catch broader errors including RuntimeError
        print(f"ERROR setting up GPIO: {e}")
        return False

def check_buttons():
    global buttons_currently_pressed
    try:
        button1_state = GPIO.input(BUTTON_PIN_1)
        button2_state = GPIO.input(BUTTON_PIN_2)
        if button1_state == GPIO.LOW and button2_state == GPIO.LOW:
            if not buttons_currently_pressed:
                print(f"\nButton press detected (Pins {BUTTON_PIN_1} & {BUTTON_PIN_2})!")
                handle_identifier_update()
                buttons_currently_pressed = True
        elif button1_state == GPIO.HIGH and button2_state == GPIO.HIGH: # Both must be released
            if buttons_currently_pressed:
                print("Buttons released.")
                buttons_currently_pressed = False
    except Exception as e: # Catch broader errors including RuntimeError
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
    """Loads the registrar API URL from REGISTRAR_CONFIG_FILE."""
    global REGISTRAR_API_URL # To modify the global variable
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
        print(f"!!! Script is using a placeholder: {REGISTRAR_API_URL} !!!")
        print(f"!!! Create '{REGISTRAR_CONFIG_FILE}' with the correct HTTPS URL.           !!!")
        print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")

# --- HTTP SD API Reporting Function ---
def report_ip_to_api(identifier, ip_address, port):
    global last_reported_ip_for_api, PI_SHARED_API_KEY, REGISTRAR_API_URL

    if not identifier or not ip_address:
        print("  [API Report] Skipping: Missing identifier or IP.")
        return False
    if not PI_SHARED_API_KEY:
        print("  [API Report] Skipping: Pi's API key for registration is not loaded.")
        return False
    if "PLEASE_CONFIGURE_IN_FILE" in REGISTRAR_API_URL:
        print(f"  [API Report] Skipping: REGISTRAR_API_URL is not configured (current: {REGISTRAR_API_URL}).")
        return False
    if not REGISTRAR_API_URL.startswith("https://"):
        print(f"  [API Report] Warning: REGISTRAR_API_URL ('{REGISTRAR_API_URL}') does not use HTTPS. Reporting may be insecure or fail.")
        # Allow attempt for flexibility, but it's strongly discouraged

    api_endpoint = REGISTRAR_API_URL
    payload = {"identifier": identifier, "ip": ip_address, "port": port}
    headers = {"X-Pi-Register-Api-Key": PI_SHARED_API_KEY}

    # Check if the server certificate file exists for verification
    verify_path_or_bool = SERVER_CERT_PATH_ON_PI # Use the constant for clarity
    if not os.path.exists(verify_path_or_bool):
        print(f"  [API Report] WARNING: Server certificate file '{verify_path_or_bool}' not found for HTTPS verification.")
        print(f"  API calls will be made WITHOUT SSL VERIFICATION. This is INSECURE.")
        print(f"  Copy the server's public certificate (cert.pem) to this Pi at '{verify_path_or_bool}'.")
        verify_path_or_bool = False # Disables verification, requests library handles this
        # Suppress InsecureRequestWarning if verify_path is False
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        print(f"  [API Report] Attempting to report to {api_endpoint} with payload: {payload}")
        response = requests.post(
            api_endpoint,
            json=payload,
            headers=headers,
            timeout=10,
            verify=verify_path_or_bool # Pass path or False
        )
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
        print(f"  [API Report] ERROR: Connection error for API at {api_endpoint}")
    except requests.exceptions.HTTPError as e:
        print(f"  [API Report] ERROR: HTTP Error {e.response.status_code} from API: {e.response.text}")
    except requests.exceptions.RequestException as e: # Catch any other requests-related errors
        print(f"  [API Report] ERROR: General failure reporting to API: {e}")
    return False

# --- Main Execution ---
def main():
    global last_check_times, speedtest_process, speedtest_queue
    global last_api_report_time, last_reported_ip_for_api

    if os.geteuid() != 0:
        print("Warning: Root privileges may be required for some functions (GPIO, iwlist scan).")
        time.sleep(1) # Give a moment to see the warning

    # Initial command checks (can be added here if desired, e.g., for ip, iwconfig, iwlist)

    try:
        start_http_server(PROMETHEUS_PORT)
        print(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")
    except Exception as e:
        print(f"FATAL: Error starting Prometheus server on port {PROMETHEUS_PORT}: {e}\nExiting.")
        return

    gpio_ok = setup_gpio()
    if not gpio_ok:
        print("Warning: GPIO setup failed. Button press for ID reset disabled.")

    print("--- Initializing Device Identifier ---")
    initial_id = load_identifier()
    if not initial_id:
        initial_id = generate_new_identifier()
        save_identifier(initial_id) # Save the newly generated one
    update_prometheus_identifier(initial_id) # Update Prometheus gauge with loaded/new ID
    print("--- Device Identifier Initialized ---")

    print("--- Loading Pi API Key for Registration ---")
    load_pi_api_key() # Load the key for API reports

    print("--- Loading Registrar API URL Configuration ---")
    load_and_set_registrar_url() # Load the URL, prints its own status
    print("--- Registrar API URL Configuration Set ---")


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

            if current_time - last_check_times["ping_scan_ip"] >= PING_SCAN_IP_INTERVAL:
                print(f"\n--- Running Scheduled Checks (Interval: {PING_SCAN_IP_INTERVAL}s) ---")
                run_ping_checks()
                update_wireless_metrics(WIRELESS_INTERFACE)
                scan_wifi_aps(WIRELESS_INTERFACE)
                update_device_ip(WIRELESS_INTERFACE)
                last_check_times["ping_scan_ip"] = current_time
                print("--- Scheduled Checks Complete ---")

            # Periodic API Report
            current_ip = current_ip_labels.get(WIRELESS_INTERFACE)
            identifier = current_device_id_label
            ip_changed = (current_ip is not None and current_ip != last_reported_ip_for_api)
            time_to_report = (current_time - last_api_report_time >= API_REPORT_INTERVAL)

            # Ensure API key is loaded before attempting to report
            if identifier and current_ip and PI_SHARED_API_KEY and (ip_changed or time_to_report):
                 print(f"\n--- Reporting to Registration API (Reason: {'IP Changed' if ip_changed else 'Periodic Update'}) ---")
                 if report_ip_to_api(identifier, current_ip, PROMETHEUS_PORT):
                     pass # Success is handled and logged within the function
                 last_api_report_time = current_time # Update last *attempt* time
                 print("--- API Report Attempt Complete ---")

            # Scheduled Speedtest Start
            if current_time - last_check_times["speedtest"] >= SPEEDTEST_CHECK_INTERVAL:
                if speedtest_process is None:
                    print(f"\n--- Starting New Speedtest (Interval: {SPEEDTEST_CHECK_INTERVAL}s) ---")
                    speedtest_queue = multiprocessing.Queue()
                    speedtest_process = multiprocessing.Process(
                        target=run_speedtest_child, args=(speedtest_queue,), daemon=True
                    )
                    speedtest_process.start()
                    last_check_times["speedtest"] = current_time # Record start time

            # Check for Speedtest Results
            if speedtest_queue is not None:
                try:
                    result = speedtest_queue.get_nowait() # Non-blocking check
                    print("\n--- Processing Speedtest Results ---")
                    SPEEDTEST_PING.set(result.get('ping', -1))
                    DOWNLOAD_SPEED.set(result.get('download', -1))
                    UPLOAD_SPEED.set(result.get('upload', -1))

                    if speedtest_process is not None:
                        speedtest_process.join(timeout=0.5) # Give it a moment
                        if speedtest_process.is_alive():
                             print("  Warning: Speedtest process did not exit cleanly after result, terminating.")
                             speedtest_process.terminate()
                             speedtest_process.join(timeout=1) # Wait for termination
                    speedtest_process = None
                    if speedtest_queue: # Close and join queue resources
                        speedtest_queue.close()
                        try:
                            speedtest_queue.join_thread()
                        except Exception: # Can sometimes raise if already closed/empty
                            pass
                    speedtest_queue = None
                    print("--- Speedtest Results Processed ---")

                except multiprocessing.queues.Empty: # Correct exception for empty queue
                    # Queue is empty, check if the process died unexpectedly
                    if speedtest_process and not speedtest_process.is_alive():
                         print(f"\n--- Speedtest process ended unexpectedly (Exit code: {speedtest_process.exitcode}) ---")
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
            speedtest_process.join(timeout=2) # Wait a bit
        if gpio_ok:
            print("Cleaning up GPIO...")
            GPIO.cleanup()
        print("--- Shutdown Complete ---")

if __name__ == '__main__':
    main()
