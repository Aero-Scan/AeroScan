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

# --- Configuration ---
PROMETHEUS_PORT = 8000 # Port the script's own /metrics endpoint runs on
PING_TARGET = "1.1.1.1"
WIRELESS_INTERFACE = "wlan0"  # Wireless interface to check IP for and monitor
# Button Pins (BCM numbering) - Connect each to GND via a button
BUTTON_PIN_1 = 23
BUTTON_PIN_2 = 24

# Intervals
LOOP_SLEEP_INTERVAL = 0.1 # Main loop check frequency (seconds)
PING_SCAN_IP_INTERVAL = 30   # How often to run ping, scan, wireless metrics, IP check (seconds)
SPEEDTEST_CHECK_INTERVAL = 60 # How often to start/check speedtest (seconds) - should be >= PING_SCAN_IP_INTERVAL

# File to store the persistent identifier
IDENTIFIER_FILE = "/var/local/network_monitor_identifier.txt"
# File to store the registrar API URL
REGISTRAR_CONFIG_FILE = "/var/local/network_monitor_registrar_url.txt"


# --- HTTP Service Discovery Configuration ---
# Default URL, will be overridden by REGISTRAR_CONFIG_FILE if it exists and is valid.
REGISTRAR_API_URL = "http://default-registrar-host:5001/register" # A default, less alarming placeholder
# How often to report to the API (in seconds) even if IP hasn't changed (acts as a heartbeat)
API_REPORT_INTERVAL = 300 # Report every 5 minutes (adjust as needed)
# --- End HTTP SD Configuration ---


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
# --- End Prometheus Gauges ---

# --- Global Variables ---
current_device_id_label = None
raspberry_pi_serial = None
buttons_currently_pressed = False
last_check_times = {
    "ping_scan_ip": 0,
    "speedtest": 0,
}
speedtest_process = None
speedtest_queue = None
# Dictionary to store current IP labels {interface: ip_address_string}
current_ip_labels = {}

# --- Global variables for HTTP SD ---
last_api_report_time = 0
last_reported_ip_for_api = None # Track last reported IP to avoid spamming API if IP is stable
# --- End Global Variables ---


# --- Functions for Network Metrics ---

def run_ping_checks(target=PING_TARGET):
    """
    Run ping with 5 packets to get first packet RTT, TTL, and calculate jitter.
    Updates PING_RESPONSE_TIME, NETWORK_TTL, and NETWORK_JITTER gauges.
    """
    response_time = -1
    ttl = -1
    jitter = -1
    print(f"Running ping checks to {target}...")

    try:
        result = subprocess.run(
            ["ping", "-c", "5", "-w", "5", target], # 5 packets, 5 second overall timeout
            capture_output=True,
            text=True,
            check=True, # Raises error on non-zero exit (e.g., host unreachable)
            timeout=6 # Slightly longer subprocess timeout
        )
        output = result.stdout
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)
        times = list(map(float, times_matches))

        if times:
            response_time = times[0]
            if ttl_matches:
                ttl = int(ttl_matches[0])
            print(f"  Ping First Reply: RTT={response_time:.2f} ms, TTL={ttl if ttl != -1 else 'N/A'}")
        else:
            print("  Ping: No replies received.")

        if len(times) >= 2:
            diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]
            jitter = sum(diffs) / len(diffs)
            print(f"  Ping Jitter: {jitter:.2f} ms (from {len(times)} replies)")
        elif len(times) == 1:
            jitter = 0
            print("  Ping Jitter: 0 ms (only 1 reply)")
        else:
             print("  Ping Jitter: N/A (no replies)")

    except subprocess.TimeoutExpired:
        print(f"  Ping command timed out for {target}")
    except subprocess.CalledProcessError as e:
        output = e.stdout + e.stderr
        times_matches = re.findall(r"time=([\d\.]+)", output)
        ttl_matches = re.findall(r"ttl=(\d+)", output)
        times = list(map(float, times_matches))
        if times:
             response_time = times[0]; ttl = int(ttl_matches[0]) if ttl_matches else -1
             if len(times) >= 2: diffs = [abs(times[i+1] - times[i]) for i in range(len(times) - 1)]; jitter = sum(diffs) / len(diffs)
             elif len(times) == 1: jitter = 0
        print(f"  Ping command failed for {target} (Exit code: {e.returncode}). Partial data? RTT={response_time}, TTL={ttl}, Jitter={jitter}. Error: {e.stderr.strip()}")
    except Exception as e:
        print(f"  Error in run_ping_checks: {e}")

    PING_RESPONSE_TIME.set(response_time)
    NETWORK_TTL.set(ttl)
    NETWORK_JITTER.set(jitter)

def update_wireless_metrics(interface=WIRELESS_INTERFACE):
    """
    Update connected wireless metrics (signal strength and link quality) using iwconfig.
    """
    signal_level = -1
    quality_percentage = -1
    print(f"Checking wireless metrics for {interface}...")
    try:
        result = subprocess.run(
            ["iwconfig", interface], capture_output=True, text=True, check=True, timeout=5
        )
        output = result.stdout
        link_quality_match = re.search(r"Link Quality=(\d+)/(\d+)", output)
        if link_quality_match:
            q_curr, q_max = map(int, link_quality_match.groups())
            quality_percentage = (q_curr / q_max * 100) if q_max > 0 else 0
        signal_level_match = re.search(r"Signal level=(-?\d+)\s*dBm", output)
        if signal_level_match: signal_level = int(signal_level_match.group(1))

        print(f"  Wireless Metrics: Signal={signal_level if signal_level != -1 else 'N/A'} dBm, Quality={quality_percentage:.1f}%" if quality_percentage != -1 else 'N/A')
    except subprocess.TimeoutExpired: print(f"  iwconfig command timed out for {interface}")
    except subprocess.CalledProcessError: print(f"  Failed to get wireless metrics for {interface} (is it up and wireless?).")
    except FileNotFoundError: print("  Error: 'iwconfig' command not found. Is 'wireless-tools' installed?")
    except Exception as e: print(f"  Error in update_wireless_metrics: {e}")

    LINK_QUALITY.set(quality_percentage)
    SIGNAL_STRENGTH.set(signal_level)

def run_speedtest_child(result_queue):
    """
    Child process function that runs the speedtest. Puts results in queue.
    """
    result_data = {'ping': -1, 'download': -1, 'upload': -1}
    try:
        print("  Starting speedtest process...")
        st = speedtest.Speedtest(secure=True)
        st.get_best_server() # Can fail
        d_bps = st.download() # Can fail
        u_bps = st.upload() # Can fail
        result_data['download'] = d_bps / 1e6 if d_bps is not None else -1
        result_data['upload'] = u_bps / 1e6 if u_bps is not None else -1
        results_dict = st.results.dict()
        result_data['ping'] = results_dict.get('ping', -1)
        print(f"  Speedtest Finished: Ping={result_data['ping']:.2f} ms, Download={result_data['download']:.2f} Mbps, Upload={result_data['upload']:.2f} Mbps")
    except speedtest.SpeedtestException as e: print(f"  Speedtest failed: {e}") # Catch specific speedtest errors
    except Exception as e: print(f"  Speedtest process failed unexpectedly: {e}") # Catch other errors
    finally: result_queue.put(result_data) # Always put a result

def scan_wifi_aps(interface=WIRELESS_INTERFACE):
    """Scans for WiFi APs and updates Prometheus metrics."""
    print(f"Scanning for WiFi APs on {interface}...")
    aps = []
    cmd = ["iwlist", interface, "scan"]
    try:
        if os.geteuid() != 0: print("  Warning: 'iwlist scan' may require root privileges for full results.")
        result = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=15)
        output = result.stdout
        # Simplified parsing logic (adjust regex if needed for different iwlist versions)
        current_ap = {}
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("Cell"):
                if current_ap: aps.append(current_ap)
                addr_match = re.search(r"Address: (([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2})", line)
                current_ap = {'bssid': addr_match.group(1) if addr_match else None}
            elif "ESSID:" in line:
                ssid_match = re.search(r'ESSID:"([^"]*)"', line)
                current_ap['ssid'] = ssid_match.group(1) if ssid_match else '<hidden>'
            elif "Channel:" in line:
                 channel_match = re.search(r"Channel:(\d+)", line)
                 if channel_match: current_ap['channel'] = channel_match.group(1)
            elif "Frequency:" in line and 'channel' not in current_ap: # Alternative channel finding
                 freq_match = re.search(r"\(Channel (\d+)\)", line)
                 if freq_match: current_ap['channel'] = freq_match.group(1)
            elif "Signal level=" in line:
                 signal_match = re.search(r"Signal level=(-?\d+)\s*dBm", line)
                 if signal_match: current_ap['signal'] = int(signal_match.group(1))
            # Add other fields if needed (Quality, Encryption, etc.)
        if current_ap: aps.append(current_ap) # Add the last AP

    except subprocess.TimeoutExpired: print(f"  iwlist scan command timed out for {interface}")
    except subprocess.CalledProcessError as e: print(f"  Failed to run iwlist scan on {interface}: {e}")
    except FileNotFoundError: print("  Error: 'iwlist' command not found. Is 'wireless-tools' installed?")
    except Exception as e: print(f"  Error during WiFi AP scan: {e}")

    # Clear previous AP metrics before adding new ones
    WIFI_AP_SIGNAL.clear()
    reported_aps = set() # Avoid duplicate labels if scan returns same AP multiple times
    valid_aps_count = 0
    for ap in aps:
        # Ensure mandatory fields were parsed
        if all(k in ap for k in ('ssid', 'bssid', 'channel', 'signal')):
            label_tuple = (ap['ssid'], ap['bssid'], ap['channel'])
            if label_tuple not in reported_aps:
                try:
                    # Sanitize SSID label - Prometheus labels have restrictions
                    sanitized_ssid = re.sub(r'[^a-zA-Z0-9_:]', '_', ap['ssid'])
                    WIFI_AP_SIGNAL.labels(ssid=sanitized_ssid, bssid=ap['bssid'], channel=ap['channel']).set(ap['signal'])
                    reported_aps.add(label_tuple)
                    valid_aps_count += 1
                except Exception as label_err: # Catch errors setting specific labels
                    print(f"  Error setting label for AP {ap.get('ssid','N/A')} (BSSID: {ap.get('bssid','N/A')}). Error: {label_err}")
        # else: print(f"  Skipping AP due to missing fields: {ap}") # Optional debug

    print(f"  Found and processed {valid_aps_count} valid APs.")
    if not aps: print("  No APs found in scan.")


# --- Function for Device IP ---
def update_device_ip(interface=WIRELESS_INTERFACE):
    """Gets the device's IPv4 address for the specified interface and updates Prometheus."""
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
            print(f"  Found IP: {current_ip}")
        else:
            print(f"  No IPv4 address found for {interface}.")
    except FileNotFoundError: print("  Error: 'ip' command not found. Is 'iproute2' package installed?")
    except subprocess.TimeoutExpired: print(f"  'ip addr show' command timed out for {interface}")
    except subprocess.CalledProcessError: print(f"  Failed to get IP for {interface} (is it up?).") # Interface might be down
    except Exception as e: print(f"  Error getting IP address: {e}")

    # --- Update Prometheus Metric and internal state ---
    last_known_ip = current_ip_labels.get(interface)

    if current_ip != last_known_ip:
        # Remove old label if it existed
        if last_known_ip:
            try:
                NETWORK_INTERFACE_INFO.remove(interface, last_known_ip)
                print(f"  Removed old IP label: {interface} / {last_known_ip}")
            except KeyError: pass # OK if label didn't exist
            except Exception as e: print(f"  Error removing old IP label {interface} / {last_known_ip}: {e}")

        # Add new label if we have a current IP
        if current_ip:
            try:
                NETWORK_INTERFACE_INFO.labels(interface=interface, ip_address=current_ip).set(1)
                current_ip_labels[interface] = current_ip # Store the new IP internally
                print(f"  Set new IP label: {interface} / {current_ip}")
            except Exception as e:
                print(f"  Error setting new IP label {interface} / {current_ip}: {e}")
                # If setting failed, remove from internal state too
                if interface in current_ip_labels: del current_ip_labels[interface]
        else:
            # If no IP found now, ensure it's removed from internal state
             if interface in current_ip_labels: del current_ip_labels[interface]

    # If IP is the same, do nothing to the metric or internal state


# --- Functions for Unique Identifier ---
def get_raspberry_pi_serial():
    """Attempts to read the Raspberry Pi's unique serial number."""
    global raspberry_pi_serial
    if raspberry_pi_serial: return raspberry_pi_serial
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
        print("Warning: Could not determine Raspberry Pi serial number.")
    # else: print(f"  Found Serial: {raspberry_pi_serial}") # Optional debug
    return raspberry_pi_serial

def generate_new_identifier():
    """Generates a unique identifier using Serial and current timestamp."""
    serial = get_raspberry_pi_serial()
    timestamp_int = int(time.time())
    # Use URL-safe base64 encoding, remove padding
    timestamp_b64 = base64.urlsafe_b64encode(timestamp_int.to_bytes(8, byteorder='big')).rstrip(b'=').decode('utf-8')
    new_identifier = f"{serial}-{timestamp_b64}"
    print(f"  Generated new identifier: {new_identifier}")
    return new_identifier

def save_identifier(identifier):
    """Saves the generated identifier to a file."""
    try:
        os.makedirs(os.path.dirname(IDENTIFIER_FILE), exist_ok=True)
        with open(IDENTIFIER_FILE, 'w') as f: f.write(identifier)
        print(f"  Identifier saved to {IDENTIFIER_FILE}")
        return True
    except Exception as e:
        print(f"  ERROR: Could not write identifier file {IDENTIFIER_FILE}: {e}")
        return False

def load_identifier():
    """Loads the identifier from the file if it exists."""
    if os.path.exists(IDENTIFIER_FILE):
        try:
            with open(IDENTIFIER_FILE, 'r') as f: identifier = f.read().strip()
            if identifier:
                print(f"  Loaded identifier from {IDENTIFIER_FILE}: {identifier}")
                return identifier
        except Exception as e: print(f"  Error reading identifier file {IDENTIFIER_FILE}: {e}")
    print(f"  Identifier file not found or empty: {IDENTIFIER_FILE}")
    return None

def update_prometheus_identifier(new_identifier):
    """Updates the Prometheus gauge for the device identifier."""
    global current_device_id_label
    old_label_to_remove = current_device_id_label
    print(f"  Updating Prometheus identifier metric to: {new_identifier}")
    try:
        DEVICE_IDENTIFIER.labels(identifier=new_identifier).set(1)
        current_device_id_label = new_identifier # Update global state *after* success
        # print(f"  Set new Prometheus identifier label: {new_identifier}") # Optional debug
    except Exception as e:
        print(f"  ERROR setting new Prometheus identifier label '{new_identifier}': {e}")
        return # Abort if we can't set the new label

    # Remove the old label if it was different
    if old_label_to_remove and old_label_to_remove != new_identifier:
        try:
            DEVICE_IDENTIFIER.remove(old_label_to_remove)
            # print(f"  Removed old Prometheus ID label: {old_label_to_remove}") # Optional debug
        except KeyError: pass # Ignore if not found
        except Exception as e: print(f"  ERROR removing old Prometheus ID label '{old_label_to_remove}': {e}")

def handle_identifier_update():
    """Handles the process of generating, saving, and updating the identifier."""
    print("\n--- Generating New Identifier ---")
    new_id = generate_new_identifier()
    if save_identifier(new_id):
        update_prometheus_identifier(new_id) # Only update Prometheus if save was successful
    else:
        print("--- Identifier Update Failed (Could not save) ---")
        return # Don't update Prometheus if we couldn't save
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
    except RuntimeError as e:
         print(f"ERROR setting up GPIO: {e}. Requires root/sudo? RPi.GPIO installed?")
         return False
    except Exception as e: # Catch other potential errors like missing libraries
        print(f"An unexpected error occurred during GPIO setup: {e}")
        return False

def check_buttons():
    """Checks the state of the two buttons and triggers update if both pressed."""
    global buttons_currently_pressed
    try:
        button1_state = GPIO.input(BUTTON_PIN_1)
        button2_state = GPIO.input(BUTTON_PIN_2)
        # Buttons connect pin to GND, so LOW means pressed
        if button1_state == GPIO.LOW and button2_state == GPIO.LOW:
            if not buttons_currently_pressed:
                print(f"\nButton press detected (Pins {BUTTON_PIN_1} & {BUTTON_PIN_2})!")
                handle_identifier_update()
                buttons_currently_pressed = True # Set flag to prevent repeated triggers
        else:
            # Reset flag only when *both* buttons are released
            if button1_state == GPIO.HIGH and button2_state == GPIO.HIGH:
                 if buttons_currently_pressed:
                     print("Buttons released.")
                     buttons_currently_pressed = False
    except RuntimeError: print("Error reading GPIO state. Check permissions/hardware.")
    except Exception as e: print(f"An unexpected error occurred during button check: {e}")


# --- Function for loading Registrar URL ---
def load_and_set_registrar_url():
    """
    Attempts to load the registrar API URL from REGISTRAR_CONFIG_FILE.
    If successful, updates the global REGISTRAR_API_URL.
    Prints whether the configuration was loaded from file or if using the default.
    """
    global REGISTRAR_API_URL # To modify the global variable

    loaded_from_file = False
    if os.path.exists(REGISTRAR_CONFIG_FILE):
        try:
            with open(REGISTRAR_CONFIG_FILE, 'r') as f:
                url_from_file = f.read().strip()
            if url_from_file:
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
        print(f"  Using default Registrar API URL: {REGISTRAR_API_URL}")
        print(f"  (To customize, create and populate '{REGISTRAR_CONFIG_FILE}')")


# --- Function for HTTP SD API Reporting ---
def report_ip_to_api(identifier, ip_address, port):
    """Sends this Pi's details to the registration API."""
    global last_reported_ip_for_api
    # REGISTRAR_API_URL is now a global updated by load_and_set_registrar_url()

    if not identifier or not ip_address:
        print("  [API Report] Skipping API report: Missing identifier or IP.")
        return False

    api_endpoint = REGISTRAR_API_URL # Use the global, potentially updated URL

    payload = {
        "identifier": identifier,
        "ip": ip_address,
        "port": port
    }
    try:
        print(f"  [API Report] Attempting to report to {api_endpoint} with payload: {payload}")
        response = requests.post(api_endpoint, json=payload, timeout=10)
        response.raise_for_status()
        print(f"  [API Report] Successfully reported IP {ip_address} for {identifier} (Status: {response.status_code}).")
        last_reported_ip_for_api = ip_address
        return True

    except requests.exceptions.Timeout:
        print(f"  [API Report] ERROR: Timeout connecting to API at {api_endpoint}")
    except requests.exceptions.ConnectionError:
        print(f"  [API Report] ERROR: Connection refused or network error for API at {api_endpoint}")
    except requests.exceptions.HTTPError as e:
         print(f"  [API Report] ERROR: HTTP Error {e.response.status_code} reporting to API: {e.response.text}")
    except requests.exceptions.RequestException as e:
        print(f"  [API Report] ERROR: General failure reporting IP to API at {api_endpoint}: {e}")

    return False
# --- End HTTP SD Function ---


# --- Main Execution ---
def main():
    global last_check_times, speedtest_process, speedtest_queue
    global last_api_report_time, last_reported_ip_for_api # Already global

    # --- Initial checks ---
    if os.geteuid() != 0:
        print("Warning: Root privileges may be required for some functions (GPIO, iwlist scan).")
        time.sleep(2)
    if subprocess.run(["which", "ip"], capture_output=True).returncode != 0:
        print("Error: 'ip' command not found. Please install 'iproute2' (e.g., sudo apt install iproute2).")
    if subprocess.run(["which", "iwconfig"], capture_output=True).returncode != 0:
        print("Warning: 'iwconfig' command not found. Wireless metrics unavailable. Install 'wireless-tools'.")
    if subprocess.run(["which", "iwlist"], capture_output=True).returncode != 0:
        print("Warning: 'iwlist' command not found. WiFi AP scan unavailable. Install 'wireless-tools'.")

    # --- Start Prometheus server ---
    try:
        start_http_server(PROMETHEUS_PORT)
        print(f"Prometheus metrics server started on port {PROMETHEUS_PORT}")
    except Exception as e:
        print(f"FATAL: Error starting Prometheus server on port {PROMETHEUS_PORT}: {e}\nExiting.")
        return

    # --- Setup GPIO ---
    gpio_ok = setup_gpio()
    if not gpio_ok: print("Warning: GPIO setup failed. Button press for ID reset disabled.")

    # --- Initial Identifier ---
    print("--- Initializing Device Identifier ---")
    initial_id = load_identifier()
    if not initial_id:
        initial_id = generate_new_identifier()
        save_identifier(initial_id)
    update_prometheus_identifier(initial_id)
    print("--- Device Identifier Initialized ---")

    # --- Load and Check REGISTRAR_API_URL Configuration ---
    print("--- Loading Registrar API URL Configuration ---")
    load_and_set_registrar_url() # This function will print its own status
    print("--- Registrar API URL Configuration Set ---")

    # --- Initialize timers ---
    now = time.time()
    last_check_times["ping_scan_ip"] = now - PING_SCAN_IP_INTERVAL - 5
    last_check_times["speedtest"] = now - SPEEDTEST_CHECK_INTERVAL - 10
    last_api_report_time = 0

    # --- Main Loop ---
    print("--- Starting Monitoring Loop ---")
    try:
        while True:
            current_time = time.time()

            if gpio_ok: check_buttons()

            if current_time - last_check_times["ping_scan_ip"] >= PING_SCAN_IP_INTERVAL:
                print(f"\n--- Running Scheduled Checks (Interval: {PING_SCAN_IP_INTERVAL}s) ---")
                run_ping_checks()
                update_wireless_metrics(WIRELESS_INTERFACE)
                scan_wifi_aps(WIRELESS_INTERFACE)
                update_device_ip(WIRELESS_INTERFACE)
                last_check_times["ping_scan_ip"] = current_time
                print("--- Scheduled Checks Complete ---")

            current_ip = current_ip_labels.get(WIRELESS_INTERFACE)
            identifier = current_device_id_label
            ip_changed = (current_ip is not None and current_ip != last_reported_ip_for_api)
            time_to_report = (current_time - last_api_report_time >= API_REPORT_INTERVAL)

            if identifier and current_ip and (ip_changed or time_to_report):
                 print(f"\n--- Reporting to Registration API (Reason: {'IP Changed' if ip_changed else 'Periodic Update'}) ---")
                 report_ip_to_api(identifier, current_ip, PROMETHEUS_PORT)
                 last_api_report_time = current_time
                 print("--- API Report Attempt Complete ---")

            if current_time - last_check_times["speedtest"] >= SPEEDTEST_CHECK_INTERVAL:
                if speedtest_process is None:
                    print(f"\n--- Starting New Speedtest (Interval: {SPEEDTEST_CHECK_INTERVAL}s) ---")
                    speedtest_queue = multiprocessing.Queue()
                    speedtest_process = multiprocessing.Process(target=run_speedtest_child, args=(speedtest_queue,), daemon=True)
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
                             print("  Warning: Speedtest process did not exit cleanly after result, terminating.")
                             speedtest_process.terminate()
                             speedtest_process.join(timeout=1)
                    speedtest_process = None
                    if speedtest_queue:
                        speedtest_queue.close()
                        try: speedtest_queue.join_thread()
                        except Exception: pass
                    speedtest_queue = None
                    print("--- Speedtest Results Processed ---")
                except multiprocessing.queues.Empty:
                    if speedtest_process and not speedtest_process.is_alive():
                         print("\n--- Speedtest process ended unexpectedly without result ---")
                         print(f"  Exit code: {speedtest_process.exitcode}")
                         speedtest_process.join(timeout=0)
                         speedtest_process = None; speedtest_queue = None
                         SPEEDTEST_PING.set(-1); DOWNLOAD_SPEED.set(-1); UPLOAD_SPEED.set(-1)
                except Exception as e:
                    print(f"\n--- Error processing speedtest queue: {e} ---")
                    if speedtest_process and speedtest_process.is_alive():
                        print("  Terminating running speedtest process due to queue error.")
                        speedtest_process.terminate(); speedtest_process.join(timeout=1)
                    speedtest_process = None; speedtest_queue = None
                    SPEEDTEST_PING.set(-1); DOWNLOAD_SPEED.set(-1); UPLOAD_SPEED.set(-1)

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
