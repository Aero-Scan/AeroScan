# AeroScan - Wireless Network Q&P Monitoring

[![License: CC BY‑NC‑SA 4.0](https://img.shields.io/badge/License-CC%20BY--NC--SA%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-sa/4.0/)

## Overview

AeroScan is an IoT-based system designed to monitor the Quality and Performance (Q&P) of the wireless network infrastructure. Developed for scanning network performance, this project utilises Raspberry Pi devices deployed across site to collect real-time network metrics, providing valuable insights into network health, identifying potential issues, and helping to ensure a reliable wireless experience for students and staff.

The system addresses the need for automated, continuous monitoring, moving beyond manual checks and reactive troubleshooting. Data collected by the Raspberry Pi units is visualized through a centralized Grafana dashboard, offering clear view of network performance across different locations.

## Features
* **Real-time Visualization:** Integrates with Prometheus for metrics scraping and Grafana for dashboard display.
* **Distributed Monitoring:** Uses low-cost Raspberry Pi devices as network sensors.
* **Real-Time Monitoring:** Continuously scans and collects data on wireless network performance.
* **Comprehensive Metrics:** Gathers data on:
    * Wireless Signal Strength (RSSI) & Link Quality 
    * Network Latency (Ping Times) & Jitter
    * Internet Bandwidth (Upload/Download via Speedtest)
    * Connected Access Point Details (SSID, BSSID, Channel, Frequency, Signal Strength)
    * Nearby Wireless Access Points Scan(SSID, BSSID, Channel, Frequency, Signal Strength)
    * Device IP Address
* **Multi-AP Scanning:** Capable of scanning and reporting on multiple Wireless Access Points (WAPs) within range.
* **Disruption Handling:** Designed to detect when a connected WAP goes down, automatically scan for, and connect to the next available WAP.
* **Scalability:** Built to support multiple Raspberry Pi devices deployed across campus for wide coverage.
* **Centralized Visualization:** Integrates with Prometheus for data scraping and Grafana for displaying metrics on a dashboard.
* **Remote Accessibility:** Devices can be configured for remote access (e.g., via SSH) for maintenance and troubleshooting.
*   **Unique Device Identification:** Each Raspberry Pi sensor has a persistent unique identifier.
*   **GPIO Interaction:** Includes functionality to reset the device identifier using physical buttons connected to GPIO pins (optional hardware setup).

## Technology Stack

*   **Hardware:**
    *   Raspberry Pi Zero WH (Primary target)
    *   Raspberry Pi 4 Model B (Development/Alternative)
    *   MicroSD Cards (Minimum 16GB recommended)
    *   Power Supplies
    *   (Optional) Push Buttons and wiring for GPIO interaction
*   **Operating System:** Custom Raspberry Pi OS image (potentially built using `pi-gen`)
*   **Core Software:**
    *   Python 3
    *   `prometheus_client` (Python library)
    *   `speedtest-cli` (Python library)
    *   `RPi.GPIO` (Python library for button interaction)
*   **Network Tools (Command Line):**
    *   `ping`
    *   `iwconfig` / `nmcli dev wifi rescan ` / `NetworkManager` (Wireless tools)
    *   `ip` (from `iproute2` package)
*   **Monitoring & Visualization:**
    *   Prometheus (Exporter on Pi, Central Server for scraping/storage)
    *   Grafana (Dashboard visualization, connected to Prometheus)
*   **Version Control:** Git / GitHub
*   **Collaboration:** Microsoft Teams, Discord, OneDrive/SharePoint


## Architecture Overview

1.  **Data Collection (Raspberry Pi):**
    *   A Python script (`main.py`) runs continuously on each Raspberry Pi.
    *   It periodically executes network tests (`ping`, `speedtest-cli`, `iwconfig`, `nmcli dev wifi rescan`, `ip addr show`).
    *   It parses the output of these commands to extract relevant metrics.
    *   It reads GPIO pins to check for button presses (for ID reset).
2.  **Metrics Exposure (Raspberry Pi):**
    *   The Python script uses the `prometheus_client` library to expose the collected metrics via an HTTP endpoint (default: port 8000, `/metrics`).
    *   A unique, persistent identifier is generated/loaded for each Pi and exposed as a label.
3.  **Metrics Scraping (Central Server):**
    *   A central Prometheus server is configured to periodically "scrape" the `/metrics` endpoint of each deployed Raspberry Pi.
4.  **Storage & Querying (Central Server):**
    *   Prometheus stores the scraped time-series data.
5.  **Visualization (Central Server/Client):**
    *   Grafana connects to the Prometheus server as a data source.
    *   Dashboards are created in Grafana to query and visualize the network metrics over time, filterable by device identifier or location (if configured).


## Setup and Installation

Follow these steps to set up an AeroScan monitoring node on a Raspberry Pi:

1.  **Prepare Raspberry Pi OS:**
    * Download the latest Raspberry Pi OS Lite (64-bit recommended for newer models).
    * Flash the OS onto the MicroSD card using Raspberry Pi Imager.
    * Use the pre-configured images, 64 bit is designed for eduroam and 32 bit is designed for eduroam2.4-legacy
2.  **Initial Boot & Configuration:**
    * Insert the SD card into the Pi and power it on.
3.  **Install Dependencies:**
    * Install Python 3 pip and necessary tools:
        ```bash
        sudo apt update
        sudo apt install -y python3-pip git iw speedtest-cli
        # Add any other system dependencies required by your scripts
        ```
    * Install required Python libraries:
        ```bash
        # Navigate to the cloned repo directory first (see step 4)
        # Example: pip3 install -r requirements.txt
        # (Create a requirements.txt file listing libraries like 'prometheus_client', etc.)
        ```

4.  **Clone AeroScan Repository:**
    ```bash
    git clone [https://github.com/Aero-Scan/AeroScan.git](https://github.com/Aero-Scan/AeroScan.git)
    cd AeroScan
    ```

5.  **Configure AeroScan Script:**
    * (Describe any necessary configuration steps here - e.g., editing a config file, setting environment variables for target ping hosts, Prometheus endpoint details, etc.)
    * Ensure the script has execute permissions if needed (`chmod +x your_script.py`).

6.  **Setup Prometheus:**
    * Install Prometheus on a central server (or another Pi).
    * Configure Prometheus (`prometheus.yml`) to scrape the metrics endpoint exposed by the Python script on each AeroScan Pi (e.g., `http://<aeroscan_pi_ip>:<port>/metrics`).
    * Example scrape config:
      ```yaml
      scrape_configs:
        - job_name: 'aeroscan_nodes'
          static_configs:
            - targets: ['<pi1_ip>:<port>', '<pi2_ip>:<port>'] # Replace with actual IPs/ports
      ```

7.  **Setup Grafana:**
    * Install Grafana on a central server.
    * Add Prometheus as a data source in Grafana.
    * Import or create a Grafana dashboard to visualize the metrics collected (e.g., signal strength over time, ping latency, bandwidth). (Consider exporting your dashboard as JSON and adding it to the repo).

8.  **Run the Monitoring Script:**
    * **Manually:** `python3 /path/to/your/aeroscan_script.py`
    * **As a Service (Recommended):** Create a systemd service file to run the script automatically on boot and restart it if it fails.
        * Create `/etc/systemd/system/aeroscan.service`:
          ```ini
          [Unit]
          Description=AeroScan Network Monitor
          After=network.target

          [Service]
          User=pi # Or another user
          WorkingDirectory=/home/pi/AeroScan # Adjust path
          ExecStart=/usr/bin/python3 /home/pi/AeroScan/your_script.py # Adjust path
          Restart=always

          [Install]
          WantedBy=multi-user.target
          ```
        * Enable and start the service:
          ```bash
          sudo systemctl enable aeroscan.service
          sudo systemctl start aeroscan.service
          sudo systemctl status aeroscan.service
          ```

## Usage

Once set up, the AeroScan Raspberry Pi node will automatically collect network data and expose it for Prometheus to scrape.

* **Accessing Data:** View the collected metrics and network status via the configured Grafana dashboard.
* **Troubleshooting:** Connect to individual Raspberry Pi nodes via SSH for maintenance or log checking (e.g., `journalctl -u aeroscan.service`).

## Configuration

*(Detail specific configuration options here. Examples:)*

* **`config.ini` / `.env`:** Explain any configuration files used by the script.
    * `TARGET_HOSTS`: Comma-separated list of hosts/IPs to ping.
    * `PROMETHEUS_PORT`: Port number for the metrics endpoint.
    * `SCAN_INTERVAL_SECONDS`: How often to run the data collection.
* **Prometheus (`prometheus.yml`):** Ensure the `scrape_configs` section includes targets for all active AeroScan nodes.
* **Grafana:** Configure the Prometheus data source and set up dashboard panels.

## License

AeroScan is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC-SA 4.0)**.

You are free to **share** (copy and redistribute the material in any medium or format) and **adapt** (remix, transform, and build upon the material) under the following terms:

* **Attribution** — You must give [appropriate credit](https://creativecommons.org/licenses/by-nc-sa/4.0/#ref-appropriate-credit), provide a link to the license, and [indicate if changes were made](https://creativecommons.org/licenses/by-nc-sa/4.0/#ref-indicate-changes). You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **NonCommercial** — You may not use the material for [commercial purposes](https://creativecommons.org/licenses/by-nc-sa/4.0/#ref-commercial-purposes).
* **ShareAlike** - If you remix, transform, or build upon the material, you must distribute your contributions under the [same license](https://creativecommons.org/licenses/by-nc-sa/4.0/#ref-same-license) as the original.
* **No additional restrictions** — You may not apply legal terms or [technological measures](https://creativecommons.org/licenses/by-nc-sa/4.0/#ref-technological-measures) that legally restrict others from doing anything the license permits.

For more information, see the [full license text](LICENSE) in this repository or visit:
[https://creativecommons.org/licenses/by-nc-sa/4.0/](https://creativecommons.org/licenses/by-nc-sa/4.0/)


