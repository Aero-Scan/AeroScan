# AeroScan - Wireless Network Q&P Monitoring

[![License: CC BY-NC 4.0](https://img.shields.io/badge/License-CC%20BY--NC%204.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc/4.0/)

## Overview

AeroScan is an IoT-based system designed to monitor the Quality and Performance (Q&P) of the wireless network infrastructure at Murdoch University (MU). Developed for MU IT Services (ITS), this project utilizes Raspberry Pi devices deployed across campus to collect real-time network metrics, providing valuable insights into network health, identifying potential issues, and helping to ensure a reliable wireless experience for students and staff.

The system addresses the need for automated, continuous monitoring, moving beyond manual checks and reactive troubleshooting. Data collected by the Raspberry Pi units is visualized through a centralized Grafana dashboard, offering ITS a clear view of network performance across different locations.

## Features

* **Real-Time Monitoring:** Continuously scans and collects data on wireless network performance.
* **Comprehensive Metrics:** Gathers data on:
    * Wireless Signal Strength (RSSI)
    * Wireless Noise Levels
    * Network Latency (Ping Times)
    * Network Jitter
    * Internet Bandwidth (Upload/Download via Speedtest)
    * Connected Access Point details (SSID, BSSID)
* **Multi-AP Scanning:** Capable of scanning and reporting on multiple Wireless Access Points (WAPs) within range.
* **Disruption Handling:** Designed to detect when a connected WAP goes down, automatically scan for, and connect to the next available WAP.
* **Alerting:** Sends notifications to MU ITS when a monitored WAP becomes unavailable (requires configuration with an alerting system like Prometheus Alertmanager).
* **Scalability:** Built to support multiple Raspberry Pi devices deployed across campus for wide coverage.
* **Centralized Visualization:** Integrates with Prometheus for data scraping and Grafana for displaying metrics on a dashboard.
* **Remote Accessibility:** Devices can be configured for remote access (e.g., via SSH) for maintenance and troubleshooting.

## Technology Stack

* **Hardware:** Raspberry Pi (Tested on Zero WH, Pi 4 Model B recommended for 5GHz)
* **OS:** Raspberry Pi OS (or other compatible Linux distribution)
* **Core Scripting:** Python 3
* **Data Collection Tools:**
    * `ping` (from iputils or similar)
    * `speedtest-cli`
    * `iw`
* **Data Storage/Scraping:** Prometheus
* **Data Visualization:** Grafana
* **Version Control:** Git / GitHub

## Hardware Requirements

* Raspberry Pi (Zero WH or Pi 4 Model B recommended)
* MicroSD Card (>= 16GB recommended, e.g., SanDisk Ultra 32GB)
* Reliable Power Supply for the Raspberry Pi
* (Optional) Case for the Raspberry Pi

## Setup and Installation

Follow these steps to set up an AeroScan monitoring node on a Raspberry Pi:

1.  **Prepare Raspberry Pi OS:**
    * Download the latest Raspberry Pi OS Lite (64-bit recommended if using Pi 4).
    * Flash the OS onto the MicroSD card using Raspberry Pi Imager or BalenaEtcher.
    * Enable SSH and configure Wi-Fi credentials headless (via Raspberry Pi Imager or by creating `ssh` and `wpa_supplicant.conf` files in the boot partition).

2.  **Initial Boot & Configuration:**
    * Insert the SD card into the Pi and power it on.
    * Connect to the Pi via SSH (`ssh pi@<raspberrypi_ip>`). Default password is `raspberry`.
    * Run `sudo raspi-config`:
        * Change the default password.
        * Set locale, timezone, and keyboard layout.
        * Expand the filesystem.
        * Update the system: `sudo apt update && sudo apt upgrade -y`

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

AeroScan is licensed under the **Creative Commons Attribution-NonCommercial 4.0 International License (CC BY-NC 4.0)**.

You are free to **share** (copy and redistribute the material in any medium or format) and **adapt** (remix, transform, and build upon the material) under the following terms:

* **Attribution** — You must give appropriate credit, provide a link to the license, and indicate if changes were made. You may do so in any reasonable manner, but not in any way that suggests the licensor endorses you or your use.
* **NonCommercial** — You may not use the material for commercial purposes.
* **No additional restrictions** — You may not apply legal terms or technological measures that legally restrict others from doing anything the license permits.

For more information, see the [full license text](LICENSE) in this repository or visit:
[https://creativecommons.org/licenses/by-nc/4.0/](https://creativecommons.org/licenses/by-nc/4.0/)


