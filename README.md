# AeroScan

The **AeroScan** project turns Raspberry Pis' into network scanners. Each Pi collects key network performance metrics—ping latency, jitter, TTL, download/upload speeds, signal strength, and nearby access point details—and exposes them via a Prometheus endpoint. A Docker‑based stack bundles Prometheus and Grafana for centralized metrics collection and visualization.

## Table of Contents

1. [Introduction](#introduction)  
2. [Architecture](#architecture)  
3. [Features](#features)  
4. [Prerequisites](#prerequisites)  
5. [Installation](#installation)  
6. [Configuration](#configuration)  
7. [Usage](#usage)  
8. [Exported Metrics](#exported-metrics)  
9. [Contributing](#contributing)  
10. [License](#license)  

## Introduction

AeroScan leverages the Raspberry Pi’s portability, and wifi scanning capability and Prometheus’s monitoring capabilities to provide a lightweight, distributed network scanning solution. Deploy Pis at remote locations or across your premises to continually monitor connectivity quality and wireless environment health.

## Architecture

- **Pi Agent**: A Python script (`main.py`) running on each Raspberry Pi. Collects network metrics and serves them on port `8000` via Prometheus’s Python client.  
- **Docker Stack**: A `docker-compose` setup with:  
  - **Prometheus** (port 9090) scraping each Pi’s exporter endpoint.  
  - **Grafana** (port 3000) for dashboards and alerting.  
- **Configuration**: Modify IP targets and interface names via the `pi/config/pi_config.txt` and `Docker/prometheus.yml` files.

## Features

- **Ping Metrics**: Latency, TTL, and calculated jitter.  
- **Speedtest Metrics**: Download, upload speeds, and ping.  
- **Wireless Metrics**: Connected network’s signal strength and link quality.  
- **Wi‑Fi Scan**: Nearby AP SSIDs, BSSIDs, channels, and RSSI values.  
- **Device Identifier**: Persistent unique ID based on Pi serial number and timestamp, triggerable via dual‑button press.  
- **Prometheus Export**: All metrics exposed as Prometheus Gauges.

## Prerequisites

- **Hardware**: Raspberry Pi.  
- **OS**: Raspberry Pi OS (or Debian‑based distro).  
- **Dependencies on Pi**:  
  - Python 3  
  - `pip3` packages: `prometheus_client`, `speedtest-cli`  
  - System packages: `wireless-tools`, `iproute2`, `python3-rpi.gpio`  
- **Docker Host**: Docker & Docker Compose v1.27+

## Installation

1. **Clone the repository**
    ```bash
    git clone https://github.com/Aero-Scan/AeroScan.git
    cd AeroScan
    ```

3. **Deploy Docker Stack**
    ```bash
    cd Docker
    docker-compose up -d
    ```

## Configuration

- **Pi Agent**: Edit `pi/config/pi_config.txt` to adjust the install commands or execution flags as needed.  
- **Prometheus**: In `Docker/prometheus.yml`, add each Pi’s IP (e.g., `192.168.x.x:8000`) under `static_configs.targets`.

## Usage

- **Run the Pi exporter**
    ```bash
    cd ~/AeroScan/pi/software
    sudo python3 main.py
    ```

- **Access Prometheus**  
  Browse to `http://<docker-host>:9090`.

- **Access Grafana**  
  Browse to `http://<docker-host>:3000` (default credentials: `admin`/`admin`).

## Exported Metrics

| Metric                           | Description                                         |
|----------------------------------|-----------------------------------------------------|
| `network_ping_response_time_ms`  | Ping first‑packet RTT (ms)                          |
| `network_ttl`                    | Ping first‑packet TTL                               |
| `network_jitter_ms`              | Ping jitter calculated over 5 packets (ms)          |
| `speedtest_ping_ms`              | Speedtest ping (ms)                                 |
| `download_speed_mbps`            | Download throughput (Mbps)                          |
| `upload_speed_mbps`              | Upload throughput (Mbps)                            |
| `signal_strength_dbm`            | Connected Wi‑Fi signal strength (dBm)               |
| `link_quality_percentage`        | Connected Wi‑Fi link quality (%)                    |
| `wifi_ap_signal_strength_dbm{}`  | Nearby AP RSSI by `ssid`, `bssid`, and `channel`    |
| `device_unique_identifier{}`     | Persistent device ID label                          |
| `network_interface_info{}`       | Device IP information by `interface` and `ip_address` |

## Contributing

Contributions are welcome! Please fork the repo, create a feature branch, and submit a pull request. Ensure any new dependencies are documented in the README.

## License

This project is released under the [MIT License](LICENSE).
