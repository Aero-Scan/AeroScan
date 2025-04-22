# Project Title
The AeroScan project turns Raspberry Pis'  into network scanners. Each Pi collects key network performance metrics—ping latency, jitter, TTL, download/upload speeds, signal strength, and nearby access point details—and exposes them via a Prometheus endpoint. A Docker-based stack bundles Prometheus and Grafana for centralized metrics collection and visualization.

## Table of Contents
1. [Introduction](#introduction)
2. [Features](#features)
3. [Architecture](#Architecture)
4. [Installation](#installation)
5. [Usage](#usage)
6. [Contributing](#contributing)
7. [License](#license)

## Introduction
AeroScan uses Raspberry Pi’s flexibility and Prometheus’s monitoring capabilities to provide a lightweight, distributed network scanning solution. Deploy Pis at remote locations or across your premises to continually monitor connectivity quality and wireless environment health. 

## Architecture
Pi Agent: A Python script (main.py) running on each Raspberry Pi. Collects network metrics and serves them on port 8000 via Prometheus’s Python client.

Docker Stack: A docker-compose setup with:

  Prometheus (port 9090) scraping each Pi’s exporter endpoint.
  
  Grafana (port 3000) for dashboards and alerting.

Configuration: Modify IP targets and interface names via the pi/config/pi_config.txt and Docker/prometheus.yml files.

## Features


## Installation

```bash
git clone https://github.com/Aero-Scan/AeroScan.git
cd AeroScan
```
## Usage

## Contribution

## License

