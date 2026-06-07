# 🔍 Network Traffic Analyzer

Real-time packet capture and threat detection tool built in Python.

## Features
- **ARP Spoofing Detection** — monitors ARP table for MAC changes
- **Port Scan Detection** — alerts when a host probes 20+ ports
- **ICMP Flood Detection** — detects ping flood attacks
- **Live terminal output** with color-coded alerts
- **JSON report** + PCAP file export

## Screenshot
![Network Analyzer](../screenshots/01_network_analyzer.png)

## Installation
```bash
pip install scapy
```

## Usage
```bash
sudo python analyzer.py -i eth0 -c 200 -o capture.pcap
```

## Tools Used
`Python` `Scapy` `Wireshark` `TCP/IP`
