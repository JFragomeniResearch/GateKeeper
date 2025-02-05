# GateKeeper Network Scanner

## Overview
GateKeeper is a network port scanning tool designed for authorized security testing and network administration. It provides a reliable and efficient way to scan network ports while maintaining ethical and legal compliance.

## ⚠️ Legal Disclaimer
This tool is intended for authorized use only. Users must ensure they have explicit permission to scan any target networks. Unauthorized scanning of networks may be illegal in your jurisdiction and could result in civil and/or criminal penalties.

## Features
- TCP port scanning with configurable ranges
- Multi-threaded scanning for improved performance
- Rate limiting to prevent network flooding
- Detailed logging and reporting
- Service identification for common ports
- Built-in safety features and scan authorization checks

## Requirements
- Python 3.7+
- Required Python packages:
  - socket (built-in)
  - argparse (built-in)
  - concurrent.futures (built-in)
  - colorama (optional, for colored output)

## Installation

1. Clone the repository (bash)

git clone https://github.com/yourusername/gatekeeper.git

2. Navigate to the project directory

cd gatekeeper

3. Install optional dependencies

pip install colorama

## Usage
Basic usage (bash):

python gatekeeper.py -t example.com -p 1-1024

Options:
- `-t, --target`: Target hostname or IP address
- `-p, --ports`: Port range to scan (e.g., "80" or "1-1024")
- `-th, --threads`: Number of concurrent threads (default: 100)
- `--timeout`: Connection timeout in seconds (default: 1)
- `--rate-limit`: Time between connection attempts in seconds (default: 0.1)

## Output
Results are saved in the `reports/` directory with the following format (yaml):

Target: example.com (192.168.1.1)
Scan Date: YYYY-MM-DD HH:MM
Open Ports:
Port 22: SSH
Port 80: HTTP
Port 443: HTTPS

## Author
Joseph Fragomeni

Application created using Cursor.ai IDE for applied/educational purposes.