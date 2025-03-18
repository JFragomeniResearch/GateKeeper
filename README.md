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
- Report Comparison Tool - Compare scan results over time to identify network changes
- **NEW: Port Behavior Analysis** - Detect anomalous port behavior patterns across multiple scans
- **NEW: Scan Policy Templates** - Create, manage, and apply reusable scan configurations
- **NEW: Target Groups** - Organize targets into logical groups for easier management and scanning

## Requirements
- Python 3.7+
- Required Python packages:
  - socket (built-in)
  - argparse (built-in)
  - concurrent.futures (built-in)
  - numpy (for statistical analysis)
  - colorama (for colored output)
  - dnspython
  - cryptography
  - pyyaml (for policy import/export)

## Installation

1. Clone the repository (bash)

git clone https://github.com/yourusername/gatekeeper.git

2. Navigate to the project directory

cd gatekeeper

3. Install dependencies

pip install -r requirements.txt

## Usage
Basic usage (bash):

python gatekeeper.py scan -t example.com -p 1-1024

Options:
- `-t, --target`: Target hostname or IP address
- `-f, --target-file`: File containing targets (one per line)
- `-g, --group`: Target group to scan
- `-p, --ports`: Port range to scan (e.g., "80" or "1-1024")
- `--threads`: Number of concurrent threads (default: 100)
- `--timeout`: Connection timeout in seconds (default: 1)
- `--rate-limit`: Time between connection attempts in seconds (default: 0.1)
- `--policy`: Name of scan policy to use
- `--list-policies`: List available scan policies
- `--list-groups`: List available target groups

## Target Groups
The target groups feature allows you to organize scanning targets into logical groups for easier management and more efficient scanning operations.

### Using Target Groups

List available groups:
```bash
python gatekeeper.py groups --list
```

Show group details:
```bash
python gatekeeper.py groups --show web_servers
```

Scan a target group:
```bash
python gatekeeper.py scan -g web_servers -p 80,443
```

### Managing Target Groups

Create a new group:
```bash
python manage_groups.py create web_servers --name "Web Servers" --description "Company web servers" --targets "example.com,192.168.1.100,192.168.1.101"
```

Add targets to a group:
```bash
python manage_groups.py add web_servers --targets "newserver.example.com,192.168.1.102"
```

Remove targets from a group:
```bash
python manage_groups.py remove web_servers --targets "192.168.1.100"
```

Import targets from a file:
```bash
python manage_groups.py import web_servers targets.txt
```

Export targets to a file:
```bash
python manage_groups.py export web_servers exported_targets.txt
```

Delete a group:
```bash
python manage_groups.py delete web_servers
```

## Scan Policy Templates
The scan policy templates feature allows you to define, save, and reuse scanning configurations for different security scenarios.

### Using Scan Policies

List available policies:
```bash
python gatekeeper.py policies --list-policies
```

or

```bash
python manage_policies.py list
```

Show policy details:
```bash
python manage_policies.py show quick
```

Create a new policy:
```bash
python manage_policies.py create web_server --name "Web Server Scan" --description "Scan for common web server ports" --ports "80,443,8080-8090" --threads 50
```

Clone and modify an existing policy:
```bash
python manage_policies.py clone quick custom_quick --name "My Quick Scan" --ports "20-25,80,443"
```

Apply a policy when scanning:
```bash
python gatekeeper.py scan -t example.com --policy quick
```

Export a policy:
```bash
python manage_policies.py export web_server web_server_policy.json
```

Import a policy:
```bash
python manage_policies.py import web_server_policy.json
```

### Built-in Scan Policies

- **Quick Scan**: Fast scan of common ports (21-23,25,53,80,443,3306,3389,8080)
- **Default Scan**: Balanced scan for general security assessments (ports 1-1024)
- **Full Scan**: Comprehensive scan of all ports (1-65535)
- **Stealth Scan**: Low-profile scan to avoid detection
- **Service Detection**: Focused on service and version detection

## Report Comparison Tool
The report comparison feature allows you to compare two scan reports to identify changes in network configuration over time.

### Using the Comparison Tool

List available reports:
```bash
python gatekeeper.py reports
```

Compare two reports:
```bash
python gatekeeper.py compare --report1 reports/scan_target1_20230101.json --report2 reports/scan_target1_20230201.json
```

## Port Behavior Analysis
The new port behavior analysis feature allows you to analyze port behavior patterns across multiple scan reports to detect anomalies and potential security risks.

### Using the Port Behavior Analysis Tool

Analyze port behavior for all targets:
```bash
python gatekeeper.py behavior
```

Analyze port behavior for a specific target:
```bash
python gatekeeper.py behavior -t example.com
```

Use the standalone analysis tool:
```bash
python analyze_port_behavior.py -t example.com
```

List available scan reports:
```bash
python analyze_port_behavior.py --list
```

### Behavior Analysis Features

- **Service Changes** - Detect when services running on ports change over time
- **Intermittent Availability** - Identify ports that are only intermittently available
- **Response Time Anomalies** - Detect unusual response time patterns
- **Recently Opened Ports** - Flag ports that were recently opened
- **Severity Classification** - Anomalies are classified by severity (high, medium, low)
- **Detailed Reports** - Generate comprehensive JSON reports with all detected anomalies

## Output
Scan results are saved in the `reports/` directory.
Comparison reports are saved in the `reports/comparisons/` directory.
Behavior analysis reports are saved in the `reports/behavior/` directory.

## Author
Joseph Fragomeni

Application created for applied/educational purposes.