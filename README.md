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
- **NEW: Export Tool** - Export scan results to CSV and HTML formats for reporting and analysis
- **NEW: Scheduled Scanning** - Set up recurring scans to run automatically at specified intervals
- **NEW: Notification System** - Receive alerts via email and webhooks when scan results match defined criteria

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
  - schedule (for scheduled scanning)
  - requests (for webhook notifications)

## Author
Joseph Fragomeni

Application created using Cursor.ai for applied/educational purposes.

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
- `--notify`: Send notifications for scan results based on configured rules

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

## Export Functionality
The new export feature allows you to export scan results to different formats for easier data analysis and reporting.

### Exporting Scan Results

Export a scan report to both CSV and HTML formats using the GateKeeper command:
```bash
python gatekeeper.py export reports/scan_example.com_20230601.json
```

Or use the standalone export script for better user experience:
```bash
python export_report.py reports/scan_example.com_20230601.json
```

Export a scan report to CSV format only:
```bash
python export_report.py reports/scan_example.com_20230601.json --format csv
```

Export a scan report to HTML format only:
```bash
python export_report.py reports/scan_example.com_20230601.json --format html
```

Specify a custom output filename:
```bash
python export_report.py reports/scan_example.com_20230601.json --output custom_report_name
```

The exported files will be saved in the `reports/exports/` directory.

### Export Formats

- **CSV Export**: Creates a comma-separated values file that can be imported into spreadsheet software like Excel or Google Sheets for data analysis.
- **HTML Export**: Creates a well-formatted HTML report with styling for easy viewing in a web browser. The HTML report includes scan information and a table of open ports with their details.

## Scheduled Scanning
The new scheduled scanning feature allows you to set up recurring scans at specified intervals. This is especially useful for continuous security monitoring of your network infrastructure.

### Managing Scheduled Scans

List all scheduled scans:
```bash
python scheduled_scan.py list
```

Add a new daily scheduled scan:
```bash
python scheduled_scan.py add --name daily_webservers --target-group web_servers --policy quick --time 02:00 --interval daily
```

Add a weekly scheduled scan:
```bash
python scheduled_scan.py add --name weekly_scan --target example.com --ports 1-1024 --interval weekly --day monday --time 22:00
```

Add a monthly scheduled scan:
```bash
python scheduled_scan.py add --name monthly_compliance --target-group all_servers --policy compliance --interval monthly --day 1 --time 01:00
```

Remove a scheduled scan:
```bash
python scheduled_scan.py remove --name daily_webservers
```

### Running the Scheduler

Run the scheduler in the foreground:
```bash
python scheduled_scan.py run
```

Run the scheduler in the background:
```bash
python scheduled_scan.py run --daemon
```

### System Service Setup

#### Linux (systemd)

To run the scheduler as a system service on Linux systems with systemd:

1. Copy the service template:
```bash
sudo cp systemd/gatekeeper-scheduler.service /etc/systemd/system/
```

2. Edit the service file to set the correct paths and username:
```bash
sudo nano /etc/systemd/system/gatekeeper-scheduler.service
```

3. Enable and start the service:
```bash
sudo systemctl enable gatekeeper-scheduler.service
sudo systemctl start gatekeeper-scheduler.service
```

#### Windows

To set up the scheduler as a scheduled task on Windows:

1. Run the setup script as Administrator:
```cmd
scripts\setup_windows_task.bat
```

2. You can customize the task settings in the Windows Task Scheduler.

### Schedule Configuration

Schedules are stored in YAML format in the `schedules/schedules.yaml` file. You can view a sample configuration in `schedules/sample_schedules.yaml`.

Each schedule includes the following settings:
- `interval`: How often to run the scan (hourly, daily, weekly, monthly)
- `time`: The time to run the scan in HH:MM format
- `day`: For weekly scans, the day of the week; for monthly scans, the day of the month
- `target` or `target_group`: The scan target (individual host or target group)
- `policy`: The scan policy to apply
- `ports`: Optional port range to scan
- `format`: Output format (json, csv, html, all)

### Logs

The scheduler logs are stored in `logs/scheduler.log`. You can monitor this file to track scheduled scan execution:

```bash
tail -f logs/scheduler.log
```

## Notification System
The new notification system allows you to receive alerts about scan results through various channels such as email and webhooks. You can define custom rules to trigger notifications based on specific conditions in the scan results.

### Managing Notification Settings

Show notification configuration:
```bash
python gatekeeper.py notifications show-config
```

Configure email notifications:
```bash
python gatekeeper.py notifications config-email --enable --smtp-server smtp.gmail.com --smtp-port 587 --username your-email@gmail.com --password your-password --from your-email@gmail.com --to recipient1@example.com recipient2@example.com --use-tls
```

Configure Slack webhook:
```bash
python gatekeeper.py notifications config-webhook --type slack --enable --url https://hooks.slack.com/services/your/webhook/url
```

Configure Microsoft Teams webhook:
```bash
python gatekeeper.py notifications config-webhook --type teams --enable --url https://example.webhook.office.com/webhookb2/your/webhook/url
```

### Managing Notification Rules

List notification rules:
```bash
python gatekeeper.py notifications rules list
```

Add a new notification rule:
```bash
python gatekeeper.py notifications rules add --name "Critical Services" --condition specific_service --services ssh telnet ftp rdp --severity critical --notify email slack
```

Another example rule:
```bash
python gatekeeper.py notifications rules add --name "Many Open Ports" --condition min_open_ports --threshold 10 --severity warning --message "High number of open ports ({count}) on {target}"
```

Enable or disable a rule:
```bash
python gatekeeper.py notifications rules toggle --name "Critical Services" --enable
python gatekeeper.py notifications rules toggle --name "Many Open Ports" --disable
```

Delete a rule:
```bash
python gatekeeper.py notifications rules delete --name "Critical Services"
```

### Testing Notifications

Test email notifications:
```bash
python gatekeeper.py notifications test --channel email
```

Test Slack webhook:
```bash
python gatekeeper.py notifications test --channel slack
```

### Triggering Notifications on Scans

Run a scan with notifications enabled:
```bash
python gatekeeper.py scan -t example.com -p 1-1024 --notify
```

Compare reports with notifications enabled:
```bash
python gatekeeper.py compare --report1 reports/scan1.json --report2 reports/scan2.json --notify
```

Analyze behavior with notifications enabled:
```bash
python gatekeeper.py behavior -t example.com --notify
```

### Default Notification Rules

- **Any Open Ports**: Triggers a notification whenever any open ports are found
- **Critical Services**: Triggers a critical notification when sensitive services (SSH, Telnet, FTP, RDP) are detected
- **Many Open Ports**: Triggers a warning when more than 10 open ports are found on a target

### Notification Templates

Notification messages support the following template variables:
- `{target}`: The target hostname or IP address
- `{count}`: The number of open ports found
- `{timestamp}`: The scan timestamp
- `{condition}`: The rule condition that triggered the notification
- `{threshold}`: The threshold value for conditions that use thresholds