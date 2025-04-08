#!/usr/bin/env python3

import json
import datetime
import os
from pathlib import Path
import statistics
from typing import Dict, List, Set, Tuple, Optional, Any
import numpy as np
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class PortBehaviorAnalyzer:
    """
    Analyzes port behavior over time by examining multiple scan reports
    to identify anomalous patterns and potential security risks.
    """
    
    def __init__(self, target: str = None, report_dir: str = "reports", max_reports: int = 10):
        """
        Initialize the port behavior analyzer.
        
        Args:
            target: Target host to analyze (None means all targets)
            report_dir: Directory containing scan reports
            max_reports: Maximum number of historical reports to analyze
        """
        self.target = target
        self.report_dir = Path(report_dir)
        self.max_reports = max_reports
        self.reports = []
        self.port_history = {}
        self.anomalies = {}
        
    def load_reports(self) -> bool:
        """
        Load relevant scan reports for the specified target.
        
        Returns:
            bool: True if reports were successfully loaded
        """
        if not self.report_dir.exists():
            print(f"{Fore.RED}Error: Report directory does not exist{Style.RESET_ALL}")
            return False
            
        # Find all JSON and YAML reports
        report_files = []
        for ext in ['.json', '.yaml', '.yml']:
            report_files.extend(sorted(self.report_dir.glob(f"*{ext}"), 
                              key=lambda x: x.stat().st_mtime, reverse=True))
            
        if not report_files:
            print(f"{Fore.YELLOW}No scan reports found in {self.report_dir}{Style.RESET_ALL}")
            return False
            
        # Load reports
        loaded_count = 0
        for report_file in report_files:
            try:
                with open(report_file, 'r') as f:
                    if report_file.suffix.lower() == '.json':
                        data = json.load(f)
                    else:  # YAML/YML
                        import yaml
                        data = yaml.safe_load(f)
                
                # If target is specified, only include matching reports
                report_target = data.get("target", "unknown")
                if self.target is None or report_target == self.target:
                    # Add file path to the data for reference
                    data["_file_path"] = str(report_file)
                    self.reports.append(data)
                    loaded_count += 1
                    
                    # Stop when we reach max_reports
                    if loaded_count >= self.max_reports:
                        break
                        
            except Exception as e:
                print(f"{Fore.YELLOW}Error loading {report_file}: {str(e)}{Style.RESET_ALL}")
                
        if not self.reports:
            if self.target:
                print(f"{Fore.YELLOW}No reports found for target: {self.target}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}No valid reports found{Style.RESET_ALL}")
            return False
            
        print(f"{Fore.GREEN}Loaded {len(self.reports)} reports for analysis{Style.RESET_ALL}")
        return True
    
    def build_port_history(self) -> Dict:
        """
        Build a history of port status and responses over time.
        
        Returns:
            Dict: Port history data
        """
        if not self.reports:
            print(f"{Fore.RED}No reports loaded. Run load_reports() first.{Style.RESET_ALL}")
            return {}
            
        # Process reports to build port history
        port_history = {}
        
        for report in self.reports:
            report_file = report.get("_file_path", "unknown")
            scan_date = report.get("scan_date", "unknown")
            target = report.get("target", "unknown")
            open_ports = report.get("open_ports", {})
            
            # Create a baseline entry for target if it doesn't exist
            if target not in port_history:
                port_history[target] = {}
            
            # Process each port
            for port_str, port_data in open_ports.items():
                port = int(port_str)
                
                # Create entry for this port if it doesn't exist
                if port not in port_history[target]:
                    port_history[target][port] = {
                        "status_history": [],
                        "service_history": [],
                        "response_times": [],
                        "first_seen": scan_date,
                        "last_seen": scan_date
                    }
                
                # Update port history
                port_history[target][port]["status_history"].append({
                    "date": scan_date,
                    "status": "open",
                    "report": report_file
                })
                
                # Update service history if service has changed
                service = port_data.get("service", "unknown")
                service_history = port_history[target][port]["service_history"]
                
                if not service_history or service_history[-1]["service"] != service:
                    service_history.append({
                        "date": scan_date,
                        "service": service,
                        "report": report_file
                    })
                
                # Record response time if available
                response_time = port_data.get("response_time")
                if response_time is not None:
                    port_history[target][port]["response_times"].append({
                        "date": scan_date,
                        "time": float(response_time),
                        "report": report_file
                    })
                
                # Update last seen date
                port_history[target][port]["last_seen"] = scan_date
        
        self.port_history = port_history
        return port_history
    
    def detect_anomalies(self) -> Dict:
        """
        Detect anomalous port behaviors based on historical data.
        
        Returns:
            Dict: Detected anomalies by target and port
        """
        if not self.port_history:
            print(f"{Fore.RED}No port history available. Run build_port_history() first.{Style.RESET_ALL}")
            return {}
            
        anomalies = {}
        
        for target, target_ports in self.port_history.items():
            anomalies[target] = {}
            
            for port, port_data in target_ports.items():
                port_anomalies = []
                
                # Check for service changes
                service_history = port_data["service_history"]
                if len(service_history) > 1:
                    port_anomalies.append({
                        "type": "service_change",
                        "severity": "medium",
                        "details": f"Service changed {len(service_history) - 1} times",
                        "history": service_history
                    })
                
                # Check for intermittent availability
                status_history = port_data["status_history"]
                if len(status_history) < len(self.reports):
                    port_anomalies.append({
                        "type": "intermittent",
                        "severity": "high",
                        "details": f"Port is intermittently available ({len(status_history)}/{len(self.reports)} scans)",
                        "history": status_history
                    })
                
                # Check for response time anomalies
                response_times = port_data["response_times"]
                if len(response_times) >= 3:  # Need at least 3 data points for statistical analysis
                    times = [r["time"] for r in response_times]
                    mean_time = statistics.mean(times)
                    stdev_time = statistics.stdev(times) if len(times) > 1 else 0
                    
                    # Look for outliers (> 2 standard deviations from mean)
                    outliers = []
                    for i, rt in enumerate(response_times):
                        if abs(rt["time"] - mean_time) > 2 * stdev_time:
                            outliers.append({
                                "date": rt["date"],
                                "time": rt["time"],
                                "deviation": (rt["time"] - mean_time) / stdev_time if stdev_time else 0,
                                "report": rt["report"]
                            })
                    
                    if outliers:
                        port_anomalies.append({
                            "type": "response_time",
                            "severity": "medium",
                            "details": f"Unusual response times detected ({len(outliers)} outliers)",
                            "statistics": {
                                "mean": mean_time,
                                "stdev": stdev_time,
                                "min": min(times),
                                "max": max(times)
                            },
                            "outliers": outliers
                        })
                
                # Check for recently opened ports
                if len(self.reports) > 1 and len(status_history) == 1:
                    port_anomalies.append({
                        "type": "recently_opened",
                        "severity": "high",
                        "details": f"Port was recently opened (first seen: {port_data['first_seen']})",
                        "first_seen": port_data["first_seen"]
                    })
                
                # Only add to anomalies if anomalies were detected
                if port_anomalies:
                    anomalies[target][port] = port_anomalies
        
        self.anomalies = anomalies
        return anomalies
    
    def generate_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate a comprehensive port behavior analysis report.
        
        Args:
            output_path: Path to save the report (optional)
            
        Returns:
            str: Path to the generated report
        """
        if not self.anomalies:
            if not self.port_history:
                self.build_port_history()
            self.detect_anomalies()
        
        # Prepare report data
        report_data = {
            "metadata": {
                "generated_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "target": self.target if self.target else "All Targets",
                "reports_analyzed": len(self.reports),
                "report_files": [r.get("_file_path", "unknown") for r in self.reports]
            },
            "summary": {
                "targets_analyzed": len(self.port_history),
                "total_ports": sum(len(ports) for ports in self.port_history.values()),
                "ports_with_anomalies": sum(len(ports) for ports in self.anomalies.values()),
                "total_anomalies": sum(sum(len(anomalies) for anomalies in target.values()) 
                                    for target in self.anomalies.values())
            },
            "anomalies": self.anomalies,
            "port_history": self.port_history
        }
        
        # Generate default output path if not provided
        if not output_path:
            report_dir = Path("reports/behavior")
            report_dir.mkdir(exist_ok=True, parents=True)
            
            target_str = self.target.replace('.', '_') if self.target else "all"
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = report_dir / f"behavior_{target_str}_{timestamp}.json"
        else:
            output_path = Path(output_path)
            output_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Save report to file
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        return str(output_path)
    
    def print_analysis_summary(self) -> None:
        """
        Print a human-readable summary of the port behavior analysis.
        """
        if not self.anomalies:
            if not self.port_history:
                self.build_port_history()
            self.detect_anomalies()
            
        if not self.port_history:
            print(f"{Fore.RED}No data available for analysis{Style.RESET_ALL}")
            return
        
        # Print report header
        print(f"\n{Fore.CYAN}========== GATEKEEPER PORT BEHAVIOR ANALYSIS =========={Style.RESET_ALL}")
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {self.target if self.target else 'All targets'}")
        print(f"{Fore.CYAN}Reports analyzed:{Style.RESET_ALL} {len(self.reports)}")
        print(f"{Fore.CYAN}Analysis time:{Style.RESET_ALL} {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Calculate statistics
        total_ports = sum(len(ports) for ports in self.port_history.values())
        anomalous_ports = sum(len(ports) for ports in self.anomalies.values())
        
        # Print summary statistics
        print(f"\n{Fore.YELLOW}=== ANALYSIS SUMMARY ==={Style.RESET_ALL}")
        print(f"Targets analyzed: {len(self.port_history)}")
        print(f"Total ports examined: {total_ports}")
        print(f"Ports with anomalous behavior: {anomalous_ports} ({anomalous_ports/total_ports*100:.1f}% of total)")
        
        # Print anomalies by severity
        high_severity = 0
        medium_severity = 0
        low_severity = 0
        
        for target, ports in self.anomalies.items():
            for port, anomalies in ports.items():
                for anomaly in anomalies:
                    severity = anomaly.get("severity", "low")
                    if severity == "high":
                        high_severity += 1
                    elif severity == "medium":
                        medium_severity += 1
                    else:
                        low_severity += 1
        
        print(f"\n{Fore.RED}High severity anomalies: {high_severity}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Medium severity anomalies: {medium_severity}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Low severity anomalies: {low_severity}{Style.RESET_ALL}")
        
        # Print details of high-severity anomalies
        if high_severity > 0:
            print(f"\n{Fore.RED}=== HIGH SEVERITY ANOMALIES ==={Style.RESET_ALL}")
            for target, ports in self.anomalies.items():
                for port, anomalies in ports.items():
                    for anomaly in anomalies:
                        if anomaly.get("severity") == "high":
                            anomaly_type = anomaly.get("type", "unknown")
                            details = anomaly.get("details", "No details available")
                            print(f"{Fore.RED}[{target}:{port}] {anomaly_type.upper()}: {details}{Style.RESET_ALL}")
        
        # Print sample of other anomalies (limited to 5)
        if medium_severity + low_severity > 0:
            print(f"\n{Fore.YELLOW}=== OTHER ANOMALIES (SAMPLE) ==={Style.RESET_ALL}")
            count = 0
            for target, ports in self.anomalies.items():
                for port, anomalies in ports.items():
                    for anomaly in anomalies:
                        if anomaly.get("severity") != "high":
                            anomaly_type = anomaly.get("type", "unknown")
                            details = anomaly.get("details", "No details available")
                            severity = anomaly.get("severity", "low")
                            color = Fore.YELLOW if severity == "medium" else Fore.GREEN
                            print(f"{color}[{target}:{port}] {anomaly_type.upper()}: {details}{Style.RESET_ALL}")
                            count += 1
                            if count >= 5:
                                break
                    if count >= 5:
                        break
                if count >= 5:
                    break
                    
            if medium_severity + low_severity > 5:
                print(f"{Fore.YELLOW}... and {medium_severity + low_severity - 5} more{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}=========================================={Style.RESET_ALL}")


def find_scan_reports(report_dir: str = "reports", limit: int = 10) -> List[str]:
    """
    Find scan reports in the specified directory.
    
    Args:
        report_dir: Directory containing reports
        limit: Maximum number of reports to return
        
    Returns:
        List[str]: List of report file paths
    """
    report_dir = Path(report_dir)
    if not report_dir.exists() or not report_dir.is_dir():
        return []
    
    # Get all JSON and YAML files
    report_files = []
    for ext in ['.json', '.yaml', '.yml']:
        report_files.extend(report_dir.glob(f"*{ext}"))
    
    # Sort by modification time (newest first)
    report_files.sort(key=lambda x: x.stat().st_mtime, reverse=True)
    
    # Return paths as strings
    return [str(f) for f in report_files[:limit]] 