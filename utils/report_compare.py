#!/usr/bin/env python3

from pathlib import Path
import json
import yaml
import os
import datetime
import argparse
import sys
from typing import Dict, List, Tuple, Set, Optional
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class ReportComparer:
    """
    A class for comparing two GateKeeper scan reports to identify changes
    in network configuration and security posture over time.
    """
    
    def __init__(self, report1_path: str, report2_path: str):
        """
        Initialize with paths to two reports for comparison.
        
        Args:
            report1_path: Path to the baseline/older report
            report2_path: Path to the newer report
        """
        self.report1_path = Path(report1_path)
        self.report2_path = Path(report2_path)
        self.report1_data = None
        self.report2_data = None
        
    def load_reports(self) -> bool:
        """
        Load report data from files.
        
        Returns:
            bool: True if both reports loaded successfully
        """
        if not self.report1_path.exists() or not self.report2_path.exists():
            print(f"{Fore.RED}Error: One or both report files don't exist{Style.RESET_ALL}")
            return False
            
        try:
            # Determine file type by extension
            if self.report1_path.suffix.lower() == '.json':
                with open(self.report1_path, 'r') as f:
                    self.report1_data = json.load(f)
            elif self.report1_path.suffix.lower() in ['.yaml', '.yml']:
                with open(self.report1_path, 'r') as f:
                    self.report1_data = yaml.safe_load(f)
            else:
                print(f"{Fore.RED}Error: Unsupported file format for report 1{Style.RESET_ALL}")
                return False
                
            if self.report2_path.suffix.lower() == '.json':
                with open(self.report2_path, 'r') as f:
                    self.report2_data = json.load(f)
            elif self.report2_path.suffix.lower() in ['.yaml', '.yml']:
                with open(self.report2_path, 'r') as f:
                    self.report2_data = yaml.safe_load(f)
            else:
                print(f"{Fore.RED}Error: Unsupported file format for report 2{Style.RESET_ALL}")
                return False
                
            return True
        except Exception as e:
            print(f"{Fore.RED}Error loading reports: {str(e)}{Style.RESET_ALL}")
            return False
    
    def compare_reports(self) -> Dict:
        """
        Compare two reports and identify differences.
        
        Returns:
            Dict: Comparison results
        """
        if not self.report1_data or not self.report2_data:
            if not self.load_reports():
                return {"error": "Failed to load reports"}
        
        # Extract basic information
        report1_target = self.report1_data.get("target", "Unknown")
        report2_target = self.report2_data.get("target", "Unknown")
        
        # Check if comparing reports for the same target
        if report1_target != report2_target:
            print(f"{Fore.YELLOW}Warning: Comparing reports for different targets: "
                  f"{report1_target} vs {report2_target}{Style.RESET_ALL}")
        
        # Extract scan dates
        report1_date = self.report1_data.get("scan_date", "Unknown")
        report2_date = self.report2_data.get("scan_date", "Unknown")
        
        # Extract open ports
        report1_ports = set(int(port) for port in self.report1_data.get("open_ports", {}).keys())
        report2_ports = set(int(port) for port in self.report2_data.get("open_ports", {}).keys())
        
        # Calculate differences
        new_ports = report2_ports - report1_ports
        closed_ports = report1_ports - report2_ports
        common_ports = report1_ports.intersection(report2_ports)
        
        # Check for service changes on common ports
        service_changes = {}
        for port in common_ports:
            port_str = str(port)
            service1 = self.report1_data.get("open_ports", {}).get(port_str, {}).get("service", "Unknown")
            service2 = self.report2_data.get("open_ports", {}).get(port_str, {}).get("service", "Unknown")
            
            if service1 != service2:
                service_changes[port] = {
                    "old": service1,
                    "new": service2
                }
        
        # Prepare comparison results
        results = {
            "metadata": {
                "baseline_report": str(self.report1_path),
                "comparison_report": str(self.report2_path),
                "baseline_date": report1_date,
                "comparison_date": report2_date,
                "target": report1_target,
                "comparison_target": report2_target,
                "comparison_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            "changes": {
                "new_ports": sorted(list(new_ports)),
                "closed_ports": sorted(list(closed_ports)),
                "service_changes": service_changes,
                "total_changes": len(new_ports) + len(closed_ports) + len(service_changes)
            },
            "statistics": {
                "baseline_ports_count": len(report1_ports),
                "current_ports_count": len(report2_ports),
                "unchanged_ports_count": len(common_ports) - len(service_changes)
            }
        }
        
        return results
    
    def generate_comparison_report(self, output_path: Optional[str] = None) -> str:
        """
        Generate a comparison report and save it to a file.
        
        Args:
            output_path: Path to save the report (optional)
            
        Returns:
            str: Path to the generated report file
        """
        comparison_results = self.compare_reports()
        
        if "error" in comparison_results:
            return f"Error: {comparison_results['error']}"
        
        # Generate default output path if not provided
        if not output_path:
            report_dir = Path("reports/comparisons")
            report_dir.mkdir(exist_ok=True, parents=True)
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_path = report_dir / f"comparison_{timestamp}.json"
        else:
            output_path = Path(output_path)
            # Create directory if it doesn't exist
            output_path.parent.mkdir(exist_ok=True, parents=True)
        
        # Save report to file
        with open(output_path, 'w') as f:
            json.dump(comparison_results, f, indent=4)
        
        return str(output_path)
    
    def print_comparison_summary(self) -> None:
        """
        Print a human-readable summary of the comparison results.
        """
        comparison_results = self.compare_reports()
        
        if "error" in comparison_results:
            print(f"{Fore.RED}Error: {comparison_results['error']}{Style.RESET_ALL}")
            return
        
        metadata = comparison_results["metadata"]
        changes = comparison_results["changes"]
        stats = comparison_results["statistics"]
        
        print(f"\n{Fore.CYAN}========== GATEKEEPER SCAN COMPARISON =========={Style.RESET_ALL}")
        print(f"{Fore.CYAN}Baseline scan:{Style.RESET_ALL} {metadata['baseline_date']} - {metadata['baseline_report']}")
        print(f"{Fore.CYAN}Current scan:{Style.RESET_ALL} {metadata['comparison_date']} - {metadata['comparison_report']}")
        print(f"{Fore.CYAN}Target:{Style.RESET_ALL} {metadata['target']}")
        print(f"{Fore.CYAN}Comparison performed:{Style.RESET_ALL} {metadata['comparison_time']}")
        
        print(f"\n{Fore.YELLOW}=== CHANGES SUMMARY ==={Style.RESET_ALL}")
        print(f"Total changes detected: {changes['total_changes']}")
        
        # New ports
        if changes['new_ports']:
            print(f"\n{Fore.GREEN}New open ports ({len(changes['new_ports'])}):{Style.RESET_ALL}")
            for port in changes['new_ports']:
                port_str = str(port)
                service = self.report2_data.get("open_ports", {}).get(port_str, {}).get("service", "Unknown")
                print(f"  {Fore.GREEN}Port {port}: {service}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.GREEN}No new open ports detected.{Style.RESET_ALL}")
        
        # Closed ports
        if changes['closed_ports']:
            print(f"\n{Fore.RED}Closed ports ({len(changes['closed_ports'])}):{Style.RESET_ALL}")
            for port in changes['closed_ports']:
                port_str = str(port)
                service = self.report1_data.get("open_ports", {}).get(port_str, {}).get("service", "Unknown")
                print(f"  {Fore.RED}Port {port}: {service}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.RED}No closed ports detected.{Style.RESET_ALL}")
        
        # Service changes
        if changes['service_changes']:
            print(f"\n{Fore.YELLOW}Service changes ({len(changes['service_changes'])}):{Style.RESET_ALL}")
            for port, change in changes['service_changes'].items():
                print(f"  {Fore.YELLOW}Port {port}: {change['old']} → {change['new']}{Style.RESET_ALL}")
        else:
            print(f"\n{Fore.YELLOW}No service changes detected.{Style.RESET_ALL}")
        
        # Statistics
        print(f"\n{Fore.BLUE}=== STATISTICS ==={Style.RESET_ALL}")
        print(f"Baseline open ports: {stats['baseline_ports_count']}")
        print(f"Current open ports: {stats['current_ports_count']}")
        print(f"Unchanged ports: {stats['unchanged_ports_count']}")
        
        if changes['total_changes'] == 0:
            print(f"\n{Fore.GREEN}No changes detected between scans.{Style.RESET_ALL}")
        elif changes['total_changes'] > 5:
            print(f"\n{Fore.RED}Warning: Significant network changes detected!{Style.RESET_ALL}")
        
        print(f"\n{Fore.CYAN}=========================================={Style.RESET_ALL}")


def find_latest_reports(report_dir: str = "reports", limit: int = 10) -> List[str]:
    """
    Find the latest scan reports in the specified directory.
    
    Args:
        report_dir: Directory containing reports
        limit: Maximum number of reports to list
        
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


def parse_arguments():
    """Parse command-line arguments for the standalone tool."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Report Comparison Tool',
        epilog='Compare two scan reports to identify network changes'
    )
    
    parser.add_argument('--report1', required=False,
                        help='Path to first (baseline) report')
    parser.add_argument('--report2', required=False,
                        help='Path to second (comparison) report')
    parser.add_argument('-o', '--output', 
                        help='Output file for comparison results (JSON format)')
    parser.add_argument('--list', action='store_true',
                        help='List available reports')
    parser.add_argument('-n', '--limit', type=int, default=10,
                        help='Maximum number of reports to list (default: 10)')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not (args.list or (args.report1 and args.report2)):
        parser.print_help()
        sys.exit(1)
    
    return args


def main():
    """Main function for standalone report comparison."""
    args = parse_arguments()
    
    # List available reports
    if args.list:
        reports = find_latest_reports(limit=args.limit)
        
        if not reports:
            print(f"{Fore.YELLOW}No reports found in the reports directory.{Style.RESET_ALL}")
            sys.exit(0)
        
        print(f"\n{Fore.CYAN}Available scan reports (most recent first):{Style.RESET_ALL}")
        for i, report in enumerate(reports, 1):
            report_path = Path(report)
            mod_time = datetime.datetime.fromtimestamp(report_path.stat().st_mtime)
            print(f"{i}. {report_path.name} - {mod_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        print(f"\nTo compare reports, use: {sys.argv[0]} --report1 <path1> --report2 <path2>\n")
        sys.exit(0)
    
    # Compare reports
    try:
        # Create ReportComparer instance
        comparer = ReportComparer(args.report1, args.report2)
        
        # Print comparison summary
        comparer.print_comparison_summary()
        
        # Generate comparison report
        if args.output:
            output_path = comparer.generate_comparison_report(args.output)
        else:
            output_path = comparer.generate_comparison_report()
        
        print(f"\n{Fore.GREEN}Comparison report saved to: {output_path}{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)


if __name__ == "__main__":
    main() 