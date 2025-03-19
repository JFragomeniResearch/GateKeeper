#!/usr/bin/env python3
"""
GateKeeper Report Exporter

This script exports GateKeeper scan reports to CSV and HTML formats.
Usage:
    python export_report.py reports/scan_example.com_20230601.json --format csv
"""

import argparse
import json
import sys
import os
from pathlib import Path
from utils.export import export_results
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Report Exporter',
        epilog='Export scan reports to different formats for analysis and reporting.'
    )
    
    parser.add_argument('report', help='Path to the report file to export')
    parser.add_argument('--format', choices=['csv', 'html', 'both'], default='both', 
                        help='Export format (default: both)')
    parser.add_argument('--output', help='Output file name (without extension)')
    
    args = parser.parse_args()
    return args

def main():
    """Main function for the report exporter."""
    args = parse_arguments()
    
    # Display banner
    print(f"\n{Fore.CYAN}=== GateKeeper Report Exporter ==={Style.RESET_ALL}\n")
    
    try:
        # Check if the report file exists
        if not os.path.exists(args.report):
            print(f"{Fore.RED}Error: Report file '{args.report}' not found{Style.RESET_ALL}")
            sys.exit(1)
            
        # Load the report data
        print(f"{Fore.YELLOW}Loading report: {args.report}{Style.RESET_ALL}")
        with open(args.report, 'r') as f:
            try:
                report_data = json.load(f)
            except json.JSONDecodeError:
                print(f"{Fore.RED}Error: Invalid JSON format in report file{Style.RESET_ALL}")
                sys.exit(1)
        
        # Determine the output filename
        if args.output:
            output_filename = args.output
        else:
            # Use the report filename without extension
            output_filename = os.path.splitext(os.path.basename(args.report))[0]
        
        # Prepare the results data for export
        target = report_data.get('scan_info', {}).get('target', 'Unknown')
        scan_date = report_data.get('scan_info', {}).get('timestamp', '')
        
        # Calculate scan duration if available
        scan_duration = "Unknown"
        if 'scan_info' in report_data and 'scan_duration' in report_data['scan_info']:
            scan_duration = f"{report_data['scan_info']['scan_duration']:.2f} seconds"
        
        # Print scan info
        print(f"\n{Fore.CYAN}Scan Information:{Style.RESET_ALL}")
        print(f"  Target: {target}")
        print(f"  Date: {scan_date}")
        print(f"  Open Ports: {report_data.get('scan_info', {}).get('open_ports_found', 0)}")
        
        # Format the results for our exporter
        results = {
            "target": target,
            "scan_date": scan_date,
            "scan_duration": scan_duration,
            "open_ports": report_data.get('results', [])
        }
        
        # Create exports directory if it doesn't exist
        Path('reports/exports').mkdir(parents=True, exist_ok=True)
        
        # Export based on the format specified
        if args.format == 'csv' or args.format == 'both':
            print(f"\n{Fore.YELLOW}Exporting to CSV...{Style.RESET_ALL}")
            csv_path = export_results(results, output_filename, 'csv')
            print(f"{Fore.GREEN}Exported CSV report to: {csv_path}{Style.RESET_ALL}")
            
        if args.format == 'html' or args.format == 'both':
            print(f"\n{Fore.YELLOW}Exporting to HTML...{Style.RESET_ALL}")
            html_path = export_results(results, output_filename, 'html')
            print(f"{Fore.GREEN}Exported HTML report to: {html_path}{Style.RESET_ALL}")
            
        print(f"\n{Fore.GREEN}Export completed successfully!{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}Error during export: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == '__main__':
    main() 