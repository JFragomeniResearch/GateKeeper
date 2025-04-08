#!/usr/bin/env python3
"""
GateKeeper Port Behavior Analysis Tool

This tool analyzes port behavior across multiple scan reports to detect
anomalous patterns and potential security risks.
"""

import sys
import argparse
from pathlib import Path
from utils.port_behavior import PortBehaviorAnalyzer, find_scan_reports
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Port Behavior Analysis Tool',
        epilog='Analyze port behavior across multiple scan reports to detect anomalies'
    )
    
    parser.add_argument('-t', '--target', 
                        help='Target host to analyze (default: analyze all targets)')
    parser.add_argument('-d', '--dir', default='reports',
                        help='Directory containing scan reports (default: reports)')
    parser.add_argument('-n', '--max-reports', type=int, default=10,
                        help='Maximum number of reports to analyze (default: 10)')
    parser.add_argument('-o', '--output',
                        help='Output file for analysis results (default: auto-generated)')
    parser.add_argument('-l', '--list', action='store_true',
                        help='List available scan reports and exit')
    
    args = parser.parse_args()
    return args

def main():
    """Main function for the port behavior analysis tool."""
    args = parse_arguments()
    
    # List available reports if requested
    if args.list:
        reports = find_scan_reports(args.dir, limit=20)
        
        if not reports:
            print(f"{Fore.YELLOW}No scan reports found in {args.dir}{Style.RESET_ALL}")
            sys.exit(0)
        
        print(f"\n{Fore.CYAN}Available scan reports (most recent first):{Style.RESET_ALL}")
        for i, report in enumerate(reports, 1):
            report_path = Path(report)
            print(f"{i}. {report_path.name}")
        
        print(f"\nTo analyze these reports, run without --list\n")
        sys.exit(0)
    
    # Initialize the analyzer
    analyzer = PortBehaviorAnalyzer(
        target=args.target,
        report_dir=args.dir,
        max_reports=args.max_reports
    )
    
    # Load and analyze reports
    print(f"{Fore.CYAN}Loading scan reports from {args.dir}...{Style.RESET_ALL}")
    if not analyzer.load_reports():
        print(f"{Fore.RED}Could not load enough reports for analysis. Exiting.{Style.RESET_ALL}")
        sys.exit(1)
    
    print(f"{Fore.CYAN}Building port history...{Style.RESET_ALL}")
    analyzer.build_port_history()
    
    print(f"{Fore.CYAN}Detecting anomalous behavior...{Style.RESET_ALL}")
    analyzer.detect_anomalies()
    
    # Print analysis summary
    analyzer.print_analysis_summary()
    
    # Generate and save report
    output_path = analyzer.generate_report(args.output)
    print(f"\n{Fore.GREEN}Analysis report saved to: {output_path}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Analysis interrupted by user.{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1) 