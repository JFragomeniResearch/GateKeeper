#!/usr/bin/env python3
"""
Simple test script for the report comparison feature.
"""
from utils.report_compare import ReportComparer

def main():
    """Test the report comparison functionality."""
    # Create a report comparer
    comparer = ReportComparer('reports/sample_scan_20230101.json', 'reports/sample_scan_20230201.json')
    
    # Load the reports
    if not comparer.load_reports():
        print("Failed to load reports!")
        return
    
    # Compare reports and get results
    results = comparer.compare_reports()
    
    # Display some basic results
    print("\nComparison Results:")
    print("===================")
    print(f"Baseline: {results['metadata']['baseline_report']}")
    print(f"Comparison: {results['metadata']['comparison_report']}")
    
    print(f"\nNew ports: {results['changes']['new_ports']}")
    print(f"Closed ports: {results['changes']['closed_ports']}")
    print(f"Service changes: {results['changes']['service_changes']}")
    print(f"Total changes: {results['changes']['total_changes']}")
    
    # Generate a report
    output_path = comparer.generate_comparison_report()
    print(f"\nComparison report saved to: {output_path}")

if __name__ == "__main__":
    main() 