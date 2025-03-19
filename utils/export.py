#!/usr/bin/env python3
"""
GateKeeper Export Utilities

This module provides functionality to export scan results to different formats:
- CSV: For data analysis in spreadsheet software
- HTML: For web-based reporting with formatting

Usage:
    from utils.export import export_results
    export_results(results, "output_file", "csv")
"""

import json
import csv
import os
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional


class ResultExporter:
    """Class to handle exporting scan results to different formats."""
    
    def __init__(self, results: Dict[str, Any], filename: str):
        """
        Initialize the exporter with scan results.
        
        Args:
            results: The scan results dictionary
            filename: Base filename without extension
        """
        self.results = results
        self.filename = filename
        
    def export_csv(self, output_dir: str = "reports/exports") -> str:
        """
        Export results to CSV format.
        
        Args:
            output_dir: Directory to save the file
            
        Returns:
            Path to the exported file
        """
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Create full filepath
        filepath = os.path.join(output_dir, f"{self.filename}.csv")
        
        # Extract the list of open ports from the results
        open_ports = self.results.get("open_ports", [])
        
        with open(filepath, 'w', newline='') as csvfile:
            fieldnames = ['target', 'port', 'status', 'service', 'timestamp']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for port_info in open_ports:
                row = {
                    'target': self.results.get("target", "unknown"),
                    'port': port_info.get("port", ""),
                    'status': port_info.get("status", ""),
                    'service': port_info.get("service", ""),
                    'timestamp': port_info.get("timestamp", "")
                }
                writer.writerow(row)
                
        return filepath
    
    def export_html(self, output_dir: str = "reports/exports") -> str:
        """
        Export results to HTML format.
        
        Args:
            output_dir: Directory to save the file
            
        Returns:
            Path to the exported file
        """
        # Create output directory if it doesn't exist
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        # Create full filepath
        filepath = os.path.join(output_dir, f"{self.filename}.html")
        
        # Extract data from results
        target = self.results.get("target", "Unknown Target")
        scan_date = self.results.get("scan_date", datetime.now().isoformat())
        open_ports = self.results.get("open_ports", [])
        scan_duration = self.results.get("scan_duration", "Unknown")
        
        try:
            # Format the scan date
            dt_obj = datetime.fromisoformat(scan_date)
            formatted_date = dt_obj.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            formatted_date = scan_date
        
        # Create HTML content
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GateKeeper Scan Report - {target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2 {{ color: #333; }}
        .info-box {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        table {{ border-collapse: collapse; width: 100%; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .open {{ background-color: #d4edda; color: #155724; }}
        .footer {{ margin-top: 30px; font-size: 0.8em; color: #777; text-align: center; }}
    </style>
</head>
<body>
    <h1>GateKeeper Scan Report</h1>
    
    <div class="info-box">
        <h2>Scan Information</h2>
        <p><strong>Target:</strong> {target}</p>
        <p><strong>Scan Date:</strong> {formatted_date}</p>
        <p><strong>Scan Duration:</strong> {scan_duration}</p>
        <p><strong>Total Open Ports:</strong> {len(open_ports)}</p>
    </div>
    
    <h2>Open Ports</h2>
    """
        
        if open_ports:
            html_content += """
    <table>
        <thead>
            <tr>
                <th>Port</th>
                <th>Status</th>
                <th>Service</th>
                <th>Timestamp</th>
            </tr>
        </thead>
        <tbody>
    """
            
            for port_info in open_ports:
                port = port_info.get("port", "")
                status = port_info.get("status", "")
                service = port_info.get("service", "")
                timestamp = port_info.get("timestamp", "")
                
                try:
                    # Format the timestamp
                    dt_obj = datetime.fromisoformat(timestamp)
                    formatted_timestamp = dt_obj.strftime("%H:%M:%S")
                except (ValueError, TypeError):
                    formatted_timestamp = timestamp
                
                html_content += f"""
            <tr class="{status.lower()}">
                <td>{port}</td>
                <td>{status}</td>
                <td>{service}</td>
                <td>{formatted_timestamp}</td>
            </tr>
            """
                
            html_content += """
        </tbody>
    </table>
    """
        else:
            html_content += """
    <p>No open ports were found during the scan.</p>
    """
            
        html_content += """
    <div class="footer">
        <p>Generated by GateKeeper Network Scanner</p>
    </div>
</body>
</html>
"""
        
        # Write the HTML file
        with open(filepath, 'w') as html_file:
            html_file.write(html_content)
            
        return filepath


def export_results(results: Dict[str, Any], filename: str, format_type: str) -> str:
    """
    Export scan results to the specified format.
    
    Args:
        results: Scan results dictionary
        filename: Base filename without extension
        format_type: Export format ('csv' or 'html')
        
    Returns:
        Path to the exported file
    """
    exporter = ResultExporter(results, filename)
    
    if format_type.lower() == 'csv':
        return exporter.export_csv()
    elif format_type.lower() == 'html':
        return exporter.export_html()
    else:
        raise ValueError(f"Unsupported export format: {format_type}") 