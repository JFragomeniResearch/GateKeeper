#!/usr/bin/env python3
"""
Test script for the GateKeeper export functionality.
"""

import unittest
import os
import json
import sys
import tempfile
import shutil
from pathlib import Path

# Add the parent directory to the system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from utils.export import export_results, ResultExporter


class TestExportFunctionality(unittest.TestCase):
    """Test case for export functionality."""
    
    def setUp(self):
        """Set up test environment."""
        # Create a temporary directory for test outputs
        self.test_dir = tempfile.mkdtemp()
        
        # Create a sample scan results dict
        self.sample_results = {
            "target": "example.com",
            "scan_date": "2023-06-01T12:00:00",
            "scan_duration": "5.25 seconds",
            "open_ports": [
                {
                    "port": 80,
                    "status": "open",
                    "service": "http",
                    "timestamp": "2023-06-01T12:00:01"
                },
                {
                    "port": 443,
                    "status": "open",
                    "service": "https",
                    "timestamp": "2023-06-01T12:00:02"
                },
                {
                    "port": 22,
                    "status": "open",
                    "service": "ssh",
                    "timestamp": "2023-06-01T12:00:03"
                }
            ]
        }
        
    def tearDown(self):
        """Clean up test environment."""
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
        
    def test_csv_export(self):
        """Test CSV export functionality."""
        # Create test output directory
        output_dir = os.path.join(self.test_dir, "csv_test")
        os.makedirs(output_dir, exist_ok=True)
        
        # Export to CSV
        exporter = ResultExporter(self.sample_results, "test_export")
        csv_path = exporter.export_csv(output_dir)
        
        # Check if the file exists
        self.assertTrue(os.path.exists(csv_path))
        
        # Check if the file has content
        with open(csv_path, 'r') as f:
            content = f.read()
            self.assertIn("target,port,status,service,timestamp", content)
            self.assertIn("example.com,80,open,http,", content)
            self.assertIn("example.com,443,open,https,", content)
            self.assertIn("example.com,22,open,ssh,", content)
    
    def test_html_export(self):
        """Test HTML export functionality."""
        # Create test output directory
        output_dir = os.path.join(self.test_dir, "html_test")
        os.makedirs(output_dir, exist_ok=True)
        
        # Export to HTML
        exporter = ResultExporter(self.sample_results, "test_export")
        html_path = exporter.export_html(output_dir)
        
        # Check if the file exists
        self.assertTrue(os.path.exists(html_path))
        
        # Check if the file has content
        with open(html_path, 'r') as f:
            content = f.read()
            self.assertIn("<title>GateKeeper Scan Report - example.com</title>", content)
            self.assertIn("<strong>Target:</strong> example.com", content)
            self.assertIn("<strong>Total Open Ports:</strong> 3", content)
            self.assertIn("<td>80</td>", content)
            self.assertIn("<td>443</td>", content)
            self.assertIn("<td>22</td>", content)
    
    def test_export_results_function(self):
        """Test the export_results function."""
        # Create test output directories
        csv_dir = os.path.join(self.test_dir, "reports/exports")
        os.makedirs(csv_dir, exist_ok=True)
        
        # Test CSV export
        csv_path = export_results(self.sample_results, "function_test", "csv")
        self.assertTrue(os.path.exists(csv_path))
        
        # Test HTML export
        html_path = export_results(self.sample_results, "function_test", "html")
        self.assertTrue(os.path.exists(html_path))
        
        # Test invalid format
        with self.assertRaises(ValueError):
            export_results(self.sample_results, "function_test", "invalid_format")


if __name__ == '__main__':
    unittest.main() 