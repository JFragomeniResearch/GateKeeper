#!/usr/bin/env python3
"""
Test script for the GateKeeper scheduled scan manager.
"""

import unittest
import os
import sys
import tempfile
import shutil
import yaml
from datetime import datetime
from pathlib import Path

# Add the parent directory to the system path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from scheduled_scan import ScheduledScanManager


class TestScheduledScanManager(unittest.TestCase):
    """Test case for the scheduled scan manager."""
    
    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for test configurations
        self.test_dir = tempfile.mkdtemp()
        self.config_dir = Path(self.test_dir) / 'schedules'
        self.config_dir.mkdir()
        self.config_file = self.config_dir / 'schedules.yaml'
        
        # Create a sample configuration
        self.sample_schedules = {
            'test_daily': {
                'interval': 'daily',
                'time': '12:00',
                'target': 'example.com',
                'policy': 'quick',
                'format': 'json',
                'created_at': datetime.now().isoformat()
            }
        }
        
        with open(self.config_file, 'w') as f:
            yaml.dump(self.sample_schedules, f)
        
        # Patch the CONFIG_FILE path in the module
        self.original_config_dir = scheduled_scan.CONFIG_DIR
        self.original_config_file = scheduled_scan.CONFIG_FILE
        scheduled_scan.CONFIG_DIR = self.config_dir
        scheduled_scan.CONFIG_FILE = self.config_file
        
        # Initialize the manager
        self.manager = ScheduledScanManager()
    
    def tearDown(self):
        """Clean up the test environment."""
        # Restore original paths
        scheduled_scan.CONFIG_DIR = self.original_config_dir
        scheduled_scan.CONFIG_FILE = self.original_config_file
        
        # Remove temporary directory
        shutil.rmtree(self.test_dir)
    
    def test_load_schedules(self):
        """Test loading schedules from file."""
        schedules = self.manager.load_schedules()
        self.assertIn('test_daily', schedules)
        self.assertEqual(schedules['test_daily']['interval'], 'daily')
        self.assertEqual(schedules['test_daily']['time'], '12:00')
    
    def test_add_schedule(self):
        """Test adding a new schedule."""
        new_schedule = {
            'interval': 'weekly',
            'time': '14:00',
            'day': 'monday',
            'target_group': 'web_servers',
            'policy': 'full',
            'format': 'html'
        }
        
        success = self.manager.add_schedule('test_weekly', new_schedule)
        self.assertTrue(success)
        self.assertIn('test_weekly', self.manager.schedules)
        self.assertEqual(self.manager.schedules['test_weekly']['interval'], 'weekly')
        
        # Try adding a duplicate
        success = self.manager.add_schedule('test_weekly', new_schedule)
        self.assertFalse(success)
    
    def test_remove_schedule(self):
        """Test removing a schedule."""
        # Remove existing schedule
        success = self.manager.remove_schedule('test_daily')
        self.assertTrue(success)
        self.assertNotIn('test_daily', self.manager.schedules)
        
        # Try removing non-existent schedule
        success = self.manager.remove_schedule('nonexistent')
        self.assertFalse(success)
    
    def test_list_schedules(self):
        """Test listing schedules."""
        schedules = self.manager.list_schedules()
        self.assertIsInstance(schedules, dict)
        self.assertIn('test_daily', schedules)
    
    def test_save_schedules(self):
        """Test saving schedules to file."""
        # Add a new schedule
        new_schedule = {
            'interval': 'monthly',
            'time': '03:00',
            'day': '1',
            'target': 'example.org',
            'policy': 'compliance',
            'format': 'all'
        }
        
        self.manager.add_schedule('test_monthly', new_schedule)
        
        # Verify it was saved to the file
        with open(self.config_file, 'r') as f:
            saved_schedules = yaml.safe_load(f)
        
        self.assertIn('test_monthly', saved_schedules)
        self.assertEqual(saved_schedules['test_monthly']['interval'], 'monthly')


if __name__ == '__main__':
    import scheduled_scan
    unittest.main() 