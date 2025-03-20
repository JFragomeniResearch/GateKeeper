#!/usr/bin/env python3
"""
GateKeeper Scheduled Scan Manager

This module adds scheduled scanning capabilities to GateKeeper, allowing users to set up 
recurring scans at specified intervals. Schedules can be managed through command-line 
arguments, and the scanner can run as a daemon process in the background.

Usage examples:
    # Add a new daily scan schedule
    python scheduled_scan.py add --name daily_webservers --target-group web_servers --policy quick --time 02:00 --interval daily
    
    # List all scheduled scans
    python scheduled_scan.py list
    
    # Remove a scheduled scan
    python scheduled_scan.py remove --name daily_webservers
    
    # Run the scheduler daemon in the foreground
    python scheduled_scan.py run
    
    # Run the scheduler daemon in the background
    python scheduled_scan.py run --daemon
"""

import os
import sys
import time
import datetime
import signal
import argparse
import threading
import logging
import json
import yaml
import schedule
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
import subprocess
from colorama import init, Fore, Style
import pytz

# Initialize colorama
init(autoreset=True)

# Constants
CONFIG_DIR = Path('schedules')
CONFIG_FILE = CONFIG_DIR / 'schedules.yaml'
LOG_DIR = Path('logs')
SCHEDULE_LOG = LOG_DIR / 'scheduler.log'

class ScheduledScanManager:
    """Manages scheduled scans for GateKeeper."""
    
    def __init__(self):
        """Initialize the scheduled scan manager."""
        self.logger = self._setup_logging()
        self.ensure_directories()
        self.schedules = self.load_schedules()
        self.running = False
        self.lock = threading.Lock()
    
    def _setup_logging(self) -> logging.Logger:
        """Set up logging for the scheduler."""
        logger = logging.getLogger('GateKeeper_Scheduler')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        LOG_DIR.mkdir(exist_ok=True)
        
        # File handler
        file_handler = logging.FileHandler(SCHEDULE_LOG)
        file_handler.setLevel(logging.INFO)
        
        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        
        # Formatter
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        console_handler.setFormatter(formatter)
        
        # Add handlers
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger
    
    def ensure_directories(self):
        """Ensure that required directories exist."""
        CONFIG_DIR.mkdir(exist_ok=True)
        LOG_DIR.mkdir(exist_ok=True)
    
    def load_schedules(self) -> Dict[str, Dict[str, Any]]:
        """Load schedules from the configuration file."""
        if not CONFIG_FILE.exists():
            return {}
        
        try:
            with open(CONFIG_FILE, 'r') as file:
                schedules = yaml.safe_load(file) or {}
            return schedules
        except Exception as e:
            self.logger.error(f"Error loading schedules: {str(e)}")
            return {}
    
    def save_schedules(self):
        """Save schedules to the configuration file."""
        try:
            with open(CONFIG_FILE, 'w') as file:
                yaml.dump(self.schedules, file, default_flow_style=False)
            self.logger.info(f"Schedules saved to {CONFIG_FILE}")
        except Exception as e:
            self.logger.error(f"Error saving schedules: {str(e)}")
    
    def add_schedule(self, name: str, schedule_config: Dict[str, Any]) -> bool:
        """
        Add a new scheduled scan.
        
        Args:
            name: Name of the scheduled scan
            schedule_config: Configuration for the scheduled scan
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.lock:
            if name in self.schedules:
                self.logger.warning(f"Schedule '{name}' already exists")
                return False
            
            # Add creation timestamp
            schedule_config['created_at'] = datetime.datetime.now().isoformat()
            
            # Store the schedule
            self.schedules[name] = schedule_config
            self.save_schedules()
            
            self.logger.info(f"Added new schedule: {name}")
            return True
    
    def remove_schedule(self, name: str) -> bool:
        """
        Remove a scheduled scan.
        
        Args:
            name: Name of the scheduled scan to remove
            
        Returns:
            bool: True if successful, False otherwise
        """
        with self.lock:
            if name not in self.schedules:
                self.logger.warning(f"Schedule '{name}' does not exist")
                return False
            
            # Remove the schedule
            del self.schedules[name]
            self.save_schedules()
            
            self.logger.info(f"Removed schedule: {name}")
            return True
    
    def list_schedules(self) -> Dict[str, Dict[str, Any]]:
        """
        List all scheduled scans.
        
        Returns:
            Dict: Dictionary of scheduled scans
        """
        return self.schedules
    
    def print_schedules(self):
        """Print all scheduled scans to the console."""
        schedules = self.list_schedules()
        
        if not schedules:
            print(f"{Fore.YELLOW}No scheduled scans configured.{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.GREEN}Configured Scheduled Scans:{Style.RESET_ALL}")
        print(f"{'-' * 80}")
        print(f"{'Name':<20} {'Schedule':<15} {'Target/Group':<20} {'Policy':<15} {'Last Run':<20}")
        print(f"{'-' * 80}")
        
        for name, config in schedules.items():
            # Format schedule time
            schedule_time = config.get('time', 'Any')
            interval = config.get('interval', 'Unknown')
            schedule_str = f"{interval} @ {schedule_time}"
            
            # Determine target
            target = config.get('target', '')
            if not target:
                target = f"Group: {config.get('target_group', 'None')}"
            
            # Get last run time
            last_run = config.get('last_run', 'Never')
            
            # Print details
            print(f"{name:<20} {schedule_str:<15} {target:<20} {config.get('policy', 'Default'):<15} {last_run:<20}")
        
        print(f"{'-' * 80}")
    
    def run_scan(self, schedule_name: str):
        """
        Execute a scheduled scan.
        
        Args:
            schedule_name: Name of the scheduled scan to run
        """
        with self.lock:
            if schedule_name not in self.schedules:
                self.logger.error(f"Cannot run schedule '{schedule_name}': Schedule not found")
                return
            
            config = self.schedules[schedule_name]
            
            # Prepare command arguments
            cmd = ['python', 'gatekeeper.py', 'scan']
            
            # Add target or target group
            if 'target' in config and config['target']:
                cmd.extend(['-t', config['target']])
            elif 'target_group' in config and config['target_group']:
                cmd.extend(['-g', config['target_group']])
            else:
                self.logger.error(f"Cannot run schedule '{schedule_name}': No target or target group specified")
                return
            
            # Add policy if specified
            if 'policy' in config and config['policy']:
                cmd.extend(['--policy', config['policy']])
            
            # Add ports if specified
            if 'ports' in config and config['ports']:
                cmd.extend(['-p', config['ports']])
            
            # Add output file with timestamp
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"sched_{schedule_name}_{timestamp}"
            cmd.extend(['--output', output_file])
            
            # Add format
            cmd.extend(['--format', config.get('format', 'json')])
            
            # Log the scan start
            self.logger.info(f"Running scheduled scan '{schedule_name}': {' '.join(cmd)}")
            print(f"{Fore.CYAN}Running scheduled scan '{schedule_name}'...{Style.RESET_ALL}")
            
            try:
                # Run the scan
                proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = proc.communicate()
                
                # Update last run time
                self.schedules[schedule_name]['last_run'] = datetime.datetime.now().isoformat()
                self.save_schedules()
                
                if proc.returncode == 0:
                    self.logger.info(f"Scheduled scan '{schedule_name}' completed successfully")
                    print(f"{Fore.GREEN}Scheduled scan '{schedule_name}' completed successfully{Style.RESET_ALL}")
                else:
                    self.logger.error(f"Scheduled scan '{schedule_name}' failed: {stderr}")
                    print(f"{Fore.RED}Scheduled scan '{schedule_name}' failed: {stderr}{Style.RESET_ALL}")
            
            except Exception as e:
                self.logger.error(f"Error running scheduled scan '{schedule_name}': {str(e)}")
                print(f"{Fore.RED}Error running scheduled scan '{schedule_name}': {str(e)}{Style.RESET_ALL}")
    
    def setup_schedules(self):
        """Set up all scheduled scans using the schedule library."""
        # Clear existing jobs
        schedule.clear()
        
        for name, config in self.schedules.items():
            interval = config.get('interval', '').lower()
            scan_time = config.get('time', '00:00')
            
            job = None
            
            # Set up the schedule based on the interval
            if interval == 'hourly':
                job = schedule.every().hour
            elif interval == 'daily':
                job = schedule.every().day.at(scan_time)
            elif interval == 'weekly':
                day = config.get('day', 'monday').lower()
                if day == 'monday':
                    job = schedule.every().monday.at(scan_time)
                elif day == 'tuesday':
                    job = schedule.every().tuesday.at(scan_time)
                elif day == 'wednesday':
                    job = schedule.every().wednesday.at(scan_time)
                elif day == 'thursday':
                    job = schedule.every().thursday.at(scan_time)
                elif day == 'friday':
                    job = schedule.every().friday.at(scan_time)
                elif day == 'saturday':
                    job = schedule.every().saturday.at(scan_time)
                elif day == 'sunday':
                    job = schedule.every().sunday.at(scan_time)
            elif interval == 'monthly':
                # Monthly schedules need custom handling since 'schedule' doesn't support them directly
                # We'll check the date when running the scheduler
                pass
            elif interval.isdigit():
                # If interval is a number, interpret as minutes
                minutes = int(interval)
                job = schedule.every(minutes).minutes
            
            if job:
                # Set up the job to run the scan
                job.do(self.run_scan, name)
                self.logger.info(f"Scheduled '{name}' to run {interval}")
    
    def check_monthly_schedules(self):
        """Check and run monthly schedules if it's time."""
        today = datetime.datetime.now().day
        
        for name, config in self.schedules.items():
            interval = config.get('interval', '').lower()
            if interval == 'monthly':
                # Get the day of month to run (default to 1st)
                day_of_month = int(config.get('day', 1))
                
                # If today is the day to run the monthly schedule
                if today == day_of_month:
                    scan_time = config.get('time', '00:00')
                    current_time = datetime.datetime.now().strftime('%H:%M')
                    
                    # If it's the right time (within a minute)
                    if current_time == scan_time:
                        self.run_scan(name)
    
    def run_scheduler(self, daemon: bool = False):
        """
        Run the scheduler to execute scheduled scans.
        
        Args:
            daemon: Whether to run as a daemon process
        """
        self.running = True
        self.setup_schedules()
        
        self.logger.info("Scheduler started")
        print(f"{Fore.GREEN}Scheduler started. Press Ctrl+C to exit.{Style.RESET_ALL}")
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        
        try:
            while self.running:
                schedule.run_pending()
                self.check_monthly_schedules()
                time.sleep(60)  # Check every minute
        except KeyboardInterrupt:
            self.logger.info("Scheduler stopped by user")
            print(f"{Fore.YELLOW}Scheduler stopped by user.{Style.RESET_ALL}")
        finally:
            self.running = False
    
    def handle_signal(self, signum, frame):
        """Handle termination signals."""
        self.logger.info(f"Received signal {signum}, stopping scheduler")
        self.running = False
    
    def run_as_daemon(self):
        """Run the scheduler as a daemon process."""
        # Not implementing full daemonization here as it's complex and OS-dependent
        # Instead, we'll use threading to run in the background
        self.logger.info("Starting scheduler as daemon")
        
        # Create a daemon thread
        daemon_thread = threading.Thread(target=self.run_scheduler, daemon=True)
        daemon_thread.start()
        
        return daemon_thread


def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Scheduled Scan Manager',
        epilog='Manage scheduled scans for continuous security monitoring.'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List schedules
    list_parser = subparsers.add_parser('list', help='List all scheduled scans')
    
    # Add schedule
    add_parser = subparsers.add_parser('add', help='Add a new scheduled scan')
    add_parser.add_argument('--name', required=True, help='Name for the scheduled scan')
    
    target_group = add_parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('--target', help='Target hostname or IP address')
    target_group.add_argument('--target-group', help='Target group to scan')
    
    add_parser.add_argument('--policy', help='Scan policy to use')
    add_parser.add_argument('--ports', help='Port range to scan (e.g., "80,443" or "1-1024")')
    add_parser.add_argument('--interval', choices=['hourly', 'daily', 'weekly', 'monthly'], 
                           default='daily', help='Interval for the scan')
    add_parser.add_argument('--time', default='00:00', help='Time to run the scan (HH:MM format)')
    add_parser.add_argument('--day', help='Day to run (day of week for weekly, day of month for monthly)')
    add_parser.add_argument('--format', choices=['json', 'csv', 'html', 'all'], 
                           default='json', help='Output format for scan results')
    
    # Remove schedule
    remove_parser = subparsers.add_parser('remove', help='Remove a scheduled scan')
    remove_parser.add_argument('--name', required=True, help='Name of the scheduled scan to remove')
    
    # Run scheduler
    run_parser = subparsers.add_parser('run', help='Run the scheduler')
    run_parser.add_argument('--daemon', action='store_true', help='Run as a daemon process')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    return args


def main():
    """Main function for the scheduled scan manager."""
    args = parse_arguments()
    
    # Initialize the manager
    manager = ScheduledScanManager()
    
    # Process commands
    if args.command == 'list':
        manager.print_schedules()
    
    elif args.command == 'add':
        # Create schedule configuration
        schedule_config = {
            'interval': args.interval,
            'time': args.time,
            'format': args.format
        }
        
        # Add target info
        if args.target:
            schedule_config['target'] = args.target
        elif args.target_group:
            schedule_config['target_group'] = args.target_group
        
        # Add optional parameters
        if args.policy:
            schedule_config['policy'] = args.policy
        if args.ports:
            schedule_config['ports'] = args.ports
        if args.day:
            schedule_config['day'] = args.day
        
        # Add the schedule
        success = manager.add_schedule(args.name, schedule_config)
        
        if success:
            print(f"{Fore.GREEN}Successfully added scheduled scan '{args.name}'{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to add scheduled scan '{args.name}'{Style.RESET_ALL}")
    
    elif args.command == 'remove':
        success = manager.remove_schedule(args.name)
        
        if success:
            print(f"{Fore.GREEN}Successfully removed scheduled scan '{args.name}'{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to remove scheduled scan: '{args.name}' not found{Style.RESET_ALL}")
    
    elif args.command == 'run':
        if args.daemon:
            print(f"{Fore.CYAN}Starting scheduler in daemon mode...{Style.RESET_ALL}")
            daemon_thread = manager.run_as_daemon()
            
            # Keep the main thread alive
            try:
                while daemon_thread.is_alive():
                    time.sleep(1)
            except KeyboardInterrupt:
                print(f"{Fore.YELLOW}Stopping scheduler...{Style.RESET_ALL}")
        else:
            manager.run_scheduler()


if __name__ == '__main__':
    main() 