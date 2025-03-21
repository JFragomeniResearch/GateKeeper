#!/usr/bin/env python3
"""
GateKeeper Notification System

This module provides notification capabilities for the GateKeeper scanner,
allowing users to receive alerts about scan results via email and webhooks.
It also supports rule-based notifications.
"""

import os
import json
import smtplib
import ssl
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Any, Optional, Union, Callable
import yaml
from datetime import datetime
import re
from colorama import Fore, Style

# Constants
CONFIG_DIR = Path('notifications')
CONFIG_FILE = CONFIG_DIR / 'config.yaml'
RULES_FILE = CONFIG_DIR / 'rules.yaml'
LOG_FILE = Path('logs/notifications.log')

# Ensure config directory exists
CONFIG_DIR.mkdir(exist_ok=True)

# Setup logging
logger = logging.getLogger('GateKeeper_Notifications')
logger.setLevel(logging.INFO)

# Ensure logs directory exists
Path('logs').mkdir(exist_ok=True)

# File handler
file_handler = logging.FileHandler(LOG_FILE)
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


class NotificationRule:
    """Class representing a notification rule."""
    
    def __init__(self, rule_config: Dict[str, Any]):
        """
        Initialize a notification rule.
        
        Args:
            rule_config: Rule configuration dictionary
        """
        self.name = rule_config.get('name', 'Unnamed Rule')
        self.enabled = rule_config.get('enabled', True)
        self.condition = rule_config.get('condition', 'any_open_ports')
        self.threshold = rule_config.get('threshold', 1)
        self.message_template = rule_config.get('message', 'GateKeeper Alert: {condition} detected on {target}')
        self.severity = rule_config.get('severity', 'info').lower()  # info, warning, critical
        self.notify_channels = rule_config.get('notify', ['email'])  # email, slack, teams, etc.
        self.ports = rule_config.get('ports', [])  # Specific ports to check
        self.services = rule_config.get('services', [])  # Specific services to check
        self.include_details = rule_config.get('include_details', True)
    
    def evaluate(self, scan_results: Dict[str, Any]) -> bool:
        """
        Evaluate if the rule condition is met.
        
        Args:
            scan_results: Scan results to evaluate against
            
        Returns:
            bool: True if the condition is met, False otherwise
        """
        # Extract relevant data
        target = scan_results.get('scan_info', {}).get('target', 'Unknown')
        open_ports = scan_results.get('results', [])
        
        # Handle different conditions
        if self.condition == 'any_open_ports':
            return len(open_ports) > 0
        
        elif self.condition == 'min_open_ports':
            return len(open_ports) >= self.threshold
        
        elif self.condition == 'specific_port_open':
            return any(str(port.get('port')) in self.ports for port in open_ports)
        
        elif self.condition == 'specific_service':
            return any(port.get('service', '').lower() in [s.lower() for s in self.services] for port in open_ports)
        
        elif self.condition == 'new_ports':
            # This would require comparing with previous scans, placeholder for now
            return False
        
        return False
    
    def format_message(self, scan_results: Dict[str, Any]) -> str:
        """
        Format the notification message.
        
        Args:
            scan_results: Scan results to include in the message
            
        Returns:
            str: Formatted notification message
        """
        target = scan_results.get('scan_info', {}).get('target', 'Unknown')
        timestamp = scan_results.get('scan_info', {}).get('timestamp', datetime.now().isoformat())
        open_port_count = len(scan_results.get('results', []))
        
        # Format the basic message
        message = self.message_template.format(
            condition=self.condition.replace('_', ' ').title(),
            target=target,
            timestamp=timestamp,
            count=open_port_count,
            threshold=self.threshold
        )
        
        # Add details if requested
        if self.include_details and open_port_count > 0:
            message += "\n\nOpen Ports:"
            for port in scan_results.get('results', []):
                message += f"\n- Port {port.get('port')}: {port.get('service', 'Unknown Service')} {port.get('version', '')}"
        
        # Add severity tag
        if self.severity == 'critical':
            message = f"[CRITICAL] {message}"
        elif self.severity == 'warning':
            message = f"[WARNING] {message}"
        else:
            message = f"[INFO] {message}"
        
        return message


class NotificationManager:
    """Class for managing notifications."""
    
    def __init__(self, config_file: Path = CONFIG_FILE, rules_file: Path = RULES_FILE):
        """
        Initialize the notification manager.
        
        Args:
            config_file: Path to the configuration file
            rules_file: Path to the rules file
        """
        self.config_file = config_file
        self.rules_file = rules_file
        self.config = self._load_config()
        self.rules = self._load_rules()
        
        # Create default files if they don't exist
        if not self.config:
            self._create_default_config()
            self.config = self._load_config()
        
        if not self.rules:
            self._create_default_rules()
            self.rules = self._load_rules()
    
    def _load_config(self) -> Dict[str, Any]:
        """
        Load the notification configuration.
        
        Returns:
            Dict: Configuration dictionary
        """
        if not self.config_file.exists():
            return {}
        
        try:
            with open(self.config_file, 'r') as f:
                config = yaml.safe_load(f) or {}
            return config
        except Exception as e:
            logger.error(f"Error loading notification config: {str(e)}")
            return {}
    
    def _load_rules(self) -> List[NotificationRule]:
        """
        Load notification rules.
        
        Returns:
            List: List of NotificationRule objects
        """
        if not self.rules_file.exists():
            return []
        
        try:
            with open(self.rules_file, 'r') as f:
                rules_data = yaml.safe_load(f) or []
            
            return [NotificationRule(rule_config) for rule_config in rules_data]
        except Exception as e:
            logger.error(f"Error loading notification rules: {str(e)}")
            return []
    
    def _create_default_config(self):
        """Create a default configuration file."""
        default_config = {
            'email': {
                'enabled': False,
                'smtp_server': 'smtp.gmail.com',
                'smtp_port': 587,
                'username': 'your-email@gmail.com',
                'password': '',  # Should be set by user
                'from_address': 'your-email@gmail.com',
                'to_addresses': ['recipient@example.com'],
                'use_tls': True
            },
            'webhook': {
                'slack': {
                    'enabled': False,
                    'url': 'https://hooks.slack.com/services/your/webhook/url'
                },
                'teams': {
                    'enabled': False,
                    'url': 'https://example.webhook.office.com/webhookb2/your/webhook/url'
                },
                'custom': {
                    'enabled': False,
                    'url': 'https://your-custom-webhook-endpoint.com/hook',
                    'method': 'POST',
                    'headers': {'Content-Type': 'application/json'},
                    'auth': {'username': '', 'password': ''}
                }
            },
            'notify_on': {
                'scan_complete': True,
                'rule_triggered': True
            }
        }
        
        try:
            with open(self.config_file, 'w') as f:
                yaml.dump(default_config, f, default_flow_style=False)
            logger.info(f"Created default notification config at {self.config_file}")
        except Exception as e:
            logger.error(f"Error creating default notification config: {str(e)}")
    
    def _create_default_rules(self):
        """Create default notification rules."""
        default_rules = [
            {
                'name': 'Any Open Ports',
                'enabled': True,
                'condition': 'any_open_ports',
                'severity': 'info',
                'message': 'GateKeeper Alert: {count} open ports found on {target}',
                'notify': ['email'],
                'include_details': True
            },
            {
                'name': 'Critical Services',
                'enabled': True,
                'condition': 'specific_service',
                'severity': 'critical',
                'message': 'GateKeeper Alert: Critical services detected on {target}',
                'services': ['ssh', 'telnet', 'ftp', 'rdp'],
                'notify': ['email', 'slack'],
                'include_details': True
            },
            {
                'name': 'Many Open Ports',
                'enabled': True,
                'condition': 'min_open_ports',
                'threshold': 10,
                'severity': 'warning',
                'message': 'GateKeeper Alert: High number of open ports ({count}) on {target}',
                'notify': ['email'],
                'include_details': True
            }
        ]
        
        try:
            with open(self.rules_file, 'w') as f:
                yaml.dump(default_rules, f, default_flow_style=False)
            logger.info(f"Created default notification rules at {self.rules_file}")
        except Exception as e:
            logger.error(f"Error creating default notification rules: {str(e)}")
    
    def send_email(self, subject: str, message: str) -> bool:
        """
        Send an email notification.
        
        Args:
            subject: Email subject
            message: Email body
            
        Returns:
            bool: True if successful, False otherwise
        """
        if not self.config.get('email', {}).get('enabled', False):
            logger.warning("Email notifications are disabled")
            return False
        
        email_config = self.config.get('email', {})
        smtp_server = email_config.get('smtp_server')
        smtp_port = email_config.get('smtp_port')
        username = email_config.get('username')
        password = email_config.get('password')
        from_address = email_config.get('from_address')
        to_addresses = email_config.get('to_addresses', [])
        use_tls = email_config.get('use_tls', True)
        
        if not all([smtp_server, smtp_port, username, password, from_address, to_addresses]):
            logger.error("Email configuration is incomplete")
            return False
        
        # Create message
        msg = MIMEMultipart()
        msg['From'] = from_address
        msg['To'] = ', '.join(to_addresses)
        msg['Subject'] = subject
        
        # Add body
        msg.attach(MIMEText(message, 'plain'))
        
        try:
            # Connect to server
            server = smtplib.SMTP(smtp_server, smtp_port)
            
            if use_tls:
                server.starttls(context=ssl.create_default_context())
            
            # Login
            server.login(username, password)
            
            # Send email
            server.sendmail(from_address, to_addresses, msg.as_string())
            
            # Quit
            server.quit()
            
            logger.info(f"Email notification sent to {', '.join(to_addresses)}")
            return True
        
        except Exception as e:
            logger.error(f"Error sending email notification: {str(e)}")
            return False
    
    def send_webhook(self, webhook_type: str, message: str, data: Dict[str, Any] = None) -> bool:
        """
        Send a webhook notification.
        
        Args:
            webhook_type: Type of webhook (slack, teams, custom)
            message: Message to send
            data: Additional data to include in the webhook
            
        Returns:
            bool: True if successful, False otherwise
        """
        webhook_config = self.config.get('webhook', {}).get(webhook_type, {})
        
        if not webhook_config.get('enabled', False):
            logger.warning(f"{webhook_type.title()} webhook notifications are disabled")
            return False
        
        webhook_url = webhook_config.get('url')
        
        if not webhook_url:
            logger.error(f"{webhook_type.title()} webhook URL not configured")
            return False
        
        try:
            payload = None
            headers = webhook_config.get('headers', {'Content-Type': 'application/json'})
            
            # Format payload based on webhook type
            if webhook_type == 'slack':
                payload = {
                    'text': message,
                    'attachments': [
                        {
                            'color': '#36a64f',
                            'title': 'GateKeeper Scan Results',
                            'text': message,
                            'fields': [
                                {
                                    'title': 'Target',
                                    'value': data.get('target', 'Unknown'),
                                    'short': True
                                },
                                {
                                    'title': 'Open Ports',
                                    'value': data.get('open_port_count', 0),
                                    'short': True
                                }
                            ],
                            'footer': f"GateKeeper Scanner • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
                        }
                    ]
                }
            
            elif webhook_type == 'teams':
                payload = {
                    '@type': 'MessageCard',
                    '@context': 'http://schema.org/extensions',
                    'themeColor': '0076D7',
                    'summary': 'GateKeeper Scan Results',
                    'sections': [
                        {
                            'activityTitle': 'GateKeeper Scan Results',
                            'activitySubtitle': f"Target: {data.get('target', 'Unknown')}",
                            'activityImage': 'https://raw.githubusercontent.com/your-repo/gatekeeper/main/logo.png',
                            'facts': [
                                {
                                    'name': 'Target',
                                    'value': data.get('target', 'Unknown')
                                },
                                {
                                    'name': 'Open Ports',
                                    'value': str(data.get('open_port_count', 0))
                                },
                                {
                                    'name': 'Scan Date',
                                    'value': data.get('timestamp', datetime.now().isoformat())
                                }
                            ],
                            'text': message
                        }
                    ]
                }
            
            elif webhook_type == 'custom':
                # For custom webhook, use the data directly
                payload = data or {}
                payload['message'] = message
            
            # Send the webhook request
            method = webhook_config.get('method', 'POST').upper()
            auth = webhook_config.get('auth')
            
            if method == 'POST':
                if auth:
                    response = requests.post(webhook_url, json=payload, headers=headers, auth=(auth.get('username'), auth.get('password')))
                else:
                    response = requests.post(webhook_url, json=payload, headers=headers)
            elif method == 'GET':
                if auth:
                    response = requests.get(webhook_url, params=payload, headers=headers, auth=(auth.get('username'), auth.get('password')))
                else:
                    response = requests.get(webhook_url, params=payload, headers=headers)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return False
            
            if response.status_code >= 200 and response.status_code < 300:
                logger.info(f"{webhook_type.title()} webhook notification sent successfully")
                return True
            else:
                logger.error(f"Error sending {webhook_type} webhook: {response.status_code} {response.text}")
                return False
        
        except Exception as e:
            logger.error(f"Error sending {webhook_type} webhook notification: {str(e)}")
            return False
    
    def notify(self, subject: str, message: str, channels: List[str] = None, data: Dict[str, Any] = None) -> Dict[str, bool]:
        """
        Send notifications through multiple channels.
        
        Args:
            subject: Notification subject
            message: Notification message
            channels: List of channels to notify (email, slack, teams, etc.)
            data: Additional data to include in the notification
            
        Returns:
            Dict: Dictionary of channels and their success status
        """
        if channels is None:
            channels = ['email']
        
        results = {}
        
        for channel in channels:
            if channel == 'email':
                results['email'] = self.send_email(subject, message)
            elif channel in ['slack', 'teams', 'custom']:
                results[channel] = self.send_webhook(channel, message, data)
            else:
                logger.warning(f"Unknown notification channel: {channel}")
                results[channel] = False
        
        return results
    
    def process_scan_results(self, scan_results: Dict[str, Any], notify_on_complete: bool = None) -> Dict[str, Any]:
        """
        Process scan results and send notifications based on rules.
        
        Args:
            scan_results: Scan results to process
            notify_on_complete: Whether to send a notification on scan completion,
                               overrides the configuration setting if provided
            
        Returns:
            Dict: Dictionary with notification results
        """
        if notify_on_complete is None:
            notify_on_complete = self.config.get('notify_on', {}).get('scan_complete', True)
        
        notify_on_rule = self.config.get('notify_on', {}).get('rule_triggered', True)
        
        notification_results = {
            'scan_complete': False,
            'rules_triggered': [],
            'notification_sent': False
        }
        
        # Extract basic scan info for notifications
        target = scan_results.get('scan_info', {}).get('target', 'Unknown')
        timestamp = scan_results.get('scan_info', {}).get('timestamp', datetime.now().isoformat())
        open_port_count = len(scan_results.get('results', []))
        
        notification_data = {
            'target': target,
            'timestamp': timestamp,
            'open_port_count': open_port_count,
            'scan_results': scan_results
        }
        
        # Notify on scan complete if enabled
        if notify_on_complete:
            subject = f"GateKeeper Scan Complete: {target}"
            message = f"Scan completed for {target} at {timestamp}\n"
            message += f"Open Ports: {open_port_count}\n\n"
            
            if open_port_count > 0:
                message += "Details:\n"
                for port in scan_results.get('results', []):
                    message += f"- Port {port.get('port')}: {port.get('service', 'Unknown')} {port.get('version', '')}\n"
            
            channels = ['email']  # Default to email for scan complete
            
            # Send the notification
            notification_results['scan_complete'] = self.notify(subject, message, channels, notification_data)
            notification_results['notification_sent'] = any(notification_results['scan_complete'].values())
        
        # Process rules if enabled
        if notify_on_rule:
            for rule in self.rules:
                if not rule.enabled:
                    continue
                
                # Evaluate the rule against scan results
                if rule.evaluate(scan_results):
                    logger.info(f"Rule triggered: {rule.name}")
                    
                    # Format message based on rule template
                    message = rule.format_message(scan_results)
                    subject = f"GateKeeper Alert: {rule.name} - {target}"
                    
                    # Send notification to specified channels
                    rule_result = {
                        'rule_name': rule.name,
                        'triggered': True,
                        'severity': rule.severity,
                        'notification_results': self.notify(subject, message, rule.notify_channels, notification_data)
                    }
                    
                    notification_results['rules_triggered'].append(rule_result)
                    notification_results['notification_sent'] = notification_results['notification_sent'] or any(rule_result['notification_results'].values())
        
        return notification_results


def get_notification_manager() -> NotificationManager:
    """
    Get the notification manager instance.
    
    Returns:
        NotificationManager: The notification manager instance
    """
    return NotificationManager()


# Direct usage for testing
if __name__ == '__main__':
    # Create some test data
    test_results = {
        'scan_info': {
            'target': 'example.com',
            'timestamp': datetime.now().isoformat(),
            'ports_scanned': 1000,
            'open_ports_found': 3
        },
        'results': [
            {'port': 22, 'status': 'open', 'service': 'ssh', 'version': 'OpenSSH 8.2p1'},
            {'port': 80, 'status': 'open', 'service': 'http', 'version': 'Apache httpd 2.4.46'},
            {'port': 443, 'status': 'open', 'service': 'https', 'version': 'Apache httpd 2.4.46'}
        ]
    }
    
    # Process the test results
    notification_manager = get_notification_manager()
    results = notification_manager.process_scan_results(test_results)
    
    print(f"{Fore.GREEN}Notification processing completed:{Style.RESET_ALL}")
    print(f"  Notification sent: {results['notification_sent']}")
    print(f"  Scan complete notification: {results['scan_complete']}")
    print(f"  Rules triggered: {len(results['rules_triggered'])}")
    
    for rule_result in results['rules_triggered']:
        print(f"    - {rule_result['rule_name']} ({rule_result['severity']})") 