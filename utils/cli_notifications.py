#!/usr/bin/env python3
"""
GateKeeper Notifications CLI

This module provides a command-line interface for managing the GateKeeper notification system.
It allows users to configure email and webhook notifications, manage notification rules,
and test the notification system.
"""

import argparse
import sys
import json
import yaml
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
import os

# Import the notification system
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils.notifications import NotificationManager, get_notification_manager
from colorama import Fore, Style


def setup_parser() -> argparse.ArgumentParser:
    """Set up the argument parser for the notifications CLI."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Notification System CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Configure email notification
    email_parser = subparsers.add_parser('config-email', help='Configure email notifications')
    email_parser.add_argument('--enable', action='store_true', help='Enable email notifications')
    email_parser.add_argument('--disable', action='store_true', help='Disable email notifications')
    email_parser.add_argument('--smtp-server', help='SMTP server address')
    email_parser.add_argument('--smtp-port', type=int, help='SMTP server port')
    email_parser.add_argument('--username', help='SMTP username')
    email_parser.add_argument('--password', help='SMTP password')
    email_parser.add_argument('--from', dest='from_address', help='From email address')
    email_parser.add_argument('--to', dest='to_addresses', nargs='+', help='To email addresses')
    email_parser.add_argument('--use-tls', action='store_true', help='Use TLS for SMTP connection')
    email_parser.add_argument('--no-tls', action='store_true', help='Do not use TLS for SMTP connection')
    
    # Configure webhook notification
    webhook_parser = subparsers.add_parser('config-webhook', help='Configure webhook notifications')
    webhook_parser.add_argument('--type', choices=['slack', 'teams', 'custom'], required=True, help='Webhook type')
    webhook_parser.add_argument('--enable', action='store_true', help='Enable webhook')
    webhook_parser.add_argument('--disable', action='store_true', help='Disable webhook')
    webhook_parser.add_argument('--url', help='Webhook URL')
    webhook_parser.add_argument('--method', choices=['GET', 'POST'], help='HTTP method for custom webhook')
    webhook_parser.add_argument('--headers', help='HTTP headers as JSON string for custom webhook')
    webhook_parser.add_argument('--auth-username', help='Auth username for custom webhook')
    webhook_parser.add_argument('--auth-password', help='Auth password for custom webhook')
    
    # Create a notification rule
    rule_parser = subparsers.add_parser('rule-add', help='Add a notification rule')
    rule_parser.add_argument('--name', required=True, help='Rule name')
    rule_parser.add_argument('--condition', choices=[
        'any_open_ports', 'min_open_ports', 'specific_port_open', 'specific_service', 'new_ports'
    ], required=True, help='Rule condition')
    rule_parser.add_argument('--threshold', type=int, help='Threshold value for min_open_ports condition')
    rule_parser.add_argument('--message', help='Custom notification message template')
    rule_parser.add_argument('--severity', choices=['info', 'warning', 'critical'], default='info', help='Rule severity')
    rule_parser.add_argument('--notify', nargs='+', choices=['email', 'slack', 'teams', 'custom'], default=['email'], help='Notification channels')
    rule_parser.add_argument('--ports', nargs='+', help='Specific ports for specific_port_open condition')
    rule_parser.add_argument('--services', nargs='+', help='Specific services for specific_service condition')
    rule_parser.add_argument('--include-details', action='store_true', help='Include scan details in notification')
    rule_parser.add_argument('--no-details', action='store_true', help='Do not include scan details in notification')
    
    # List rules
    subparsers.add_parser('rule-list', help='List all notification rules')
    
    # Delete rule
    rule_delete_parser = subparsers.add_parser('rule-delete', help='Delete a notification rule')
    rule_delete_parser.add_argument('--name', required=True, help='Rule name to delete')
    
    # Enable/disable rule
    rule_toggle_parser = subparsers.add_parser('rule-toggle', help='Enable or disable a notification rule')
    rule_toggle_parser.add_argument('--name', required=True, help='Rule name')
    rule_toggle_parser.add_argument('--enable', action='store_true', help='Enable the rule')
    rule_toggle_parser.add_argument('--disable', action='store_true', help='Disable the rule')
    
    # Test notification
    test_parser = subparsers.add_parser('test', help='Test notification system')
    test_parser.add_argument('--channel', choices=['email', 'slack', 'teams', 'custom'], default='email', help='Channel to test')
    
    # Show configuration
    subparsers.add_parser('show-config', help='Show current notification configuration')
    
    return parser


def config_email(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Configure email notifications."""
    config = notification_manager.config
    email_config = config.get('email', {})
    
    # Enable or disable email
    if args.enable:
        email_config['enabled'] = True
        print(f"{Fore.GREEN}Email notifications enabled{Style.RESET_ALL}")
    elif args.disable:
        email_config['enabled'] = False
        print(f"{Fore.YELLOW}Email notifications disabled{Style.RESET_ALL}")
    
    # Update SMTP settings
    if args.smtp_server:
        email_config['smtp_server'] = args.smtp_server
        print(f"SMTP server set to: {args.smtp_server}")
    
    if args.smtp_port:
        email_config['smtp_port'] = args.smtp_port
        print(f"SMTP port set to: {args.smtp_port}")
    
    if args.username:
        email_config['username'] = args.username
        print(f"SMTP username set to: {args.username}")
    
    if args.password:
        email_config['password'] = args.password
        print(f"SMTP password updated")
    
    if args.from_address:
        email_config['from_address'] = args.from_address
        print(f"From address set to: {args.from_address}")
    
    if args.to_addresses:
        email_config['to_addresses'] = args.to_addresses
        print(f"To addresses set to: {', '.join(args.to_addresses)}")
    
    if args.use_tls:
        email_config['use_tls'] = True
        print(f"TLS enabled for SMTP connection")
    elif args.no_tls:
        email_config['use_tls'] = False
        print(f"TLS disabled for SMTP connection")
    
    # Update configuration
    config['email'] = email_config
    
    # Save configuration
    try:
        with open(notification_manager.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        print(f"{Fore.GREEN}Email configuration saved successfully{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving email configuration: {str(e)}{Style.RESET_ALL}")


def config_webhook(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Configure webhook notifications."""
    config = notification_manager.config
    webhook_config = config.get('webhook', {}).get(args.type, {})
    
    # Enable or disable webhook
    if args.enable:
        webhook_config['enabled'] = True
        print(f"{Fore.GREEN}{args.type.title()} webhook enabled{Style.RESET_ALL}")
    elif args.disable:
        webhook_config['enabled'] = False
        print(f"{Fore.YELLOW}{args.type.title()} webhook disabled{Style.RESET_ALL}")
    
    # Update webhook URL
    if args.url:
        webhook_config['url'] = args.url
        print(f"{args.type.title()} webhook URL set to: {args.url}")
    
    # Update custom webhook settings
    if args.type == 'custom':
        if args.method:
            webhook_config['method'] = args.method
            print(f"Custom webhook method set to: {args.method}")
        
        if args.headers:
            try:
                headers = json.loads(args.headers)
                webhook_config['headers'] = headers
                print(f"Custom webhook headers updated")
            except json.JSONDecodeError:
                print(f"{Fore.RED}Error: Headers must be a valid JSON string{Style.RESET_ALL}")
                return
        
        # Update auth settings
        auth = webhook_config.get('auth', {})
        if args.auth_username:
            auth['username'] = args.auth_username
            print(f"Custom webhook auth username set")
        
        if args.auth_password:
            auth['password'] = args.auth_password
            print(f"Custom webhook auth password set")
        
        if args.auth_username or args.auth_password:
            webhook_config['auth'] = auth
    
    # Update configuration
    webhook_configs = config.get('webhook', {})
    webhook_configs[args.type] = webhook_config
    config['webhook'] = webhook_configs
    
    # Save configuration
    try:
        with open(notification_manager.config_file, 'w') as f:
            yaml.dump(config, f, default_flow_style=False)
        print(f"{Fore.GREEN}{args.type.title()} webhook configuration saved successfully{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error saving webhook configuration: {str(e)}{Style.RESET_ALL}")


def rule_add(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Add a notification rule."""
    # Check for existing rule with the same name
    existing_rules = [rule for rule in notification_manager.rules if rule.name == args.name]
    if existing_rules:
        print(f"{Fore.RED}Error: A rule with the name '{args.name}' already exists{Style.RESET_ALL}")
        return
    
    # Create rule config
    rule_config = {
        'name': args.name,
        'enabled': True,
        'condition': args.condition,
        'severity': args.severity,
        'notify': args.notify
    }
    
    # Add condition-specific parameters
    if args.condition == 'min_open_ports' and args.threshold:
        rule_config['threshold'] = args.threshold
    
    if args.condition == 'specific_port_open' and args.ports:
        rule_config['ports'] = args.ports
    
    if args.condition == 'specific_service' and args.services:
        rule_config['services'] = args.services
    
    # Add message template if provided
    if args.message:
        rule_config['message'] = args.message
    
    # Set include_details flag
    if args.include_details:
        rule_config['include_details'] = True
    elif args.no_details:
        rule_config['include_details'] = False
    
    # Load existing rules
    rules = []
    try:
        with open(notification_manager.rules_file, 'r') as f:
            rules = yaml.safe_load(f) or []
    except Exception:
        # File might not exist yet
        pass
    
    # Add new rule
    rules.append(rule_config)
    
    # Save rules
    try:
        with open(notification_manager.rules_file, 'w') as f:
            yaml.dump(rules, f, default_flow_style=False)
        print(f"{Fore.GREEN}Rule '{args.name}' added successfully{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error adding rule: {str(e)}{Style.RESET_ALL}")


def rule_list(notification_manager: NotificationManager) -> None:
    """List all notification rules."""
    if not notification_manager.rules:
        print(f"{Fore.YELLOW}No notification rules defined{Style.RESET_ALL}")
        return
    
    print(f"\n{Fore.CYAN}Notification Rules:{Style.RESET_ALL}")
    print(f"{'-' * 80}")
    
    for i, rule in enumerate(notification_manager.rules, 1):
        status = f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if rule.enabled else f"{Fore.RED}Disabled{Style.RESET_ALL}"
        
        # Set severity color
        severity_color = Fore.WHITE
        if rule.severity == 'critical':
            severity_color = Fore.RED
        elif rule.severity == 'warning':
            severity_color = Fore.YELLOW
        elif rule.severity == 'info':
            severity_color = Fore.CYAN
        
        print(f"{i}. {Fore.WHITE}{rule.name}{Style.RESET_ALL} ({status}) - {severity_color}{rule.severity.upper()}{Style.RESET_ALL}")
        print(f"   Condition: {rule.condition}")
        
        if rule.condition == 'min_open_ports':
            print(f"   Threshold: {rule.threshold}")
        elif rule.condition == 'specific_port_open' and rule.ports:
            print(f"   Ports: {', '.join(rule.ports)}")
        elif rule.condition == 'specific_service' and rule.services:
            print(f"   Services: {', '.join(rule.services)}")
        
        print(f"   Notify via: {', '.join(rule.notify_channels)}")
        print(f"   Message template: {rule.message_template}")
        print(f"   Include details: {rule.include_details}")
        print(f"{'-' * 80}")


def rule_delete(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Delete a notification rule."""
    # Load existing rules
    rules = []
    try:
        with open(notification_manager.rules_file, 'r') as f:
            rules = yaml.safe_load(f) or []
    except Exception as e:
        print(f"{Fore.RED}Error loading rules: {str(e)}{Style.RESET_ALL}")
        return
    
    # Find rule to delete
    rule_index = None
    for i, rule in enumerate(rules):
        if rule.get('name') == args.name:
            rule_index = i
            break
    
    if rule_index is None:
        print(f"{Fore.RED}Error: Rule '{args.name}' not found{Style.RESET_ALL}")
        return
    
    # Delete rule
    del rules[rule_index]
    
    # Save rules
    try:
        with open(notification_manager.rules_file, 'w') as f:
            yaml.dump(rules, f, default_flow_style=False)
        print(f"{Fore.GREEN}Rule '{args.name}' deleted successfully{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error deleting rule: {str(e)}{Style.RESET_ALL}")


def rule_toggle(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Enable or disable a notification rule."""
    if not args.enable and not args.disable:
        print(f"{Fore.RED}Error: Must specify --enable or --disable{Style.RESET_ALL}")
        return
    
    # Load existing rules
    rules = []
    try:
        with open(notification_manager.rules_file, 'r') as f:
            rules = yaml.safe_load(f) or []
    except Exception as e:
        print(f"{Fore.RED}Error loading rules: {str(e)}{Style.RESET_ALL}")
        return
    
    # Find rule to toggle
    rule_found = False
    for rule in rules:
        if rule.get('name') == args.name:
            if args.enable:
                rule['enabled'] = True
                print(f"{Fore.GREEN}Rule '{args.name}' enabled{Style.RESET_ALL}")
            elif args.disable:
                rule['enabled'] = False
                print(f"{Fore.YELLOW}Rule '{args.name}' disabled{Style.RESET_ALL}")
            rule_found = True
            break
    
    if not rule_found:
        print(f"{Fore.RED}Error: Rule '{args.name}' not found{Style.RESET_ALL}")
        return
    
    # Save rules
    try:
        with open(notification_manager.rules_file, 'w') as f:
            yaml.dump(rules, f, default_flow_style=False)
        print(f"{Fore.GREEN}Rule status updated successfully{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}Error updating rule status: {str(e)}{Style.RESET_ALL}")


def test_notification(args: argparse.Namespace, notification_manager: NotificationManager) -> None:
    """Test the notification system."""
    channel = args.channel
    
    # Create test data
    test_data = {
        'scan_info': {
            'target': 'test.example.com',
            'timestamp': datetime.now().isoformat(),
            'ports_scanned': 100,
            'open_ports_found': 2
        },
        'results': [
            {'port': 80, 'status': 'open', 'service': 'http', 'version': 'Apache httpd 2.4.46'},
            {'port': 443, 'status': 'open', 'service': 'https', 'version': 'Apache httpd 2.4.46'}
        ]
    }
    
    if channel == 'email':
        # Check if email is configured
        email_config = notification_manager.config.get('email', {})
        if not email_config.get('enabled', False):
            print(f"{Fore.RED}Error: Email notifications are disabled{Style.RESET_ALL}")
            return
        
        if not all([
            email_config.get('smtp_server'),
            email_config.get('smtp_port'),
            email_config.get('username'),
            email_config.get('password'),
            email_config.get('from_address'),
            email_config.get('to_addresses')
        ]):
            print(f"{Fore.RED}Error: Email configuration is incomplete{Style.RESET_ALL}")
            return
        
        # Send test email
        subject = "GateKeeper Test Notification"
        message = "This is a test notification from GateKeeper.\n\n"
        message += "If you are receiving this, your email notifications are configured correctly."
        
        print(f"Sending test email...")
        result = notification_manager.send_email(subject, message)
        
        if result:
            print(f"{Fore.GREEN}Test email sent successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to send test email{Style.RESET_ALL}")
    
    elif channel in ['slack', 'teams', 'custom']:
        # Check if webhook is configured
        webhook_config = notification_manager.config.get('webhook', {}).get(channel, {})
        if not webhook_config.get('enabled', False):
            print(f"{Fore.RED}Error: {channel.title()} webhook is disabled{Style.RESET_ALL}")
            return
        
        if not webhook_config.get('url'):
            print(f"{Fore.RED}Error: {channel.title()} webhook URL is not configured{Style.RESET_ALL}")
            return
        
        # Send test webhook
        message = "This is a test notification from GateKeeper."
        
        print(f"Sending test {channel} webhook...")
        result = notification_manager.send_webhook(channel, message, test_data)
        
        if result:
            print(f"{Fore.GREEN}Test {channel} webhook sent successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to send test {channel} webhook{Style.RESET_ALL}")


def show_config(notification_manager: NotificationManager) -> None:
    """Show the current notification configuration."""
    config = notification_manager.config
    
    print(f"\n{Fore.CYAN}Notification Configuration:{Style.RESET_ALL}")
    print(f"{'-' * 80}")
    
    # Email configuration
    email_config = config.get('email', {})
    email_enabled = email_config.get('enabled', False)
    status = f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if email_enabled else f"{Fore.RED}Disabled{Style.RESET_ALL}"
    
    print(f"{Fore.WHITE}Email Notifications:{Style.RESET_ALL} {status}")
    
    if email_enabled:
        print(f"  SMTP Server: {email_config.get('smtp_server', 'Not configured')}")
        print(f"  SMTP Port: {email_config.get('smtp_port', 'Not configured')}")
        print(f"  Username: {email_config.get('username', 'Not configured')}")
        print(f"  From Address: {email_config.get('from_address', 'Not configured')}")
        print(f"  To Addresses: {', '.join(email_config.get('to_addresses', ['Not configured']))}")
        print(f"  Use TLS: {email_config.get('use_tls', True)}")
    
    print(f"{'-' * 80}")
    
    # Webhook configurations
    webhook_configs = config.get('webhook', {})
    
    for webhook_type in ['slack', 'teams', 'custom']:
        webhook_config = webhook_configs.get(webhook_type, {})
        webhook_enabled = webhook_config.get('enabled', False)
        status = f"{Fore.GREEN}Enabled{Style.RESET_ALL}" if webhook_enabled else f"{Fore.RED}Disabled{Style.RESET_ALL}"
        
        print(f"{Fore.WHITE}{webhook_type.title()} Webhook:{Style.RESET_ALL} {status}")
        
        if webhook_enabled:
            print(f"  URL: {webhook_config.get('url', 'Not configured')}")
            
            if webhook_type == 'custom':
                print(f"  Method: {webhook_config.get('method', 'POST')}")
                print(f"  Headers: {webhook_config.get('headers', {})}")
                
                auth = webhook_config.get('auth', {})
                if auth:
                    print(f"  Auth: {'Configured' if auth.get('username') else 'Not configured'}")
        
        print(f"{'-' * 80}")
    
    # Notification triggers
    notify_on = config.get('notify_on', {})
    print(f"{Fore.WHITE}Notification Triggers:{Style.RESET_ALL}")
    print(f"  On Scan Complete: {notify_on.get('scan_complete', True)}")
    print(f"  On Rule Triggered: {notify_on.get('rule_triggered', True)}")
    print(f"{'-' * 80}")


def main():
    """Main function for the notifications CLI."""
    parser = setup_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Get notification manager
    notification_manager = get_notification_manager()
    
    # Execute command
    if args.command == 'config-email':
        config_email(args, notification_manager)
    elif args.command == 'config-webhook':
        config_webhook(args, notification_manager)
    elif args.command == 'rule-add':
        rule_add(args, notification_manager)
    elif args.command == 'rule-list':
        rule_list(notification_manager)
    elif args.command == 'rule-delete':
        rule_delete(args, notification_manager)
    elif args.command == 'rule-toggle':
        rule_toggle(args, notification_manager)
    elif args.command == 'test':
        test_notification(args, notification_manager)
    elif args.command == 'show-config':
        show_config(notification_manager)


if __name__ == '__main__':
    main() 