#!/usr/bin/env python3
"""
GateKeeper Scan Policy Manager

This tool allows you to create, manage, and apply scan policy templates
for different security scanning scenarios.
"""

import sys
import argparse
from pathlib import Path
from utils.scan_policy import get_policy_manager
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Scan Policy Manager',
        epilog='Manage scan policy templates for different security scenarios'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List policies command
    list_parser = subparsers.add_parser('list', help='List available policies')
    
    # Show policy details command
    show_parser = subparsers.add_parser('show', help='Show policy details')
    show_parser.add_argument('policy_id', help='ID of the policy to show')
    
    # Create policy command
    create_parser = subparsers.add_parser('create', help='Create a new policy')
    create_parser.add_argument('policy_id', help='ID for the new policy')
    create_parser.add_argument('--name', required=True, help='Name of the policy')
    create_parser.add_argument('--description', required=True, help='Description of the policy')
    create_parser.add_argument('--ports', required=True, help='Port range to scan (e.g., "80,443" or "1-1024")')
    create_parser.add_argument('--threads', type=int, default=100, help='Number of threads to use')
    create_parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout in seconds')
    create_parser.add_argument('--rate-limit', type=float, default=0.1, help='Rate limiting between connection attempts')
    create_parser.add_argument('--vuln-check', type=bool, default=True, help='Whether to check for vulnerabilities')
    
    # Delete policy command
    delete_parser = subparsers.add_parser('delete', help='Delete a policy')
    delete_parser.add_argument('policy_id', help='ID of the policy to delete')
    delete_parser.add_argument('--force', action='store_true', help='Force deletion without confirmation')
    
    # Clone policy command
    clone_parser = subparsers.add_parser('clone', help='Clone an existing policy')
    clone_parser.add_argument('source_id', help='ID of the policy to clone')
    clone_parser.add_argument('target_id', help='ID for the new policy')
    clone_parser.add_argument('--name', help='New name for the cloned policy')
    clone_parser.add_argument('--description', help='New description for the cloned policy')
    clone_parser.add_argument('--ports', help='New port range for the cloned policy')
    clone_parser.add_argument('--threads', type=int, help='New thread count for the cloned policy')
    clone_parser.add_argument('--timeout', type=float, help='New timeout for the cloned policy')
    clone_parser.add_argument('--rate-limit', type=float, help='New rate limit for the cloned policy')
    clone_parser.add_argument('--vuln-check', type=bool, help='New vulnerability check setting for the cloned policy')
    
    # Export policy command
    export_parser = subparsers.add_parser('export', help='Export a policy to a file')
    export_parser.add_argument('policy_id', help='ID of the policy to export')
    export_parser.add_argument('output_file', help='Path to save the exported policy')
    
    # Import policy command
    import_parser = subparsers.add_parser('import', help='Import a policy from a file')
    import_parser.add_argument('input_file', help='Path to the policy file to import')
    import_parser.add_argument('--policy-id', help='ID to use for the imported policy (default: use filename)')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    return args

def main():
    """Main function for the scan policy manager."""
    args = parse_arguments()
    
    # Initialize the policy manager
    policy_manager = get_policy_manager()
    
    # Process commands
    if args.command == 'list':
        policy_manager.print_policies()
    
    elif args.command == 'show':
        policy_manager.print_policy_details(args.policy_id)
    
    elif args.command == 'create':
        # Extract policy parameters
        params = {
            'policy_id': args.policy_id,
            'name': args.name,
            'description': args.description,
            'ports': args.ports,
            'threads': args.threads,
            'timeout': args.timeout,
            'rate_limit': args.rate_limit,
            'vuln_check': args.vuln_check
        }
        
        # Create the policy
        if policy_manager.create_policy(**params):
            print(f"{Fore.GREEN}Policy '{args.policy_id}' created successfully{Style.RESET_ALL}")
            policy_manager.print_policy_details(args.policy_id)
        else:
            print(f"{Fore.RED}Failed to create policy{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'delete':
        # Confirm deletion if not forced
        if not args.force:
            confirm = input(f"Are you sure you want to delete policy '{args.policy_id}'? (y/n): ")
            if confirm.lower() != 'y':
                print(f"{Fore.YELLOW}Deletion cancelled{Style.RESET_ALL}")
                sys.exit(0)
        
        # Delete the policy
        if policy_manager.delete_policy(args.policy_id):
            print(f"{Fore.GREEN}Policy '{args.policy_id}' deleted successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to delete policy{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'clone':
        # Extract updates for the cloned policy
        updates = {}
        if args.name:
            updates['name'] = args.name
        if args.description:
            updates['description'] = args.description
        if args.ports:
            updates['ports'] = args.ports
        if args.threads:
            updates['threads'] = args.threads
        if args.timeout:
            updates['timeout'] = args.timeout
        if args.rate_limit:
            updates['rate_limit'] = args.rate_limit
        if args.vuln_check is not None:
            updates['vuln_check'] = args.vuln_check
        
        # Clone the policy
        if policy_manager.clone_policy(args.source_id, args.target_id, **updates):
            print(f"{Fore.GREEN}Policy '{args.source_id}' cloned to '{args.target_id}' successfully{Style.RESET_ALL}")
            policy_manager.print_policy_details(args.target_id)
        else:
            print(f"{Fore.RED}Failed to clone policy{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'export':
        # Export the policy
        if policy_manager.export_policy(args.policy_id, args.output_file):
            print(f"{Fore.GREEN}Policy '{args.policy_id}' exported to '{args.output_file}' successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to export policy{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'import':
        # Import the policy
        if policy_manager.import_policy(args.input_file, args.policy_id):
            policy_id = args.policy_id or Path(args.input_file).stem
            print(f"{Fore.GREEN}Policy imported as '{policy_id}' successfully{Style.RESET_ALL}")
            policy_manager.print_policy_details(policy_id)
        else:
            print(f"{Fore.RED}Failed to import policy{Style.RESET_ALL}")
            sys.exit(1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Operation cancelled by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        sys.exit(1) 