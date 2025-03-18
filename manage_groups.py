#!/usr/bin/env python3
"""
GateKeeper Target Groups Manager

This tool allows you to create, manage, and use target groups for network scanning.
Target groups help organize targets for more efficient scanning operations.
"""

import sys
import argparse
from pathlib import Path
from utils.target_groups import get_target_groups
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

def parse_arguments():
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description='GateKeeper Target Groups Manager',
        epilog='Manage groups of targets for network scanning'
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # List groups command
    list_parser = subparsers.add_parser('list', help='List available target groups')
    
    # Show group details command
    show_parser = subparsers.add_parser('show', help='Show group details')
    show_parser.add_argument('group_id', help='ID of the group to show')
    
    # Create group command
    create_parser = subparsers.add_parser('create', help='Create a new target group')
    create_parser.add_argument('group_id', help='ID for the new group')
    create_parser.add_argument('--name', required=True, help='Name of the group')
    create_parser.add_argument('--description', required=True, help='Description of the group')
    create_parser.add_argument('--targets', help='Comma-separated list of targets (optional)')
    
    # Delete group command
    delete_parser = subparsers.add_parser('delete', help='Delete a target group')
    delete_parser.add_argument('group_id', help='ID of the group to delete')
    delete_parser.add_argument('--force', action='store_true', help='Force deletion without confirmation')
    
    # Update group command
    update_parser = subparsers.add_parser('update', help='Update a target group\'s name or description')
    update_parser.add_argument('group_id', help='ID of the group to update')
    update_parser.add_argument('--name', help='New name for the group')
    update_parser.add_argument('--description', help='New description for the group')
    
    # Add target command
    add_parser = subparsers.add_parser('add', help='Add targets to a group')
    add_parser.add_argument('group_id', help='ID of the group to add targets to')
    add_parser.add_argument('--targets', help='Comma-separated list of targets to add')
    add_parser.add_argument('--file', help='File containing targets, one per line')
    
    # Remove target command
    remove_parser = subparsers.add_parser('remove', help='Remove targets from a group')
    remove_parser.add_argument('group_id', help='ID of the group to remove targets from')
    remove_parser.add_argument('--targets', help='Comma-separated list of targets to remove')
    remove_parser.add_argument('--all', action='store_true', help='Remove all targets from the group')
    
    # Export targets command
    export_parser = subparsers.add_parser('export', help='Export group targets to a file')
    export_parser.add_argument('group_id', help='ID of the group to export targets from')
    export_parser.add_argument('file_path', help='Path to save the targets to')
    
    # Import targets command
    import_parser = subparsers.add_parser('import', help='Import targets from a file into a group')
    import_parser.add_argument('group_id', help='ID of the group to import targets to')
    import_parser.add_argument('file_path', help='Path to the file containing targets')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    return args

def main():
    """Main function for the target groups manager."""
    args = parse_arguments()
    
    # Initialize the target groups manager
    groups_manager = get_target_groups()
    
    # Process commands
    if args.command == 'list':
        groups_manager.print_groups()
    
    elif args.command == 'show':
        groups_manager.print_group_details(args.group_id)
    
    elif args.command == 'create':
        # Parse targets if provided
        targets = None
        if args.targets:
            targets = [t.strip() for t in args.targets.split(',') if t.strip()]
        
        # Create the group
        if groups_manager.create_group(args.group_id, args.name, args.description, targets):
            print(f"{Fore.GREEN}Group '{args.group_id}' created successfully{Style.RESET_ALL}")
            groups_manager.print_group_details(args.group_id)
        else:
            print(f"{Fore.RED}Failed to create group{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'delete':
        # Confirm deletion if not forced
        if not args.force:
            confirm = input(f"Are you sure you want to delete group '{args.group_id}'? (y/n): ")
            if confirm.lower() != 'y':
                print(f"{Fore.YELLOW}Deletion cancelled{Style.RESET_ALL}")
                sys.exit(0)
        
        # Delete the group
        if groups_manager.delete_group(args.group_id):
            print(f"{Fore.GREEN}Group '{args.group_id}' deleted successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to delete group{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'update':
        # Update the group
        if groups_manager.update_group(args.group_id, args.name, args.description):
            print(f"{Fore.GREEN}Group '{args.group_id}' updated successfully{Style.RESET_ALL}")
            groups_manager.print_group_details(args.group_id)
        else:
            print(f"{Fore.RED}Failed to update group{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'add':
        # Check if we have targets to add
        if not args.targets and not args.file:
            print(f"{Fore.RED}Error: Must specify targets to add using --targets or --file{Style.RESET_ALL}")
            sys.exit(1)
        
        # Add targets from command line
        if args.targets:
            targets = [t.strip() for t in args.targets.split(',') if t.strip()]
            if groups_manager.add_targets(args.group_id, targets):
                print(f"{Fore.GREEN}Targets added to group '{args.group_id}' successfully{Style.RESET_ALL}")
                groups_manager.print_group_details(args.group_id)
            else:
                print(f"{Fore.RED}Failed to add targets to group{Style.RESET_ALL}")
                sys.exit(1)
        
        # Add targets from file
        if args.file:
            if groups_manager.import_targets_from_file(args.group_id, args.file):
                print(f"{Fore.GREEN}Targets imported to group '{args.group_id}' successfully{Style.RESET_ALL}")
                groups_manager.print_group_details(args.group_id)
            else:
                print(f"{Fore.RED}Failed to import targets to group{Style.RESET_ALL}")
                sys.exit(1)
    
    elif args.command == 'remove':
        # Check if we have targets to remove
        if not args.targets and not args.all:
            print(f"{Fore.RED}Error: Must specify targets to remove using --targets or --all{Style.RESET_ALL}")
            sys.exit(1)
        
        # Remove targets from command line
        if args.targets:
            targets = [t.strip() for t in args.targets.split(',') if t.strip()]
            if groups_manager.remove_targets(args.group_id, targets):
                print(f"{Fore.GREEN}Targets removed from group '{args.group_id}' successfully{Style.RESET_ALL}")
                groups_manager.print_group_details(args.group_id)
            else:
                print(f"{Fore.RED}Failed to remove targets from group{Style.RESET_ALL}")
                sys.exit(1)
        
        # Remove all targets
        if args.all:
            group = groups_manager.get_group(args.group_id)
            if not group:
                print(f"{Fore.RED}Error: Group {args.group_id} not found{Style.RESET_ALL}")
                sys.exit(1)
            
            # Confirm removal if not forced
            confirm = input(f"Are you sure you want to remove ALL targets from group '{args.group_id}'? (y/n): ")
            if confirm.lower() != 'y':
                print(f"{Fore.YELLOW}Removal cancelled{Style.RESET_ALL}")
                sys.exit(0)
            
            # Remove all targets
            targets = group["targets"].copy()
            if groups_manager.remove_targets(args.group_id, targets):
                print(f"{Fore.GREEN}All targets removed from group '{args.group_id}' successfully{Style.RESET_ALL}")
                groups_manager.print_group_details(args.group_id)
            else:
                print(f"{Fore.RED}Failed to remove all targets from group{Style.RESET_ALL}")
                sys.exit(1)
    
    elif args.command == 'export':
        # Export targets to file
        if groups_manager.export_targets_to_file(args.group_id, args.file_path):
            print(f"{Fore.GREEN}Targets from group '{args.group_id}' exported to '{args.file_path}' successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}Failed to export targets{Style.RESET_ALL}")
            sys.exit(1)
    
    elif args.command == 'import':
        # Import targets from file
        if groups_manager.import_targets_from_file(args.group_id, args.file_path):
            print(f"{Fore.GREEN}Targets imported to group '{args.group_id}' successfully{Style.RESET_ALL}")
            groups_manager.print_group_details(args.group_id)
        else:
            print(f"{Fore.RED}Failed to import targets{Style.RESET_ALL}")
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