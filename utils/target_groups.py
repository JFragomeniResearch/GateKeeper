#!/usr/bin/env python3
"""
Target Groups Manager

This module handles the management of target groups, allowing users to organize scanning targets
into logical groups for easier management and scanning.
"""

import os
import json
import shutil
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style
import ipaddress
import socket
import re

class TargetGroups:
    """
    Manages target groups for easier management of scanning targets.
    """
    
    def __init__(self, groups_dir=None):
        """
        Initialize the target groups manager.
        
        Args:
            groups_dir (str, optional): Directory to store group files. Defaults to "target_groups".
        """
        # Set the groups directory
        if groups_dir:
            self.groups_dir = Path(groups_dir)
        else:
            self.groups_dir = Path("target_groups")
        
        # Ensure the groups directory exists
        self.groups_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize the groups dictionary
        self.groups = {}
        
        # Load groups
        self.load_groups()
    
    def load_groups(self):
        """
        Load all group files from the groups directory.
        """
        for file_path in self.groups_dir.glob("*.json"):
            try:
                group_id = file_path.stem
                with open(file_path, "r") as f:
                    group_data = json.load(f)
                    
                if self.validate_group(group_data):
                    self.groups[group_id] = group_data
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load group {file_path}: {str(e)}{Style.RESET_ALL}")
    
    def validate_group(self, group_data):
        """
        Validate that a group contains all required fields.
        
        Args:
            group_data (dict): The group data to validate.
            
        Returns:
            bool: True if the group is valid, False otherwise.
        """
        required_fields = ["name", "description", "targets"]
        for field in required_fields:
            if field not in group_data:
                print(f"{Fore.YELLOW}Warning: Group is missing required field: {field}{Style.RESET_ALL}")
                return False
        
        # Ensure targets is a list
        if not isinstance(group_data["targets"], list):
            print(f"{Fore.YELLOW}Warning: Group targets must be a list{Style.RESET_ALL}")
            return False
            
        return True
    
    def validate_target(self, target):
        """
        Validate that a target is in a proper format (hostname, IP address, or CIDR notation).
        
        Args:
            target (str): The target to validate.
            
        Returns:
            bool: True if the target is valid, False otherwise.
        """
        try:
            # Check if it's a valid IP address
            try:
                ipaddress.ip_address(target)
                return True
            except ValueError:
                pass
            
            # Check if it's a valid CIDR notation
            try:
                ipaddress.ip_network(target, strict=False)
                return True
            except ValueError:
                pass
            
            # Check if it's a valid hostname
            if self.is_valid_hostname(target):
                return True
                
            return False
        except Exception:
            return False
    
    def is_valid_hostname(self, hostname):
        """
        Check if a string is a valid hostname.
        
        Args:
            hostname (str): The hostname to validate.
            
        Returns:
            bool: True if the hostname is valid, False otherwise.
        """
        if len(hostname) > 255:
            return False
        
        # Hostname regex pattern
        pattern = r"^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])(\.[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])*$"
        
        if re.match(pattern, hostname):
            return True
        return False
    
    def get_group(self, group_id):
        """
        Get a group by ID.
        
        Args:
            group_id (str): The ID of the group to get.
            
        Returns:
            dict: The group data, or None if not found.
        """
        return self.groups.get(group_id)
    
    def save_group(self, group_id, group_data):
        """
        Save a group to a file.
        
        Args:
            group_id (str): The ID of the group to save.
            group_data (dict): The group data to save.
            
        Returns:
            bool: True if the group was saved successfully, False otherwise.
        """
        try:
            group_file = self.groups_dir / f"{group_id}.json"
            with open(group_file, "w") as f:
                json.dump(group_data, f, indent=4)
            
            # Update in-memory group
            self.groups[group_id] = group_data
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not save group {group_id}: {str(e)}{Style.RESET_ALL}")
            return False
    
    def delete_group(self, group_id):
        """
        Delete a group.
        
        Args:
            group_id (str): The ID of the group to delete.
            
        Returns:
            bool: True if the group was deleted successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        try:
            group_file = self.groups_dir / f"{group_id}.json"
            if group_file.exists():
                group_file.unlink()
            
            # Remove from in-memory groups
            del self.groups[group_id]
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not delete group {group_id}: {str(e)}{Style.RESET_ALL}")
            return False
    
    def create_group(self, group_id, name, description, targets=None):
        """
        Create a new group.
        
        Args:
            group_id (str): The ID for the new group.
            name (str): The name of the group.
            description (str): Description of the group.
            targets (list, optional): List of targets in the group. Defaults to empty list.
            
        Returns:
            bool: True if the group was created successfully, False otherwise.
        """
        if group_id in self.groups:
            print(f"{Fore.RED}Error: Group {group_id} already exists{Style.RESET_ALL}")
            return False
        
        # Validate targets if provided
        if targets:
            invalid_targets = [t for t in targets if not self.validate_target(t)]
            if invalid_targets:
                print(f"{Fore.RED}Error: Invalid targets: {', '.join(invalid_targets)}{Style.RESET_ALL}")
                return False
        
        group_data = {
            "name": name,
            "description": description,
            "targets": targets or [],
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        return self.save_group(group_id, group_data)
    
    def add_target(self, group_id, target):
        """
        Add a target to a group.
        
        Args:
            group_id (str): The ID of the group to add the target to.
            target (str): The target to add.
            
        Returns:
            bool: True if the target was added successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        # Validate the target
        if not self.validate_target(target):
            print(f"{Fore.RED}Error: Invalid target: {target}{Style.RESET_ALL}")
            return False
        
        # Check if the target is already in the group
        if target in group["targets"]:
            print(f"{Fore.YELLOW}Warning: Target {target} is already in group {group_id}{Style.RESET_ALL}")
            return True
        
        # Add the target
        group["targets"].append(target)
        group["updated_at"] = datetime.now().isoformat()
        
        return self.save_group(group_id, group)
    
    def remove_target(self, group_id, target):
        """
        Remove a target from a group.
        
        Args:
            group_id (str): The ID of the group to remove the target from.
            target (str): The target to remove.
            
        Returns:
            bool: True if the target was removed successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        # Check if the target is in the group
        if target not in group["targets"]:
            print(f"{Fore.YELLOW}Warning: Target {target} is not in group {group_id}{Style.RESET_ALL}")
            return True
        
        # Remove the target
        group["targets"].remove(target)
        group["updated_at"] = datetime.now().isoformat()
        
        return self.save_group(group_id, group)
    
    def add_targets(self, group_id, targets):
        """
        Add multiple targets to a group.
        
        Args:
            group_id (str): The ID of the group to add the targets to.
            targets (list): The targets to add.
            
        Returns:
            bool: True if all targets were added successfully, False otherwise.
        """
        success = True
        for target in targets:
            if not self.add_target(group_id, target):
                success = False
        
        return success
    
    def remove_targets(self, group_id, targets):
        """
        Remove multiple targets from a group.
        
        Args:
            group_id (str): The ID of the group to remove the targets from.
            targets (list): The targets to remove.
            
        Returns:
            bool: True if all targets were removed successfully, False otherwise.
        """
        success = True
        for target in targets:
            if not self.remove_target(group_id, target):
                success = False
        
        return success
    
    def update_group(self, group_id, name=None, description=None):
        """
        Update a group's name and/or description.
        
        Args:
            group_id (str): The ID of the group to update.
            name (str, optional): The new name of the group. Defaults to None.
            description (str, optional): The new description of the group. Defaults to None.
            
        Returns:
            bool: True if the group was updated successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        # Update the group
        if name:
            group["name"] = name
        
        if description:
            group["description"] = description
        
        group["updated_at"] = datetime.now().isoformat()
        
        return self.save_group(group_id, group)
    
    def list_groups(self):
        """
        Get a list of all groups.
        
        Returns:
            list: List of group IDs.
        """
        return list(self.groups.keys())
    
    def print_groups(self):
        """
        Print a list of all groups.
        """
        if not self.groups:
            print(f"{Fore.YELLOW}No groups found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Available Target Groups:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        for group_id, group in self.groups.items():
            print(f"{Fore.GREEN}{group_id}{Style.RESET_ALL}: {group['name']} - {group['description']} ({len(group['targets'])} targets)")
        
        print()
    
    def print_group_details(self, group_id):
        """
        Print detailed information about a group.
        
        Args:
            group_id (str): The ID of the group to print details for.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Group Details: {group_id}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Name:{Style.RESET_ALL} {group['name']}")
        print(f"{Fore.GREEN}Description:{Style.RESET_ALL} {group['description']}")
        print(f"{Fore.GREEN}Targets ({len(group['targets'])}):{Style.RESET_ALL}")
        
        if group["targets"]:
            for i, target in enumerate(group["targets"], 1):
                print(f"  {i}. {target}")
        else:
            print(f"  {Fore.YELLOW}No targets in this group{Style.RESET_ALL}")
        
        # Show creation and update timestamps
        created_at = datetime.fromisoformat(group['created_at']).strftime("%Y-%m-%d %H:%M:%S")
        updated_at = datetime.fromisoformat(group['updated_at']).strftime("%Y-%m-%d %H:%M:%S")
        print(f"\n{Fore.GREEN}Created:{Style.RESET_ALL} {created_at}")
        print(f"{Fore.GREEN}Updated:{Style.RESET_ALL} {updated_at}")
    
    def get_targets(self, group_id):
        """
        Get the targets in a group.
        
        Args:
            group_id (str): The ID of the group to get targets from.
            
        Returns:
            list: List of targets in the group, or empty list if group not found.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return []
        
        return group["targets"]
    
    def import_targets_from_file(self, group_id, file_path):
        """
        Import targets from a file.
        
        Args:
            group_id (str): The ID of the group to import targets to.
            file_path (str): Path to the file containing targets (one per line).
            
        Returns:
            bool: True if targets were imported successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        try:
            # Read targets from file
            with open(file_path, "r") as f:
                targets = [line.strip() for line in f if line.strip()]
            
            # Validate targets
            invalid_targets = [t for t in targets if not self.validate_target(t)]
            if invalid_targets:
                print(f"{Fore.RED}Error: Invalid targets in file: {', '.join(invalid_targets)}{Style.RESET_ALL}")
                return False
            
            # Add targets
            return self.add_targets(group_id, targets)
        except Exception as e:
            print(f"{Fore.RED}Error: Could not import targets from {file_path}: {str(e)}{Style.RESET_ALL}")
            return False
    
    def export_targets_to_file(self, group_id, file_path):
        """
        Export targets to a file.
        
        Args:
            group_id (str): The ID of the group to export targets from.
            file_path (str): Path to save the targets to.
            
        Returns:
            bool: True if targets were exported successfully, False otherwise.
        """
        group = self.get_group(group_id)
        if not group:
            print(f"{Fore.RED}Error: Group {group_id} not found{Style.RESET_ALL}")
            return False
        
        try:
            # Write targets to file
            with open(file_path, "w") as f:
                for target in group["targets"]:
                    f.write(f"{target}\n")
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not export targets to {file_path}: {str(e)}{Style.RESET_ALL}")
            return False


# Global instance of the target groups manager
_target_groups = None

def get_target_groups(groups_dir=None):
    """
    Get the global target groups manager instance.
    
    Args:
        groups_dir (str, optional): Directory to store group files. Defaults to None.
        
    Returns:
        TargetGroups: The target groups manager instance.
    """
    global _target_groups
    if _target_groups is None:
        _target_groups = TargetGroups(groups_dir)
    return _target_groups 