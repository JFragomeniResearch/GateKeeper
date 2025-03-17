#!/usr/bin/env python3
"""
Scan Policy Manager

This module handles the management of scan policy templates, allowing users to define,
save, and reuse scanning configurations for different security scenarios.
"""

import os
import json
import yaml
import shutil
from pathlib import Path
from datetime import datetime
from colorama import Fore, Style

class ScanPolicy:
    """
    Manages scan policy templates for different security scanning scenarios.
    """

    # Default built-in policies
    DEFAULT_POLICY_TYPES = {
        "quick": {
            "name": "Quick Scan",
            "description": "Fast scan of common ports",
            "ports": "21-23,25,53,80,443,3306,3389,8080",
            "threads": 150,
            "timeout": 0.5,
            "rate_limit": 0.05,
            "vuln_check": False,
        },
        "default": {
            "name": "Default Scan",
            "description": "Balanced scan for general security assessments",
            "ports": "1-1024",
            "threads": 100,
            "timeout": 1.0,
            "rate_limit": 0.1,
            "vuln_check": True,
        },
        "full": {
            "name": "Full Scan",
            "description": "Comprehensive scan of all ports",
            "ports": "1-65535",
            "threads": 75,
            "timeout": 2.0,
            "rate_limit": 0.2,
            "vuln_check": True,
        },
        "stealth": {
            "name": "Stealth Scan",
            "description": "Low-profile scan to avoid detection",
            "ports": "21-23,25,53,80,443,3306,3389,8080-8090",
            "threads": 25,
            "timeout": 3.0,
            "rate_limit": 0.5,
            "vuln_check": False,
        },
        "service": {
            "name": "Service Detection",
            "description": "Focused on service and version detection",
            "ports": "21-23,25,53,80,110,143,443,465,587,993,995,1433,3306,3389,5432,8080,8443",
            "threads": 50,
            "timeout": 2.0,
            "rate_limit": 0.2,
            "vuln_check": True,
        }
    }

    def __init__(self, policy_dir=None):
        """
        Initialize the scan policy manager.
        
        Args:
            policy_dir (str, optional): Directory to store policy files. Defaults to 'policies' in current dir.
        """
        # Set the policy directory
        if policy_dir:
            self.policy_dir = Path(policy_dir)
        else:
            self.policy_dir = Path("policies")
        
        # Ensure the policy directory exists
        self.policy_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize the policies dictionary
        self.policies = {}
        
        # Load built-in policies
        for policy_id, policy_data in self.DEFAULT_POLICY_TYPES.items():
            self.policies[policy_id] = {
                "policy_id": policy_id,
                "built_in": True,
                "created_at": datetime.now().isoformat(),
                "updated_at": datetime.now().isoformat(),
                **policy_data
            }
        
        # Load user-defined policies
        self.load_policies()

    def load_policies(self):
        """
        Load all policy files from the policy directory.
        """
        for file_path in self.policy_dir.glob("*.json"):
            try:
                policy_id = file_path.stem
                with open(file_path, "r") as f:
                    policy_data = json.load(f)
                    
                if self.validate_policy(policy_data):
                    self.policies[policy_id] = policy_data
            except Exception as e:
                print(f"{Fore.YELLOW}Warning: Could not load policy {file_path}: {str(e)}{Style.RESET_ALL}")

    def validate_policy(self, policy_data):
        """
        Validate that a policy contains all required fields.
        
        Args:
            policy_data (dict): The policy data to validate.
            
        Returns:
            bool: True if the policy is valid, False otherwise.
        """
        required_fields = ["name", "description", "ports", "threads", "timeout", "rate_limit", "vuln_check"]
        for field in required_fields:
            if field not in policy_data:
                print(f"{Fore.YELLOW}Warning: Policy is missing required field: {field}{Style.RESET_ALL}")
                return False
        return True

    def get_policy(self, policy_id):
        """
        Get a policy by ID.
        
        Args:
            policy_id (str): The ID of the policy to get.
            
        Returns:
            dict: The policy data, or None if not found.
        """
        return self.policies.get(policy_id)

    def save_policy(self, policy_id, policy_data):
        """
        Save a policy to a file.
        
        Args:
            policy_id (str): The ID of the policy to save.
            policy_data (dict): The policy data to save.
            
        Returns:
            bool: True if the policy was saved successfully, False otherwise.
        """
        if policy_data.get("built_in", False):
            print(f"{Fore.RED}Error: Cannot save built-in policies{Style.RESET_ALL}")
            return False
        
        try:
            policy_file = self.policy_dir / f"{policy_id}.json"
            with open(policy_file, "w") as f:
                json.dump(policy_data, f, indent=4)
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not save policy {policy_id}: {str(e)}{Style.RESET_ALL}")
            return False

    def delete_policy(self, policy_id):
        """
        Delete a policy.
        
        Args:
            policy_id (str): The ID of the policy to delete.
            
        Returns:
            bool: True if the policy was deleted successfully, False otherwise.
        """
        policy = self.get_policy(policy_id)
        if not policy:
            print(f"{Fore.RED}Error: Policy {policy_id} not found{Style.RESET_ALL}")
            return False
        
        if policy.get("built_in", False):
            print(f"{Fore.RED}Error: Cannot delete built-in policies{Style.RESET_ALL}")
            return False
        
        try:
            policy_file = self.policy_dir / f"{policy_id}.json"
            if policy_file.exists():
                policy_file.unlink()
            del self.policies[policy_id]
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not delete policy {policy_id}: {str(e)}{Style.RESET_ALL}")
            return False

    def create_policy(self, policy_id, name, description, ports, threads=100, timeout=1.0, rate_limit=0.1, vuln_check=True):
        """
        Create a new policy.
        
        Args:
            policy_id (str): The ID for the new policy.
            name (str): The name of the policy.
            description (str): Description of the policy.
            ports (str): Port range to scan.
            threads (int, optional): Number of threads to use. Defaults to 100.
            timeout (float, optional): Connection timeout in seconds. Defaults to 1.0.
            rate_limit (float, optional): Rate limiting between connection attempts. Defaults to 0.1.
            vuln_check (bool, optional): Whether to check for vulnerabilities. Defaults to True.
            
        Returns:
            bool: True if the policy was created successfully, False otherwise.
        """
        if policy_id in self.policies:
            print(f"{Fore.RED}Error: Policy {policy_id} already exists{Style.RESET_ALL}")
            return False
        
        policy_data = {
            "policy_id": policy_id,
            "name": name,
            "description": description,
            "ports": ports,
            "threads": threads,
            "timeout": timeout,
            "rate_limit": rate_limit,
            "vuln_check": vuln_check,
            "built_in": False,
            "created_at": datetime.now().isoformat(),
            "updated_at": datetime.now().isoformat()
        }
        
        self.policies[policy_id] = policy_data
        return self.save_policy(policy_id, policy_data)

    def export_policy(self, policy_id, output_file):
        """
        Export a policy to a file in JSON or YAML format.
        
        Args:
            policy_id (str): The ID of the policy to export.
            output_file (str): Path to save the exported policy.
            
        Returns:
            bool: True if the policy was exported successfully, False otherwise.
        """
        policy = self.get_policy(policy_id)
        if not policy:
            print(f"{Fore.RED}Error: Policy {policy_id} not found{Style.RESET_ALL}")
            return False
        
        try:
            output_path = Path(output_file)
            output_format = output_path.suffix.lower()
            
            if output_format == ".json":
                with open(output_path, "w") as f:
                    json.dump(policy, f, indent=4)
            elif output_format == ".yaml" or output_format == ".yml":
                with open(output_path, "w") as f:
                    yaml.dump(policy, f, default_flow_style=False)
            else:
                print(f"{Fore.RED}Error: Unsupported format {output_format}. Use .json, .yaml, or .yml{Style.RESET_ALL}")
                return False
            
            return True
        except Exception as e:
            print(f"{Fore.RED}Error: Could not export policy {policy_id}: {str(e)}{Style.RESET_ALL}")
            return False

    def import_policy(self, input_file, policy_id=None):
        """
        Import a policy from a file.
        
        Args:
            input_file (str): Path to the policy file to import.
            policy_id (str, optional): ID to use for the imported policy. Defaults to the filename.
            
        Returns:
            bool: True if the policy was imported successfully, False otherwise.
        """
        try:
            input_path = Path(input_file)
            input_format = input_path.suffix.lower()
            
            if not input_path.exists():
                print(f"{Fore.RED}Error: File {input_file} not found{Style.RESET_ALL}")
                return False
            
            if input_format == ".json":
                with open(input_path, "r") as f:
                    policy_data = json.load(f)
            elif input_format == ".yaml" or input_format == ".yml":
                with open(input_path, "r") as f:
                    policy_data = yaml.safe_load(f)
            else:
                print(f"{Fore.RED}Error: Unsupported format {input_format}. Use .json, .yaml, or .yml{Style.RESET_ALL}")
                return False
            
            if not self.validate_policy(policy_data):
                return False
            
            # Use the specified policy ID or the filename
            new_policy_id = policy_id or input_path.stem
            
            # Check if the policy already exists
            if new_policy_id in self.policies and self.policies[new_policy_id].get("built_in", False):
                print(f"{Fore.RED}Error: Cannot overwrite built-in policy {new_policy_id}{Style.RESET_ALL}")
                return False
            
            # Update the policy ID and timestamps
            policy_data["policy_id"] = new_policy_id
            policy_data["built_in"] = False
            if "created_at" not in policy_data:
                policy_data["created_at"] = datetime.now().isoformat()
            policy_data["updated_at"] = datetime.now().isoformat()
            
            # Save the policy
            self.policies[new_policy_id] = policy_data
            return self.save_policy(new_policy_id, policy_data)
        except Exception as e:
            print(f"{Fore.RED}Error: Could not import policy from {input_file}: {str(e)}{Style.RESET_ALL}")
            return False

    def clone_policy(self, source_id, target_id, **updates):
        """
        Clone an existing policy with optional updates.
        
        Args:
            source_id (str): ID of the policy to clone.
            target_id (str): ID for the new policy.
            **updates: Optional updates to apply to the cloned policy.
            
        Returns:
            bool: True if the policy was cloned successfully, False otherwise.
        """
        source_policy = self.get_policy(source_id)
        if not source_policy:
            print(f"{Fore.RED}Error: Source policy {source_id} not found{Style.RESET_ALL}")
            return False
        
        if target_id in self.policies:
            print(f"{Fore.RED}Error: Target policy {target_id} already exists{Style.RESET_ALL}")
            return False
        
        # Clone the policy
        new_policy = dict(source_policy)
        new_policy["policy_id"] = target_id
        new_policy["built_in"] = False
        new_policy["created_at"] = datetime.now().isoformat()
        new_policy["updated_at"] = datetime.now().isoformat()
        
        # Apply updates
        for key, value in updates.items():
            if key in new_policy:
                new_policy[key] = value
        
        # Save the cloned policy
        self.policies[target_id] = new_policy
        return self.save_policy(target_id, new_policy)

    def list_policies(self):
        """
        Get a list of all policies.
        
        Returns:
            list: List of policy IDs.
        """
        return list(self.policies.keys())

    def print_policies(self):
        """
        Print a list of all policies.
        """
        if not self.policies:
            print(f"{Fore.YELLOW}No policies found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Available Scan Policies:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        
        # Print built-in policies first
        print(f"\n{Fore.CYAN}Built-in Policies:{Style.RESET_ALL}")
        for policy_id, policy in self.policies.items():
            if policy.get("built_in", False):
                print(f"{Fore.GREEN}{policy_id}{Style.RESET_ALL}: {policy['name']} - {policy['description']}")
        
        # Print user-defined policies
        print(f"\n{Fore.CYAN}User-defined Policies:{Style.RESET_ALL}")
        user_policies = [p for p in self.policies.values() if not p.get("built_in", False)]
        if user_policies:
            for policy in user_policies:
                policy_id = policy["policy_id"]
                print(f"{Fore.GREEN}{policy_id}{Style.RESET_ALL}: {policy['name']} - {policy['description']}")
        else:
            print(f"{Fore.YELLOW}No user-defined policies found{Style.RESET_ALL}")

    def print_policy_details(self, policy_id):
        """
        Print detailed information about a policy.
        
        Args:
            policy_id (str): The ID of the policy to print details for.
        """
        policy = self.get_policy(policy_id)
        if not policy:
            print(f"{Fore.RED}Error: Policy {policy_id} not found{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}Policy Details: {policy_id}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*50}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Name:{Style.RESET_ALL} {policy['name']}")
        print(f"{Fore.GREEN}Description:{Style.RESET_ALL} {policy['description']}")
        print(f"{Fore.GREEN}Ports:{Style.RESET_ALL} {policy['ports']}")
        print(f"{Fore.GREEN}Threads:{Style.RESET_ALL} {policy['threads']}")
        print(f"{Fore.GREEN}Timeout:{Style.RESET_ALL} {policy['timeout']} seconds")
        print(f"{Fore.GREEN}Rate Limit:{Style.RESET_ALL} {policy['rate_limit']} seconds")
        print(f"{Fore.GREEN}Vulnerability Check:{Style.RESET_ALL} {'Enabled' if policy['vuln_check'] else 'Disabled'}")
        print(f"{Fore.GREEN}Built-in:{Style.RESET_ALL} {'Yes' if policy.get('built_in', False) else 'No'}")
        
        if not policy.get("built_in", False):
            created_at = datetime.fromisoformat(policy['created_at']).strftime("%Y-%m-%d %H:%M:%S")
            updated_at = datetime.fromisoformat(policy['updated_at']).strftime("%Y-%m-%d %H:%M:%S")
            print(f"{Fore.GREEN}Created:{Style.RESET_ALL} {created_at}")
            print(f"{Fore.GREEN}Updated:{Style.RESET_ALL} {updated_at}")

    def apply_policy_to_args(self, policy_id, args):
        """
        Apply a policy to command-line arguments.
        
        Args:
            policy_id (str): The ID of the policy to apply.
            args (argparse.Namespace): The command-line arguments to update.
            
        Returns:
            argparse.Namespace: The updated arguments.
        """
        policy = self.get_policy(policy_id)
        if not policy:
            print(f"{Fore.RED}Error: Policy {policy_id} not found{Style.RESET_ALL}")
            return args
        
        # Update arguments with policy values
        if hasattr(args, "ports") and args.ports is None:
            args.ports = policy["ports"]
        
        if hasattr(args, "threads") and args.threads is None:
            args.threads = policy["threads"]
        
        if hasattr(args, "timeout") and args.timeout is None:
            args.timeout = policy["timeout"]
        
        if hasattr(args, "rate_limit") and args.rate_limit is None:
            args.rate_limit = policy["rate_limit"]
        
        if hasattr(args, "vuln_check") and args.vuln_check is None:
            args.vuln_check = policy["vuln_check"]
        
        print(f"{Fore.GREEN}Applied policy '{policy_id}' ({policy['name']}){Style.RESET_ALL}")
        return args


# Global instance of the policy manager
_policy_manager = None

def get_policy_manager(policy_dir=None):
    """
    Get the global policy manager instance.
    
    Args:
        policy_dir (str, optional): Directory to store policy files. Defaults to None.
        
    Returns:
        ScanPolicy: The policy manager instance.
    """
    global _policy_manager
    if _policy_manager is None:
        _policy_manager = ScanPolicy(policy_dir)
    return _policy_manager