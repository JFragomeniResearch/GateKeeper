#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
import logging
import time
import dns.resolver  # for DNS verification
from cryptography.fernet import Fernet  # for encryption
import json
from typing import List, Tuple, Dict, Optional, Any
from utils.banner import display_banner, display_scan_start, display_scan_complete
import asyncio
from tqdm import tqdm
from colorama import init, Fore, Style
import ipaddress
import re
import os
import requests

# Initialize colorama
init(autoreset=True)  # Automatically reset colors after each print

class GateKeeper:
    def __init__(self):
        self.logger = self._setup_logging()
        self.start_time = None
        self.target = None
        self.ports = []
        self.threads = 100
        self.timeout = 1
        self.rate_limit = 0.1
        self.max_scan_rate = 1000  # maximum ports per second
        self.encryption_key = self._generate_encryption_key()
        self.reports_dir = Path('reports')
        
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for results."""
        try:
            key = Fernet.generate_key()
            if not isinstance(key, bytes) or len(key) != 44:  # Fernet keys are 44 bytes when base64 encoded
                raise ValueError("Invalid key format generated")
            return key
        except ValueError as e:
            # Re-raise ValueError directly
            raise e
        except Exception as e:
            raise RuntimeError(f"Failed to generate encryption key: {e}")

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('GateKeeper')
        logger.setLevel(logging.INFO)
        
        # Create logs directory if it doesn't exist
        log_file = Path('logs/gatekeeper.log')
        log_file.parent.mkdir(exist_ok=True)
        
        # Add handlers
        logger.addHandler(
            logging.FileHandler(log_file),
        )
        logger.addHandler(
            logging.StreamHandler()
        )
        
        return logger

    def verify_dns(self, target: str) -> bool:
        """Verify DNS resolution for target."""
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror as e:
            self.logger.error(f"DNS verification failed for {target}: {e}")
            return False  # Return False instead of raising exception

    async def scan_port(self, port: int) -> Optional[Dict]:
        """Scan a single port with rate limiting and timeout"""
        if not 0 <= port <= 65535:
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        
        try:
            # Implement rate limiting
            time.sleep(self.rate_limit)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = await self._identify_service(port)
                self.logger.info(f"Port {port} is open ({service})")
                return {
                    'port': port,
                    'status': 'open',
                    'service': service,
                    'timestamp': datetime.now().isoformat()
                }
            
            sock.close()
            return None
            
        except Exception as e:
            self.logger.error(f"Error scanning port {port}: {str(e)}")
            return None

    async def _identify_service(self, port: int) -> Optional[str]:
        """
        Identify the service running on a specific port.
        Returns the service name and version if detected.
        """
        try:
            reader, writer = await asyncio.open_connection(
                self.target, port, timeout=self.timeout
            )
            
            # Send appropriate probes based on common port numbers
            probe_data = b""
            if port == 80 or port == 443 or port == 8080:
                # HTTP probe
                probe_data = b"GET / HTTP/1.1\r\nHost: " + self.target.encode() + b"\r\n\r\n"
            elif port == 21:
                # FTP probe - just connect, no need to send data
                pass
            elif port == 22:
                # SSH probe - just connect, no need to send data
                pass
            elif port == 25 or port == 587:
                # SMTP probe
                probe_data = b"EHLO gatekeeper.scan\r\n"
            elif port == 110:
                # POP3 probe
                pass
            elif port == 143:
                # IMAP probe
                pass
            elif port == 3306:
                # MySQL probe
                pass
            
            # Send probe if we have one
            if probe_data:
                writer.write(probe_data)
                await writer.drain()
            
            # Read response with timeout
            response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
            
            # Close the connection
            writer.close()
            await writer.wait_closed()
            
            # Decode response if possible
            try:
                response_str = response.decode('utf-8', errors='ignore')
            except:
                response_str = str(response)
            
            # Identify service and version based on response
            service_info = {"name": "Unknown", "version": ""}
            
            # HTTP detection
            if b"HTTP/" in response:
                service_info["name"] = "HTTP"
                # Try to extract server info
                server_match = re.search(r"Server: ([^\r\n]+)", response_str)
                if server_match:
                    service_info["version"] = server_match.group(1)
            
            # SSH detection
            elif b"SSH-" in response:
                service_info["name"] = "SSH"
                # Extract SSH version
                ssh_match = re.search(r"SSH-\d+\.\d+-([^\r\n]+)", response_str)
                if ssh_match:
                    service_info["version"] = ssh_match.group(1)
            
            # FTP detection
            elif b"FTP" in response or b"220" in response and (b"ftp" in response.lower() or port == 21):
                service_info["name"] = "FTP"
                # Extract FTP server version
                ftp_match = re.search(r"220[- ]([^\r\n]+)", response_str)
                if ftp_match:
                    service_info["version"] = ftp_match.group(1)
            
            # SMTP detection
            elif b"SMTP" in response or b"220" in response and b"mail" in response.lower():
                service_info["name"] = "SMTP"
                # Extract SMTP server version
                smtp_match = re.search(r"220[- ]([^\r\n]+)", response_str)
                if smtp_match:
                    service_info["version"] = smtp_match.group(1)
            
            # MySQL detection
            elif b"mysql" in response.lower() or port == 3306:
                service_info["name"] = "MySQL"
                # Extract MySQL version if possible
                mysql_match = re.search(r"([0-9]+\.[0-9]+\.[0-9]+)", response_str)
                if mysql_match:
                    service_info["version"] = mysql_match.group(1)
            
            # If no specific service detected, use port number as a hint
            if service_info["name"] == "Unknown":
                common_ports = {
                    21: "FTP",
                    22: "SSH",
                    23: "Telnet",
                    25: "SMTP",
                    53: "DNS",
                    80: "HTTP",
                    110: "POP3",
                    143: "IMAP",
                    443: "HTTPS",
                    465: "SMTPS",
                    587: "SMTP",
                    993: "IMAPS",
                    995: "POP3S",
                    3306: "MySQL",
                    3389: "RDP",
                    5432: "PostgreSQL",
                    8080: "HTTP-Proxy"
                }
                service_info["name"] = common_ports.get(port, f"Unknown-{port}")
            
            return service_info
        
        except asyncio.TimeoutError:
            # Connection timed out, but port is open
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                110: "POP3",
                143: "IMAP",
                443: "HTTPS",
                465: "SMTPS",
                587: "SMTP",
                993: "IMAPS",
                995: "POP3S",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL",
                8080: "HTTP-Proxy"
            }
            return {"name": common_ports.get(port, f"Unknown-{port}"), "version": ""}
        
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            return {"name": f"Unknown-{port}", "version": ""}

    def encrypt_results(self, results: List[Dict]) -> bytes:
        """Encrypt scan results"""
        f = Fernet(self.encryption_key)
        data = json.dumps(results).encode()
        return f.encrypt(data)

    def decrypt_results(self, encrypted_data: bytes) -> List[Dict]:
        """Decrypt scan results."""
        if not encrypted_data:
            raise ValueError("Cannot decrypt empty data")
            
        try:
            f = Fernet(self.encryption_key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError(f"Failed to decrypt results: {e}")

    def save_results(self, results: List[Dict], encrypt: bool = False) -> None:
        """Save scan results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Ensure reports directory exists
        self.reports_dir.mkdir(exist_ok=True)
        
        if encrypt:
            filename = self.reports_dir / f'scan_results_{timestamp}.encrypted'
            encrypted_data = self.encrypt_results(results)
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
        else:
            filename = self.reports_dir / f'scan_results_{timestamp}.txt'
            with open(filename, 'w') as f:
                f.write(f"GateKeeper Scan Results\n")
                f.write(f"Target: {self.target}\n")
                f.write(f"Scan Date: {timestamp}\n")
                f.write(f"{'='*50}\n\n")
                
                for result in results:
                    f.write(f"Port {result['port']}: {result['service']}\n")

        self.logger.info(f"Results saved to {filename}")

    def display_disclaimer(self) -> bool:
        """
        Display legal disclaimer and require user acknowledgment.
        Returns True if user accepts, False if declined.
        """
        disclaimer = """
╔════════════════════ LEGAL DISCLAIMER ════════════════════╗
║                                                          ║
║  WARNING: This is a network security testing tool.       ║
║                                                          ║
║  By proceeding, you confirm that:                       ║
║                                                         ║
║  1. You have EXPLICIT PERMISSION to scan the target     ║
║     network/system                                      ║
║                                                         ║
║  2. You understand that unauthorized scanning may be     ║
║     ILLEGAL in your jurisdiction                        ║
║                                                         ║
║  3. You accept ALL RESPONSIBILITY for the use of this   ║
║     tool                                                ║
║                                                         ║
║  4. You will use this tool in accordance with all       ║
║     applicable laws and regulations                     ║
║                                                         ║
╚══════════════════════════════════════════════════════════╝
"""
        print(disclaimer)
        
        # Log the disclaimer display
        self.logger.info("Legal disclaimer displayed to user")
        
        try:
            # Ask for explicit confirmation
            confirmation = input("\nDo you accept these terms? (yes/no): ").lower().strip()
            
            if confirmation == 'yes':
                self.logger.info("User accepted legal disclaimer")
                print("\nDisclaimer accepted. Proceeding with scan...\n")
                return True
            else:
                self.logger.warning("User declined legal disclaimer")
                print("\nDisclaimer not accepted. Exiting program.")
                return False
            
        except KeyboardInterrupt:
            self.logger.warning("User interrupted disclaimer prompt")
            print("\nOperation cancelled by user.")
            return False

    def validate_ports(self, ports_str: str) -> List[int]:
        """Validate port numbers from string input."""
        try:
            ports = []
            for port in ports_str.split(','):
                port = int(port.strip())
                if not 1 <= port <= 65535:
                    raise ValueError(f"Port {port} is out of valid range (1-65535)")
                ports.append(port)
            return ports
        except ValueError as e:
            raise ValueError(f"Invalid port specification: {e}")

    def parse_arguments(self):
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(
            description="GateKeeper - Network Security Scanner",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter
        )
        parser.add_argument('-t', '--target', required=True, help='Target IP address or hostname or CIDR range')
        parser.add_argument('-p', '--ports', default='1-1000', help='Port(s) to scan (e.g., 80,443 or 1-1000)')
        parser.add_argument('--timeout', type=float, default=1.0, help='Timeout for connection attempts')
        parser.add_argument('--threads', type=int, default=100, help='Number of concurrent threads')
        parser.add_argument('-o', '--output', help='Output file for results')
        parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
        
        return parser.parse_args()

    def expand_targets(self, target):
        """
        Expand target to a list of IP addresses if it's a CIDR range.
        Returns a list of target IP addresses.
        """
        try:
            # Check if the target is a CIDR range
            if '/' in target:
                network = ipaddress.ip_network(target, strict=False)
                # Convert to list of strings and limit to a reasonable number
                ip_list = [str(ip) for ip in network.hosts()]
                
                # If the range is large, warn the user
                if len(ip_list) > 256:
                    print(f"{Fore.YELLOW}Warning: Large IP range detected ({len(ip_list)} hosts). This may take a while.{Style.RESET_ALL}")
                    confirm = input("Do you want to continue? (y/n): ").lower()
                    if confirm != 'y':
                        self.logger.info("Scan cancelled by user due to large IP range")
                        sys.exit(0)
                
                return ip_list
            else:
                # Single target
                return [target]
        except ValueError:
            # Not a valid CIDR, assume it's a hostname
            self.logger.info(f"Target {target} is not a valid CIDR range, treating as hostname")
            return [target]

    async def scan_ports(self):
        """
        Scan the target for open ports using asyncio for concurrency.
        Returns a list of dictionaries with port and service information.
        """
        self.logger.info(f"Starting port scan on {self.target} for ports {self.ports}")
        
        start_time = time.time()
        open_ports = []
        semaphore = asyncio.Semaphore(self.threads)
        
        # Create tasks for all ports
        tasks = [self.scan_port(port) for port in self.ports]
        
        # Set up progress bar
        with tqdm(total=len(tasks), desc="Scanning ports", unit="port") as progress_bar:
            # Process tasks as they complete
            for future in asyncio.as_completed(tasks):
                result = await future
                if result:  # If port is open
                    open_ports.append(result)
                progress_bar.update(1)
        
        scan_duration = time.time() - start_time
        
        print(f"\n{Fore.CYAN}Scan completed in {scan_duration:.2f} seconds{Style.RESET_ALL}")
        self.logger.info(f"Scan complete. Found {len(open_ports)} open ports in {scan_duration:.2f} seconds")
        return open_ports

    def validate_target(self, target: str) -> str:
        """Validate target hostname or IP address."""
        if not target:
            raise ValueError("Target cannot be empty")
        
        # Remove any whitespace and protocol prefixes
        target = target.strip().lower()
        target = target.replace('http://', '').replace('https://', '')
        
        # Basic validation of hostname format
        if not all(c.isalnum() or c in '-._' for c in target.split('.')[0]):
            raise ValueError("Invalid target format")
            
        return target

    def display_results(self, results):
        """Display scan results in a formatted, colorized way."""
        if not results:
            print(f"{Fore.YELLOW}No open ports found on {self.target}{Style.RESET_ALL}")
            return
        
        print(f"\n{Fore.CYAN}=== Scan Results for {self.target} ==={Style.RESET_ALL}")
        print(f"{Fore.GREEN}Found {len(results)} open ports:{Style.RESET_ALL}")
        
        # Create a formatted table
        print(f"\n{Fore.CYAN}{'PORT':<10}{'STATE':<10}{'SERVICE':<15}{'VERSION':<30}{Style.RESET_ALL}")
        print("-" * 65)
        
        for result in results:
            port = result.get('port', 'N/A')
            service = result.get('service', 'Unknown')
            version = result.get('version', '')
            
            print(f"{Fore.GREEN}{port:<10}{'open':<10}{Style.RESET_ALL}{service:<15}{version:<30}")
        
        print(f"\n{Fore.CYAN}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    def load_vulnerability_database(self):
        """
        Load vulnerability database from a local file or download from a remote source.
        Returns a dictionary of vulnerabilities indexed by service and version.
        """
        try:
            # First try to load from local file
            db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vuln_db.json")
            
            # Check if the database exists and is less than 7 days old
            update_db = True
            if os.path.exists(db_path):
                file_age = datetime.now().timestamp() - os.path.getmtime(db_path)
                if file_age < 7 * 24 * 60 * 60:  # 7 days in seconds
                    update_db = False
            
            if update_db:
                print(f"{Fore.CYAN}Updating vulnerability database...{Style.RESET_ALL}")
                # In a real implementation, you would download from a real vulnerability database
                # For this example, we'll create a simple database with some common vulnerabilities
                vuln_db = {
                    "HTTP": {
                        "Apache": [
                            {"id": "CVE-2021-41773", "severity": "HIGH", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.49"},
                            {"id": "CVE-2021-42013", "severity": "HIGH", "description": "Path traversal vulnerability in Apache HTTP Server 2.4.50"}
                        ],
                        "nginx": [
                            {"id": "CVE-2021-23017", "severity": "MEDIUM", "description": "Nginx resolver vulnerability"}
                        ]
                    },
                    "SSH": {
                        "OpenSSH": [
                            {"id": "CVE-2020-14145", "severity": "LOW", "description": "OpenSSH client information leak"},
                            {"id": "CVE-2019-6111", "severity": "MEDIUM", "description": "OpenSSH SCP client arbitrary file write vulnerability"}
                        ]
                    },
                    "FTP": {
                        "vsftpd": [
                            {"id": "CVE-2011-2523", "severity": "HIGH", "description": "vsftpd 2.3.4 backdoor vulnerability"}
                        ]
                    },
                    "SMTP": {
                        "Exim": [
                            {"id": "CVE-2019-15846", "severity": "CRITICAL", "description": "Exim remote command execution vulnerability"}
                        ]
                    },
                    "MySQL": {
                        "MySQL": [
                            {"id": "CVE-2021-2307", "severity": "HIGH", "description": "MySQL Server privilege escalation vulnerability"}
                        ]
                    }
                }
                
                # Save the database to a local file
                with open(db_path, 'w') as f:
                    json.dump(vuln_db, f, indent=2)
                
                print(f"{Fore.GREEN}Vulnerability database updated successfully{Style.RESET_ALL}")
            else:
                # Load from local file
                with open(db_path, 'r') as f:
                    vuln_db = json.load(f)
                
                if self.verbose:
                    print(f"{Fore.CYAN}Using cached vulnerability database{Style.RESET_ALL}")
            
            return vuln_db
        
        except Exception as e:
            self.logger.error(f"Error loading vulnerability database: {e}")
            print(f"{Fore.YELLOW}Warning: Could not load vulnerability database. Vulnerability scanning will be limited.{Style.RESET_ALL}")
            return {}

    def check_vulnerabilities(self, results):
        """
        Check for known vulnerabilities based on service and version information.
        Returns the results with added vulnerability information.
        """
        vuln_db = self.load_vulnerability_database()
        
        if not vuln_db:
            return results
        
        for result in results:
            service = result.get('service', 'Unknown')
            version_full = result.get('version', '')
            
            # Initialize vulnerabilities list
            result['vulnerabilities'] = []
            
            # Skip if service is unknown or no version info
            if service == 'Unknown' or not version_full:
                continue
            
            # Check if the service exists in the vulnerability database
            if service in vuln_db:
                # Extract the software name from the version string
                # This is a simplified approach - in reality, you'd need more sophisticated parsing
                version_parts = version_full.split()
                software_candidates = []
                
                # Try to identify the software name
                for part in version_parts:
                    if part.lower() in [s.lower() for s in vuln_db[service].keys()]:
                        software_candidates.append(part)
                
                # If we couldn't identify the software, try common names
                if not software_candidates and service == "HTTP":
                    if "apache" in version_full.lower():
                        software_candidates.append("Apache")
                    elif "nginx" in version_full.lower():
                        software_candidates.append("nginx")
                
                # Check vulnerabilities for each potential software match
                for software in software_candidates:
                    for sw_name in vuln_db[service].keys():
                        if software.lower() == sw_name.lower():
                            # Add all vulnerabilities for this software
                            for vuln in vuln_db[service][sw_name]:
                                result['vulnerabilities'].append(vuln)
        
        return results

    def main(self):
        """Main execution flow."""
        try:
            args = self.parse_arguments()
            self.target = args.target
            self.ports = self.validate_ports(args.ports)
            self.timeout = args.timeout
            self.threads = args.threads
            self.verbose = args.verbose

            self.display_disclaimer()
            if input("Do you accept these terms? (yes/no): ").lower().strip() != 'yes':
                self.logger.info("Scan cancelled by user")
                sys.exit(0)

            # Expand targets if CIDR notation is used
            targets = self.expand_targets(self.target)
            
            all_results = {}
            total_start_time = time.time()
            
            # Scan each target
            for i, target in enumerate(targets):
                if len(targets) > 1:
                    print(f"\n{Fore.CYAN}Scanning target {i+1}/{len(targets)}: {target}{Style.RESET_ALL}")
                
                self.target = target  # Update current target
                self.logger.info(f"Starting scan of {self.target}")
                
                # Scan ports
                results = asyncio.run(self.scan_ports())
                
                # Check for vulnerabilities
                print(f"\n{Fore.CYAN}Checking for vulnerabilities...{Style.RESET_ALL}")
                results = self.check_vulnerabilities(results)
                
                all_results[target] = results
                
                # Display results for this target
                self.display_results(results)
                
                # Save results for this target
                if args.output:
                    self.save_results(results, filename=f"{args.output}_{target.replace('.', '_')}.json", encrypt=True)
            
            total_duration = time.time() - total_start_time
            
            # Display summary if multiple targets were scanned
            if len(targets) > 1:
                print(f"\n{Fore.CYAN}=== Scan Summary ==={Style.RESET_ALL}")
                print(f"Scanned {len(targets)} targets in {total_duration:.2f} seconds")
                
                total_open = sum(len(results) for results in all_results.values())
                print(f"{Fore.GREEN}Found {total_open} open ports across all targets{Style.RESET_ALL}")
            
            self.logger.info("Scan complete")

        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
            self.logger.info("Scan interrupted by user")
            sys.exit(0)
        except Exception as e:
            self.logger.error(f"Error during execution: {e}")
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            sys.exit(1)

def main():
    # Display the banner first
    display_banner()
    
    scanner = GateKeeper()
    
    scanner.main()

if __name__ == "__main__":
    main() 