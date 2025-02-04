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
from typing import List, Tuple, Dict, Optional
from utils.banner import display_banner, display_scan_start, display_scan_complete
import asyncio

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
        """Identify service running on a port."""
        try:
            reader, writer = await asyncio.open_connection(self.target, port)
            try:
                # Send appropriate probe for each service
                if port == 22:
                    writer.write(b'SSH-2.0-GateKeeper\r\n')
                    await writer.drain()
                    response = await reader.readline()
                    if b'SSH' in response:
                        return 'SSH'
                elif port == 80:
                    writer.write(b'GET / HTTP/1.0\r\n\r\n')
                    await writer.drain()
                    response = await reader.readline()
                    if b'HTTP' in response:
                        return 'HTTP'
                elif port == 443:
                    return 'HTTPS'  # HTTPS detection is passive
                
                return f'Unknown-{port}'
            finally:
                writer.close()
                await writer.wait_closed()
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            return None

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

    def parse_arguments(self) -> argparse.Namespace:
        """Parse command line arguments."""
        parser = argparse.ArgumentParser(description='GateKeeper Port Scanner')
        parser.add_argument('-t', '--target', required=True, help='Target host to scan')
        parser.add_argument('-p', '--ports', required=True, help='Ports to scan (comma-separated)')
        parser.add_argument('--timeout', type=float, default=1.0, help='Timeout for each port scan')
        parser.add_argument('--threads', type=int, default=100, help='Number of concurrent scans')
        return parser.parse_args()

    async def scan_ports(self) -> List[Dict]:
        """Scan multiple ports concurrently."""
        tasks = []
        for port in self.ports:
            tasks.append(asyncio.create_task(self.scan_port(port)))
        
        results = []
        for task in asyncio.as_completed(tasks):
            try:
                result = await task
                if result:
                    results.append(result)
            except Exception as e:
                self.logger.error(f"Error during port scan: {e}")
        
        # Sort results by port number for consistency
        results.sort(key=lambda x: x['port'])
        return results

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

    def main(self):
        """Main execution flow."""
        try:
            args = self.parse_arguments()
            self.target = args.target
            self.ports = self.validate_ports(args.ports)
            self.timeout = args.timeout
            self.threads = args.threads

            self.display_disclaimer()
            if input("Do you want to continue? (yes/no): ").lower() != 'yes':
                self.logger.info("Scan cancelled by user")
                sys.exit(0)  # Add explicit exit for cancellation

            self.logger.info(f"Starting scan of {self.target}")
            results = asyncio.run(self.scan_ports())
            
            # Save results
            self.save_results(results, encrypt=True)
            self.logger.info("Scan complete")
            
        except Exception as e:
            self.logger.error(f"Error during execution: {e}")
            sys.exit(1)

def main():
    # Display the banner first
    display_banner()
    
    scanner = GateKeeper()
    
    scanner.main()

if __name__ == "__main__":
    main() 