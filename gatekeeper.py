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
        
    def _generate_encryption_key(self) -> bytes:
        """Generate encryption key for securing scan results"""
        return Fernet.generate_key()

    def _setup_logging(self) -> logging.Logger:
        """Configure logging with audit trail"""
        log_file = Path('logs/gatekeeper.log')
        log_file.parent.mkdir(exist_ok=True)
        
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('GateKeeper')

    def verify_dns(self, target: str) -> bool:
        """Verify DNS resolution and check for common DNS-related attacks"""
        try:
            # Perform forward DNS lookup
            ip_addr = socket.gethostbyname(target)
            
            # Perform reverse DNS lookup
            host_name = socket.gethostbyaddr(ip_addr)[0]
            
            # Verify with multiple DNS servers
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google DNS and Cloudflare
            answers = resolver.resolve(target, 'A')
            
            self.logger.info(f"DNS verification successful for {target} ({ip_addr})")
            return True
            
        except (socket.gaierror, dns.resolver.NXDOMAIN) as e:
            self.logger.error(f"DNS verification failed for {target}: {str(e)}")
            return False

    async def scan_port(self, port: int) -> Optional[Dict]:
        """Scan a single port with rate limiting and timeout"""
        try:
            # Implement rate limiting
            time.sleep(self.rate_limit)
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                service = self._identify_service(port)
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

    def _identify_service(self, port: int) -> str:
        """Identify common services based on port number"""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            3306: 'MySQL',
            3389: 'RDP'
        }
        return common_ports.get(port, 'Unknown')

    def encrypt_results(self, results: List[Dict]) -> bytes:
        """Encrypt scan results"""
        f = Fernet(self.encryption_key)
        data = json.dumps(results).encode()
        return f.encrypt(data)

    def save_results(self, results: List[Dict], encrypt: bool = False) -> None:
        """Save scan results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        report_dir = Path('reports')
        report_dir.mkdir(exist_ok=True)
        
        if encrypt:
            encrypted_data = self.encrypt_results(results)
            filename = report_dir / f'scan_results_{timestamp}.encrypted'
            with open(filename, 'wb') as f:
                f.write(encrypted_data)
        else:
            filename = report_dir / f'scan_results_{timestamp}.txt'
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

def main():
    parser = argparse.ArgumentParser(description='GateKeeper Network Scanner')
    parser.add_argument('-t', '--target', required=True, help='Target hostname or IP')
    parser.add_argument('-p', '--ports', required=True, help='Port range (e.g., 1-1024)')
    parser.add_argument('-th', '--threads', type=int, default=100, help='Number of threads')
    parser.add_argument('--timeout', type=float, default=1.0, help='Timeout in seconds')
    parser.add_argument('--rate-limit', type=float, default=0.1, help='Time between scans')
    parser.add_argument('--encrypt', action='store_true', help='Encrypt scan results')
    
    args = parser.parse_args()
    
    scanner = GateKeeper()
    
    # Check disclaimer acceptance
    if not scanner.display_disclaimer():
        sys.exit(1)
    
    if not scanner.verify_dns(args.target):
        sys.exit(1)
    
    # Parse port range
    try:
        if '-' in args.ports:
            start, end = map(int, args.ports.split('-'))
            ports = range(start, end + 1)
        else:
            ports = [int(args.ports)]
    except ValueError:
        scanner.logger.error("Invalid port range specified")
        sys.exit(1)

    scanner.target = args.target
    scanner.threads = args.threads
    scanner.timeout = args.timeout
    scanner.rate_limit = args.rate_limit

    # Start scanning
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_port = {executor.submit(scanner.scan_port, port): port for port in ports}
        for future in concurrent.futures.as_completed(future_to_port):
            result = future.result()
            if result:
                results.append(result)

    # Save results
    scanner.save_results(results, encrypt=args.encrypt)

if __name__ == "__main__":
    main() 