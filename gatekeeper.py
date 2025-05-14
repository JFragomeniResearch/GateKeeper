#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
import logging
import logging.handlers
import time
import dns.resolver  # for DNS verification
from cryptography.fernet import Fernet, InvalidToken  # for encryption
import json
from typing import List, Tuple, Dict, Optional, Any, TextIO, BinaryIO, Union, ContextManager
from utils.banner import display_banner, display_scan_start, display_scan_complete
from utils.report_compare import ReportComparer, find_latest_reports
from utils.port_behavior import PortBehaviorAnalyzer
from utils.scan_policy import get_policy_manager
from utils.target_groups import get_target_groups
from utils.export import export_results
from utils.notifications import get_notification_manager
from utils.config import ConfigManager, ScanConfig, ScanState
import asyncio
from tqdm import tqdm
from colorama import init, Fore, Style
import ipaddress
import re
import os
import requests
import csv
import html
import yaml
import shutil
import py_cui
import threading
import queue
import contextlib
from typing import Iterator
import functools

# Initialize colorama
init(autoreset=True)  # Automatically reset colors after each print

class GateKeeper:
    LOG_DIR = Path('logs')
    LOG_FILENAME = 'gatekeeper.log'

    def __init__(self):
        """Initialize the GateKeeper application."""
        # Set up logging
        self.logger = self._setup_logging()
        
        # Initialize configuration and state management
        self.config_manager = ConfigManager(self.logger)
        
        # Initialize managers
        self.policy_manager = get_policy_manager()
        self.target_groups = get_target_groups()
        self.notification_manager = get_notification_manager()
        self.port_analyzer = PortBehaviorAnalyzer()
        self.report_comparer = ReportComparer()
        
        # Generate encryption key if not already configured
        if not self.config_manager.config.encryption_key:
            self._generate_encryption_key()
        
        self.logger.info("GateKeeper initialized")
        
        # Define common ports as a class attribute to avoid duplication
        self.common_ports = {
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
        
    def _generate_encryption_key(self) -> bytes:
        """Generate a new encryption key."""
        try:
            key = Fernet.generate_key()
            self.logger.info("Generated new encryption key")
            return key
        except Exception as e:
            self.logger.error(f"Error generating encryption key: {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise

    def _encrypt_file(self, filepath: Union[str, Path]) -> bool:
        """Encrypt a file using the configured encryption key."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        # Check if encryption key is available
        if not config.encryption_key:
            self.logger.error("No encryption key configured")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return False
        
        try:
            # Read the file content
            content = self._read_file(filepath, binary=True)
            if content is None:
                return False
            
            # Encrypt the content
            fernet = Fernet(config.encryption_key)
            encrypted_content = fernet.encrypt(content)
            
            # Write the encrypted content
            encrypted_file = Path(f"{filepath}.enc")
            return self._write_file(encrypted_file, encrypted_content, binary=True)
        except Exception as e:
            self.logger.error(f"Error encrypting file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return False

    def _decrypt_file(self, filepath: Union[str, Path]) -> Optional[bytes]:
        """Decrypt a file using the configured encryption key."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        # Check if encryption key is available
        if not config.encryption_key:
            self.logger.error("No encryption key configured")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return None
        
        try:
            # Read the encrypted content
            encrypted_content = self._read_file(filepath, binary=True)
            if encrypted_content is None:
                return None
            
            # Decrypt the content
            fernet = Fernet(config.encryption_key)
            try:
                return fernet.decrypt(encrypted_content)
            except InvalidToken as ite:
                # Log a more specific error for invalid token or corrupted data
                self.logger.warning(
                    f"Decryption failed for file '{filepath}' due to an invalid token or corrupted data. "
                    f"This usually means the file is not a valid encrypted file or the key is incorrect. Details: {str(ite)}"
                )
                raise # Re-raise to be caught by the outer try-except
        except Exception as e:
            self.logger.error(f"Error decrypting file {filepath}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            return None

    def _setup_logging(self) -> logging.Logger:
        """Set up logging configuration."""
        logger = logging.getLogger('gatekeeper')
        logger.setLevel(logging.DEBUG)
        
        # Create logs directory if it doesn't exist using class attribute
        self.LOG_DIR.mkdir(exist_ok=True)
        
        # File handler for debug logs using class attributes
        log_filepath = self.LOG_DIR / self.LOG_FILENAME
        file_handler = logging.handlers.RotatingFileHandler(
            log_filepath,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        
        # Console handler for info and above
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(logging.Formatter(
            '%(levelname)s: %(message)s'
        ))
        
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
        
        return logger

    def _handle_dns_error(self, target: str, error: Exception) -> bool:
        """
        Handle DNS resolution errors consistently.
        Determines the error type based on the exception.
        
        Args:
            target: The target hostname or IP being resolved.
            error: The exception that was raised.
            
        Returns:
            bool: Always returns False to indicate failure.
        """
        state = self.config_manager.state
        
        # Determine error type string based on exception type
        if isinstance(error, dns.resolver.NXDOMAIN):
            error_type = "does not exist"
        elif isinstance(error, dns.resolver.Timeout):
            error_type = "timed out"
        elif isinstance(error, dns.resolver.NoAnswer):
            error_type = "no answer"
        elif isinstance(error, dns.resolver.NoNameservers):
            error_type = "no nameservers available"
        elif isinstance(error, dns.exception.DNSException):
            error_type = "specific DNS error"
        elif isinstance(error, ValueError) and "ip_address" in str(error).lower(): # Crude check for IP parsing error
             error_type = "general verification error during IP check"
        else:
            # Default for other exceptions caught during resolution/setup
            error_type = "general verification error"
            
        error_msg = f"DNS resolution failed: {error_type} for {target}: {str(error)}"
            
        self.logger.error(error_msg)
        self.config_manager.update_state(
            error_count=state.error_count + 1
        )
        return False
        
    def verify_dns(self, target: str) -> bool:
        """Verify DNS resolution for a target."""
        config = self.config_manager.config
        
        # First, check if it's a valid IP address.
        try:
            ipaddress.ip_address(target)
            return True # It's a valid IP, no DNS check needed.
        except ValueError:
            # Not an IP, so proceed with DNS resolution.
            pass # Continue to the DNS check below
        except Exception as e:
             # Catch any other unexpected errors during IP check
             return self._handle_dns_error(target, e)

        # If it wasn't a valid IP, try DNS resolution.
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = config.timeout
            resolver.lifetime = config.timeout
            resolver.resolve(target)
            return True # DNS resolved successfully
        except (dns.resolver.NXDOMAIN,
                dns.resolver.Timeout,
                dns.resolver.NoAnswer,
                dns.resolver.NoNameservers,
                dns.exception.DNSException) as e:
             # Catch specific DNS exceptions and let handler categorize
             return self._handle_dns_error(target, e)
        except Exception as e:
             # Catch broader errors during the resolver setup or resolution
             return self._handle_dns_error(target, e)

    def _scan_port(self, target: str, port: int, timeout: float, scan_type: str) -> Tuple[bool, Optional[str]]:
        """
        Scan a single port.
        
        Args:
            target: Target IP address or hostname
            port: Port number to scan
            timeout: Connection timeout in seconds
            scan_type: Type of scan ('tcp' or 'udp')
            
        Returns:
            Tuple[bool, Optional[str]]: A tuple where:
                - First element is True if port is open, False otherwise
                - Second element is None if port is closed/open normally,
                  or an error string if port is filtered or an error occurred
        """
        try:
            if scan_type == "tcp":
                # Use context manager for automatic socket closing
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    # result == 0 means open, otherwise closed/filtered
                    return result == 0, None
            elif scan_type == "udp":
                # UDP scan logic is inherently less reliable than TCP
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    sock.settimeout(timeout)
                    try:
                        # Send empty datagram
                        sock.sendto(b'', (target, port))
                        # Attempt to receive - response indicates open, timeout likely open|filtered
                        # ICMP Port Unreachable error indicates closed
                        data, addr = sock.recvfrom(1024) # Blocking call
                        return True, None # Response received, likely open
                    except socket.timeout:
                        # Timeout usually means open or filtered. Treat as not definitively open.
                        # Returning specific error string for filtered state.
                        return False, "filtered (timeout)"
                    except ConnectionRefusedError:
                         # Can indicate closed UDP port on some systems (e.g., Windows sending ICMP)
                         return False, None # Port is closed
                    except OSError as e:
                        # Catch specific OS errors like ICMP port unreachable
                        # Example: Windows may raise WinError 10054
                        if hasattr(e, 'winerror') and e.winerror == 10054:
                            return False, None # ICMP Port Unreachable received - closed
                        else:
                             # Log unexpected OS errors
                            self.logger.warning(f"UDP scan OS error for {target}:{port}: {e}")
                            return False, f"OSError: {str(e)}" 
                    except Exception as e:
                        # Catch other unexpected errors during UDP send/recv
                        self.logger.warning(f"Unexpected UDP scan error for {target}:{port}: {e}")
                        return False, f"UDP Error: {str(e)}"
            else:
                # Should not happen if validated earlier, but good practice
                raise ValueError(f"Unsupported scan type: {scan_type}")
        except socket.gaierror as e:
            # Handle DNS resolution or address-related errors
            self.logger.error(f"Address resolution error for target '{target}': {e}")
            return False, f"Address Error: {e}"
        except socket.error as e:
            # Catch other socket-level errors (e.g., permission denied to bind/listen)
            self.logger.error(f"Socket error scanning {target}:{port}: {e}")
            return False, f"Socket Error: {str(e)}"
        except Exception as e:
            # Catch-all for any other unexpected errors during the scan process
            self.logger.error(f"Unexpected error scanning {target}:{port}: {e}")
            return False, f"Scan Error: {str(e)}"

    async def scan_port(self, port: int) -> Optional[Dict]:
        """
        Scan a single port with rate limiting and timeout.
        
        Args:
            port: Port number to scan
            
        Returns:
            Optional[Dict]: Scan result if the port is open, None otherwise
        """
        config = self.config_manager.config
        
        if not 0 <= port <= 65535:
            raise ValueError(f"Port number must be between 0 and 65535, got {port}")
        
        # Use asyncio.sleep instead of time.sleep for rate limiting in async functions
        await asyncio.sleep(config.rate_limit)
        
        try:
            # Use context manager for socket handling
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(config.timeout)
            
            # Attempt connection
                result = sock.connect_ex((config.target, port))
            
            if result == 0:
                # Connection successful - port is open
                service_info = await self._identify_service(port)
                self.logger.info(f"Port {port} is open ({service_info['name']})")
                
                return {
                    'port': port,
                    'status': 'open',
                    'service': service_info['name'],
                    'version': service_info['version'],
                    'timestamp': datetime.now().isoformat()
                }
            
            return None  # Port is closed or filtered
            
        except socket.timeout:
            self.logger.debug(f"Connection to port {port} timed out")
        except ConnectionRefusedError:
            self.logger.debug(f"Connection to port {port} refused")
        except (socket.gaierror, socket.error) as e:
            self.logger.error(f"Socket error scanning port {port}: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error scanning port {port}: {e}")
        
        return None  # Return None for all error cases

    def _get_service_probe(self, port: int) -> Optional[bytes]:
        """
        Get an appropriate probe for the given port.
        
        Args:
            port: The port number to get a probe for
            
        Returns:
            Optional[bytes]: The probe data as bytes, or None if no probe is needed
        """
        config = self.config_manager.config
        # Use direct `in` check for clarity
        if port in {80, 443, 8080}:
            # HTTP probe
            return f"GET / HTTP/1.1\r\nHost: {config.target}\r\n\r\n".encode()
        elif port in {25, 587}:
            # SMTP probe
            return b"EHLO gatekeeper.scan\r\n"
        elif port == 21:
            # FTP probe - just connect, no need to send data
            return None
        elif port == 22:
            # SSH probe - just connect, no need to send data
            return None
        elif port == 3306:
            # MySQL probe
            return None
        
        # No specific probe for other ports
        return None

    async def _identify_service(self, port: int) -> Dict[str, str]:
        """Identify the service running on a specific port."""
        config = self.config_manager.config
        service_info = {"name": self.common_ports.get(port, f"Unknown-{port}"), "version": ""}

        reader = None # Initialize reader/writer to ensure they exist in finally block
        writer = None
        try:
            reader, writer = await asyncio.open_connection(
                config.target, port, timeout=config.timeout
            )

            probe_data = self._get_service_probe(port)
            if probe_data:
                writer.write(probe_data)
                await writer.drain()

            response = await asyncio.wait_for(reader.read(1024), timeout=config.timeout)
            response_str = response.decode('utf-8', errors='ignore')

            # --- Identify service based on response ---
            if b"HTTP/" in response:
                service_info = self._extract_http_info(response_str)
            elif b"SSH-" in response:
                service_info = self._extract_ssh_info(response_str)
            elif b"FTP" in response or (b"220" in response and (b"ftp" in response.lower() or port == 21)):
                service_info = self._extract_ftp_info(response_str)
            elif b"SMTP" in response or (b"220" in response and b"mail" in response.lower()):
                service_info = self._extract_smtp_info(response_str)
            elif b"mysql" in response.lower() or port == 3306:
                service_info = self._extract_mysql_info(response_str)
            # --- End service identification ---

        except asyncio.TimeoutError:
            # Timeout reading response or connecting
            self.logger.debug(f"Timeout during service identification for port {port}")
            # service_info remains default
        except ConnectionRefusedError:
             self.logger.debug(f"Connection refused during service identification for port {port}")
             # service_info remains default
        except Exception as e:
            self.logger.error(f"Service identification failed for port {port}: {e}")
            # service_info remains default
        finally:
            # Ensure connection is closed if writer was opened
            if writer:
                writer.close()
                await writer.wait_closed()

        return service_info

    def _extract_service_info(self, service_name: str, response_str: str, pattern: str) -> Dict[str, str]:
        """
        Extract service information using a regex pattern.
        
        Args:
            service_name: Name of the service
            response_str: Response string to extract info from
            pattern: Regex pattern to match the version information
            
        Returns:
            Dict[str, str]: Dictionary containing service name and version
        """
        try:
            match = re.search(pattern, response_str)
            version = match.group(1).strip() if match else ""
            return {"name": service_name, "version": version}
        except (AttributeError, IndexError) as e:
            self.logger.debug(f"Failed to extract {service_name} version: {e}")
            return {"name": service_name, "version": ""}
        except Exception as e:
            self.logger.warning(f"Unexpected error extracting {service_name} version: {e}")
            return {"name": service_name, "version": ""}
            
    def _extract_http_info(self, response_str: str) -> Dict[str, str]:
        """Extract HTTP server information from response."""
        return self._extract_service_info("HTTP", response_str, r"Server: ([^\r\n]+)")
        
    def _extract_ssh_info(self, response_str: str) -> Dict[str, str]:
        """Extract SSH server information from response."""
        return self._extract_service_info("SSH", response_str, r"SSH-\d+\.\d+-([^\r\n]+)")
        
    def _extract_ftp_info(self, response_str: str) -> Dict[str, str]:
        """Extract FTP server information from response."""
        return self._extract_service_info("FTP", response_str, r"220[- ]([^\r\n]+)")
        
    def _extract_smtp_info(self, response_str: str) -> Dict[str, str]:
        """Extract SMTP server information from response."""
        return self._extract_service_info("SMTP", response_str, r"220[- ]([^\r\n]+)")
        
    def _extract_mysql_info(self, response_str: str) -> Dict[str, str]:
        """Extract MySQL server information from response."""
        return self._extract_service_info("MySQL", response_str, r"([0-9]+\.[0-9]+\.[0-9]+)")

    def encrypt_results(self, results: List[Dict]) -> bytes:
        """Encrypt scan results"""
        config = self.config_manager.config
        if not config.encryption_key:
            raise ValueError("Encryption key not configured")
        f = Fernet(config.encryption_key)
        data = json.dumps(results).encode()
        return f.encrypt(data)

    def decrypt_results(self, encrypted_data: bytes) -> List[Dict]:
        """Decrypt scan results."""
        config = self.config_manager.config
        if not encrypted_data:
            raise ValueError("Cannot decrypt empty data")
            
        try:
            if not config.encryption_key:
                raise ValueError("Encryption key not configured")
            f = Fernet(config.encryption_key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            raise ValueError(f"Failed to decrypt results: {e}")

    def _log_and_print(self, message: str, level: str = 'info', color: str = None) -> None:
        """Log a message and optionally print it with color."""
        # Log the message
        log_level = getattr(logging, level.upper())
        self.logger.log(log_level, message)
        
        # Print with color if specified
        if color:
            print(f"{color}{message}{Style.RESET_ALL}")
        else:
            print(message)

    def _save_results(self, results: Dict[str, Any]) -> None:
        """Save scan results in configured formats."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        # Map format names to save methods
        save_methods = {
            "json": self._save_json_results,
            "csv": self._save_csv_results,
            "html": self._save_html_results,
        }
        
        try:
            # Ensure output directory exists
            output_dir = Path(config.output_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            base_filename = f"gatekeeper_scan_{timestamp}"
            
            # Save in each configured format
            for format_name in config.export_formats:
                save_func = save_methods.get(format_name)
                if save_func:
                    try:
                        filepath = output_dir / f"{base_filename}.{format_name}"
                        save_func(results, filepath)
                    except Exception as e:
                        self.logger.error(f"Error saving {format_name} results: {str(e)}")
                        self.config_manager.update_state(
                            error_count=state.error_count + 1
                        )
                else:
                    self.logger.warning(f"Unsupported export format: {format_name}")
            
            self.logger.info(f"Results saved to {output_dir}")
            
        except Exception as e:
            self.logger.error(f"Error saving results: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _save_json_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in JSON format."""
        # File opening/IO errors handled by _open_file
        with self._open_file(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        self.logger.debug(f"Saved JSON results to {filepath}")

    def _save_csv_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in CSV format."""
        # File opening/IO errors handled by _open_file
        with self._open_file(filepath, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Port', 'Status'])
            for port in results['open_ports']:
                writer.writerow([port, 'Open'])
            for port in results['closed_ports']:
                writer.writerow([port, 'Closed'])
            for port in results['filtered_ports']:
                writer.writerow([port, 'Filtered'])
            for port in results['error_ports']:
                writer.writerow([port, 'Error'])
        self.logger.debug(f"Saved CSV results to {filepath}")

    def _save_html_results(self, results: Dict[str, Any], filepath: Path) -> None:
        """Save results in HTML format."""
        # File opening/IO errors handled by _open_file
        html_template = """<!DOCTYPE html>
<html>
<head>
    <title>GateKeeper Scan Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
        .open { color: green; }
        .closed { color: red; }
        .filtered { color: orange; }
        .error { color: gray; }
    </style>
</head>
<body>
    <h1>GateKeeper Scan Results</h1>
    <p>Target: {target}</p>
    <p>Scan ID: {scan_id}</p>
    <p>Start Time: {start_time}</p>
    <p>End Time: {end_time}</p>
    
    <h2>Port Status</h2>
    <table>
        <tr><th>Port</th><th>Status</th></tr>
        {port_rows}
    </table>
</body>
</html>
"""
        # Generate table rows for each port
        port_rows = []
        for port in results['open_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="open">Open</td></tr>')
        for port in results['closed_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="closed">Closed</td></tr>')
        for port in results['filtered_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="filtered">Filtered</td></tr>')
        for port in results['error_ports']:
            port_rows.append(f'<tr><td>{port}</td><td class="error">Error</td></tr>')
        
        # Format the template with data
        html_content = html_template.format(
            target=html.escape(results["target"]),
            scan_id=html.escape(results["scan_id"]),
            start_time=html.escape(results["start_time"]),
            end_time=html.escape(results["end_time"]),
            port_rows="\n        ".join(port_rows)
        )
        
        # Write to file
        with self._open_file(filepath, 'w') as f:
            f.write(html_content)
        
        self.logger.debug(f"Saved HTML results to {filepath}")

    def compare_reports(self, report1: str, report2: str) -> None:
        """Compare two scan reports."""
        # config = self.config_manager.config # Unused
        state = self.config_manager.state
        
        try:
            report1_path = Path(report1)
            report2_path = Path(report2)
            
            if not report1_path.exists():
                self.logger.error(f"Report file does not exist: {report1_path}")
                self.config_manager.update_state(error_count=state.error_count + 1)
                return
            if not report2_path.exists():
                self.logger.error(f"Report file does not exist: {report2_path}")
                self.config_manager.update_state(error_count=state.error_count + 1)
                return
            
            # Read report contents. _read_file logs errors and returns None on failure.
            report1_content = self._read_file(report1_path)
            if report1_content is None:
                # Error already logged by _read_file. No need to log again.
                return

            report2_content = self._read_file(report2_path)
            if report2_content is None:
                # Error already logged by _read_file.
                return
            
            # Parse JSON data
            try:
                report1_data = json.loads(report1_content)
                report2_data = json.loads(report2_content)
            except json.JSONDecodeError as je:
                self.logger.error(f"Error parsing JSON from one or both reports: {str(je)}")
                # It might be useful to indicate which file failed if we parse them separately
                # For now, a general message. Both files must be valid JSON to compare.
                self.config_manager.update_state(error_count=state.error_count + 1)
                return

            # Compare the reports using the ReportComparer instance
            differences = self.report_comparer.compare_reports(report1_data, report2_data)
            
            # Display the differences
            if differences:
                self.logger.info("Report differences found:")
                for diff in differences:
                    self.logger.info(f"- {diff}")
            else:
                self.logger.info("No differences found between reports")
            
        except Exception as e:
            # Catch any other unexpected errors during the comparison process
            self.logger.error(f"Error comparing reports: {str(e)}")
            self.config_manager.update_state(error_count=state.error_count + 1)
            # No explicit return here, so it implicitly returns None on such an error.

    def list_available_reports(self) -> None:
        """List available scan reports."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            # Get the reports directory
            reports_dir = Path(config.output_dir)
            if not reports_dir.exists():
                self.logger.error("Reports directory does not exist")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            # List all report files
            report_files = []
            for ext in ['.json', '.csv', '.html']:
                report_files.extend(reports_dir.glob(f'*{ext}'))
            
            if not report_files:
                self.logger.info("No reports found")
                return
            
            # Display the reports
            self.logger.info("Available reports:")
            for report in sorted(report_files):
                self.logger.info(f"- {report.name}")
        
        except Exception as e:
            self.logger.error(f"Error listing reports: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    def analyze_port_behavior(self, report_file: str) -> None:
        """Analyze port behavior from a scan report."""
        # config = self.config_manager.config # Unused
        state = self.config_manager.state
        
        try:
            report_path = Path(report_file)
            if not report_path.exists():
                self.logger.error(f"Report file not found: {report_file}")
                self.config_manager.update_state(error_count=state.error_count + 1)
                return
            
            # Read report content. _read_file logs errors and returns None on failure.
            report_content = self._read_file(report_path)
            if report_content is None:
                # Error already logged by _read_file.
                return
            
            # Parse JSON data
            try:
                report_data = json.loads(report_content)
            except json.JSONDecodeError as je:
                self.logger.error(f"Error parsing JSON from report '{report_file}': {str(je)}")
                self.config_manager.update_state(error_count=state.error_count + 1)
                return
            
            # Analyze port behavior using the PortBehaviorAnalyzer instance
            analysis = self.port_analyzer.analyze(report_data)
            
            # Display the analysis
            if analysis:
                self.logger.info("Port behavior analysis:")
                for item in analysis:
                    self.logger.info(f"- {item}")
            else:
                self.logger.info("No significant port behavior patterns found")
            
        except Exception as e:
            # Catch any other unexpected errors during the analysis process
            self.logger.error(f"Error analyzing port behavior for '{report_file}': {str(e)}")
            self.config_manager.update_state(error_count=state.error_count + 1)
            # Implicitly returns None on such an error.

    def _validate_port(self, port: int, context: str = None) -> None:
        """Validate a port number."""
        # config = self.config_manager.config # Unused variable
        state = self.config_manager.state
        
        try:
            if not isinstance(port, int):
                raise ValueError(f"Port must be an integer, got {type(port)}")
            
            # Use chained comparison for range check
            if not 1 <= port <= 65535:
                raise ValueError(f"Port must be between 1 and 65535, got {port}")
            
            # Check if port is in restricted range
            if port < 1024:
                self.logger.warning(f"Port {port} is in the restricted range (1-1023)")
                self.config_manager.update_state(
                    warning_count=state.warning_count + 1
                )
            
        except ValueError as e: # Catch ValueError specifically
            error_msg = f"Invalid port {port}"
            if context:
                error_msg += f" in {context}"
            self.logger.error(f"{error_msg}: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _parse_port_range(self, range_str: str) -> List[int]:
        """
        Parse a port range string (e.g., '1-100') into a list of port numbers.
        
        Args:
            range_str: Port range string in the format 'start-end'
            
        Returns:
            List of port numbers in the range
        
        Raises:
            ValueError: If the range is invalid
        """
        ports = []
        start, end = map(int, range_str.split('-'))
        if start > end:
            raise ValueError(f"Invalid port range: {start}-{end}")
        for port in range(start, end + 1):
            self._validate_port(port, f"range {start}-{end}")
            ports.append(port)
        return ports

    def parse_ports(self, ports: str) -> List[int]:
        """
        Parse a string of ports into a list of integers.
        
        Supports individual ports (e.g., '80') and port ranges (e.g., '1-100').
        Multiple ports or ranges can be separated by commas.
        
        Args:
            ports: String representation of ports (e.g., '22,80,443,1000-1100')
            
        Returns:
            List of unique, sorted port numbers
            
        Raises:
            ValueError: If any port is invalid or out of range
        """
        # config = self.config_manager.config # Not used
        # state = self.config_manager.state # Not used directly here for ValueError handling
        
        parsed_ports = []
        try:
            # Split by commas and process each part
            for part in ports.split(','):
                part = part.strip()
                if not part: # Skip empty parts resulting from trailing commas etc.
                    continue 
                if '-' in part:
                    # Handle port range
                    # _parse_port_range will call _validate_port which handles logging/state for ValueError
                    parsed_ports.extend(self._parse_port_range(part))
                else:
                    # Handle single port
                    port_num = int(part) # Can raise ValueError if not an int
                    # _validate_port handles logging/state for its own ValueErrors
                    self._validate_port(port_num)
                    parsed_ports.append(port_num)
            
            # Remove duplicates and sort
            result = sorted(set(parsed_ports))
            
            # Update configuration (Consider if this update is desired here)
            # self.config_manager.update_config(ports=result)
            
            return result
            
        except ValueError:
            # ValueErrors from int(), _parse_port_range, or _validate_port are already
            # logged and state updated by _validate_port (if applicable for port value errors).
            # Simply re-raise. The initial int() conversion error won't be logged by helpers,
            # but the top-level handler in main() or scan_target() will catch it.
            raise
        except Exception as e:
            # Catch unexpected errors during parsing
            # This remains to catch other non-ValueError exceptions during the process.
            self.logger.error(f"Unexpected error parsing ports ('{ports}'): {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1 # Use self.config_manager.state here
            )
            raise # Re-raise after logging

    def _load_and_apply_sub_config(self, item_name: Optional[str], load_func: callable, item_type_name: str, 
                                       failure_return_value: Any = None) -> Optional[Dict]:
        """Helper to load, validate, and apply sub-configurations (policies/groups)."""
        config = self.config_manager.config
        state = self.config_manager.state

        if not item_name:
            return None # Return None if no name provided, indicating nothing was loaded

        try:
            loaded_config = load_func(item_name)

            if not loaded_config:
                self.logger.error(f"{item_type_name} not found or is empty: {item_name}")
                self.config_manager.update_state(error_count=state.error_count + 1)
                # Return the specific failure value directly instead of raising
                return failure_return_value
            
            # Update main configuration with loaded settings
            self.config_manager.update_config(**loaded_config)
            self.logger.info(f"Loaded {item_type_name.lower()}: {item_name}")
            return loaded_config # Return the loaded config dict

        # except ValueError as ve: # No longer need to catch ValueError raised above
        #     # Already logged, just re-raise or return failure value
        #     raise ve 
        except Exception as e:
            # Catch other exceptions during load_func or update_config
            self.logger.error(f"Error loading {item_type_name.lower()} {item_name}: {str(e)}")
            self.config_manager.update_state(error_count=state.error_count + 1)
            raise # Re-raise other exceptions

    def _load_scan_policy(self, policy_name: str) -> None:
        """Load a scan policy using the helper method."""
        # Error handling for loading/applying is now within the helper or propagates
        self._load_and_apply_sub_config(
            item_name=policy_name, 
            load_func=self.policy_manager.load_policy, 
            item_type_name="Policy",
            failure_return_value=None # Policy helper returns None on failure
        )
        # No need to catch ValueError for item not found here anymore
        # Let other exceptions propagate up

    def _load_target_group(self, group_name: str) -> Tuple[Optional[str], List[int]]:
        """Load a target group using the helper method."""
        # Error handling for loading/applying is now within the helper or propagates
        loaded_config = self._load_and_apply_sub_config(
            item_name=group_name, 
            load_func=self.target_groups.load_group, 
            item_type_name="Group",
            failure_return_value=None # Use None as failure marker; caller checks
        )
        
        if loaded_config: # Check if helper returned a valid config (not None)
            return loaded_config.get('target'), loaded_config.get('ports', [])
        else:
            # Helper returned failure_return_value (None); return the expected failure tuple
            return None, []
        # No need to catch ValueError for item not found here anymore
        # Let other exceptions propagate up

    def scan_target(self, target: str, ports: List[int], threads: int = 100, timeout: float = 1.0,
                   scan_type: str = "tcp", policy_name: Optional[str] = None,
                   group_name: Optional[str] = None) -> Dict[str, Any]:
        """Scan a target for open ports."""
        try:
            # Update configuration first
            self.config_manager.update_config(
                target=target,
                ports=ports,
                threads=threads,
                timeout=timeout,
                scan_type=scan_type
            )
            
            # Validate configuration from ConfigManager
            if not self.config_manager.validate_target(self.config_manager.config.target):
                 # Use the value from config for validation
                raise ValueError(f"Invalid target: {self.config_manager.config.target}")
            if not self.config_manager.validate_ports(self.config_manager.config.ports):
                raise ValueError("Invalid port configuration")
            
            # Load policy if specified (modifies config)
            if policy_name:
                self._load_scan_policy(policy_name)
            
            # Load target group if specified (modifies config)
            if group_name:
                group_config = self.target_groups.load_group(group_name)
                if group_config: # Check if group was loaded successfully
                    self.config_manager.update_config(**group_config)
            
            # Initialize scan state (uses current config)
            self.config_manager.update_state(
                start_time=datetime.now(),
                scan_id=f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
                status="running"
            )
            
            # Display start banner (use config values)
            display_scan_start(self.config_manager.config.target, self.config_manager.config.ports)
            self.logger.info(f"Starting scan of {self.config_manager.config.target} on ports {self.config_manager.config.ports}")
            
            # Perform the scan (uses config values)
            results = self._perform_scan()
            
            # Update scan state with results
            self.config_manager.update_state(
                end_time=datetime.now(),
                results=results,
                status="completed"
            )
            
            # Save results
            self._save_results(results)
            
            # Process notifications
            self._process_notifications(results)
            
            display_scan_complete()
            self.logger.info("Scan completed successfully")
            
            return results
            
        except Exception as e:
            # Centralized error handling for the entire scan process
            self.config_manager.update_state(
                status="failed",
                # Increment error count safely
                error_count=getattr(self.config_manager.state, 'error_count', 0) + 1 
            )
            # Log the exception causing the scan failure
            self.logger.exception(f"Scan failed for target '{target}': {str(e)}") 
            raise # Re-raise the exception so the caller knows the scan failed

    def _perform_scan(self) -> Dict[str, Any]:
        """Perform the actual port scan."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        open_ports = []
        closed_ports = []
        filtered_ports = []
        error_ports = []
        total_ports = len(config.ports)
        completed_count = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=config.threads) as executor:
            if not config.ports: # Handle case with no ports to scan
                self.logger.warning("No ports specified for scan.")
                # Return early with empty results, potentially update state?
                # For now, just return empty results consistent with no work done.
                return {
                    "target": config.target,
                    "scan_id": state.scan_id,
                    "start_time": state.start_time.isoformat() if state.start_time else None,
                    "end_time": datetime.now().isoformat(),
                    "open_ports": [], "closed_ports": [], "filtered_ports": [], "error_ports": [],
                    "scan_type": config.scan_type, "threads": config.threads, "timeout": config.timeout
                }

            future_to_port = {
                executor.submit(
                    self._scan_port,
                    config.target,
                    port,
                    config.timeout,
                    config.scan_type
                ): port for port in config.ports
            }
            
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    is_open, error = future.result()
                    if is_open:
                        open_ports.append(port)
                    elif error:
                        filtered_ports.append(port)
                        self.logger.debug(f"Port {port} filtered: {error}")
                    else:
                        closed_ports.append(port)
                except Exception as e:
                    self.logger.error(f"Error scanning port {port}: {str(e)}")
                    error_ports.append(port)
                    self.config_manager.update_state(
                        error_count=state.error_count + 1
                    )
                finally:
                    # Increment completed count regardless of outcome
                    completed_count += 1
                    # Update progress using the count
                    if total_ports > 0:
                        progress = completed_count / total_ports
                        self.config_manager.update_state(progress=progress)
        
        return {
            "target": config.target,
            "scan_id": state.scan_id,
            "start_time": state.start_time.isoformat() if state.start_time else None, # Handle potential None
            "end_time": datetime.now().isoformat(),
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "error_ports": error_ports,
            "scan_type": config.scan_type,
            "threads": config.threads,
            "timeout": config.timeout
        }

    def _process_notifications(self, scan_results: Dict[str, Any]) -> None:
        """Process notifications based on scan results."""
        config = self.config_manager.config
        state = self.config_manager.state
        
        try:
            if not self.notification_manager:
                self.logger.error("Notification manager not initialized")
                return
            
            # Process notifications - this will check rules and send notifications
            notification_results = self.notification_manager.process_scan_results(scan_results)
            
            # Log notification results
            for result in notification_results:
                if result.get('success'):
                    self.logger.info(f"Notification sent: {result.get('message')}")
            else:
                    self.logger.error(f"Notification failed: {result.get('error')}")
                    self.config_manager.update_state(
                        error_count=state.error_count + 1
                    )
        
        except Exception as e:
            self.logger.error(f"Error processing notifications: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )

    @contextlib.contextmanager
    def _open_file(self, filepath: Union[str, Path], mode: str = 'r', **kwargs) -> Iterator[Union[TextIO, BinaryIO]]:
        """Context manager for file operations."""
        filepath = Path(filepath)
        try:
            # Create parent directories for write operations
            if 'w' in mode or 'a' in mode:
                filepath.parent.mkdir(parents=True, exist_ok=True)
            
            # Open the file
            with open(filepath, mode, **kwargs) as f:
                yield f
                
        except FileNotFoundError:
            self.logger.error(f"File not found: {filepath}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise
        except PermissionError:
            self.logger.error(f"Permission denied: {filepath}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise
        except IOError as e:
            self.logger.error(f"IO error: {str(e)}")
            self.config_manager.update_state(
                error_count=self.config_manager.state.error_count + 1
            )
            raise

    def _read_file(self, filepath: Union[str, Path], binary: bool = False) -> Union[str, bytes, None]:
        """Read a file's contents."""
        # Error handling for file opening is handled by _open_file context manager
        try:
            mode = 'rb' if binary else 'r'
            with self._open_file(filepath, mode) as f:
                # Handle potential errors during the read operation itself, though less common
                try:
                    return f.read()
                except Exception as e:
                    self.logger.error(f"Error during read operation for {filepath}: {str(e)}")
                    self.config_manager.update_state(
                        error_count=self.config_manager.state.error_count + 1
                    )
                    return None
        except Exception:
            # Errors during _open_file (e.g., FileNotFoundError) are already logged
            # and handled there. We just return None as per the original logic's failure case.
            return None

    def _write_file(self, filepath: Union[str, Path], content: Union[str, bytes], binary: bool = False) -> bool:
        """Write content to a file."""
        # Error handling for file opening is handled by _open_file context manager
        try:
            mode = 'wb' if binary else 'w'
            with self._open_file(filepath, mode) as f:
                # Handle potential errors during the write operation itself
                try:
                    f.write(content)
                    return True
                except Exception as e:
                    self.logger.error(f"Error during write operation for {filepath}: {str(e)}")
                    self.config_manager.update_state(
                        error_count=self.config_manager.state.error_count + 1
                    )
                    return False
        except Exception:
            # Errors during _open_file are already logged and handled there.
            # Return False as per the original logic's failure case.
            return False

    def _configure_notifications(self, config: Dict[str, Any]) -> None:
        """Configure notifications."""
        state = self.config_manager.state
        
        try:
            if not config:
                return
            
            # Update notification configuration
            self.config_manager.update_config(notification_config=config)
            
            # Initialize notification manager
            self.notification_manager = get_notification_manager()
            if not self.notification_manager:
                self.logger.error("Failed to initialize notification manager")
                self.config_manager.update_state(
                    error_count=state.error_count + 1
                )
                return
            
            self.logger.info("Configured notifications")
            
        except Exception as e:
            self.logger.error(f"Error configuring notifications: {str(e)}")
            self.config_manager.update_state(
                error_count=state.error_count + 1
            )
            raise

    def _handle_scan_command(self, args: argparse.Namespace) -> None:
        """Handle the 'scan' command."""
        ports = self.parse_ports(args.ports)
        self.scan_target(
            target=args.target,
            ports=ports,
            threads=args.threads,
            timeout=args.timeout,
            scan_type=args.scan_type,
            policy_name=args.policy,
            group_name=args.group
            # TODO: Add notification handling based on args.notify?
        )

    def _handle_policies_command(self, args: argparse.Namespace) -> None:
        """Handle the 'policies' command and its subcommands."""
        if args.policies_command == "list":
            self.policy_manager.list_policies()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_groups_command(self, args: argparse.Namespace) -> None:
        """Handle the 'groups' command and its subcommands."""
        if args.groups_command == "list":
            self.target_groups.list_groups()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_reports_command(self, args: argparse.Namespace) -> None:
        """Handle the 'reports' command and its subcommands."""
        if args.reports_command == "list":
            self.list_available_reports()
        # No else needed: argparse handles invalid/missing subcommands due to required=True

    def _handle_compare_command(self, args: argparse.Namespace) -> None:
        """Handle the 'compare' command."""
        self.compare_reports(args.report1, args.report2)

    def _handle_analyze_command(self, args: argparse.Namespace) -> None:
        """Handle the 'analyze' command."""
        self.analyze_port_behavior(args.report)

    def main(self) -> None:
        """Main entry point for the GateKeeper application."""
        parser = argparse.ArgumentParser(description='GateKeeper Network Security Scanner')
        # Make command required by argparse itself
        subparsers = parser.add_subparsers(dest='command', help='Available commands', required=True)

        # Scan command
        scan_parser = subparsers.add_parser('scan', help='Run a network scan')
        scan_parser.add_argument('target', help='Target IP address or hostname')
        scan_parser.add_argument('ports', help='Port range or list (e.g., 80,443 or 1-1000)')
        scan_parser.add_argument('--threads', type=int, default=100, help='Number of concurrent threads')
        scan_parser.add_argument('--timeout', type=float, default=1.0, help='Connection timeout in seconds')
        scan_parser.add_argument('--scan-type', choices=['tcp', 'udp'], default='tcp', help='Scan type')
        scan_parser.add_argument('--policy', help='Scan policy name')
        scan_parser.add_argument('--group', help='Target group name')
        scan_parser.add_argument('--notify', action='store_true', help='Send notifications')
        
        # Policies command
        # Make subcommand required by argparse itself
        policies_parser = subparsers.add_parser('policies', help='Manage scan policies')
        policies_subparsers = policies_parser.add_subparsers(dest='policies_command', help='Policy subcommands', required=True)
        policies_subparsers.add_parser('list', help='List available policies')

        # Groups command
        # Make subcommand required by argparse itself
        groups_parser = subparsers.add_parser('groups', help='Manage target groups')
        groups_subparsers = groups_parser.add_subparsers(dest='groups_command', help='Group subcommands', required=True)
        groups_subparsers.add_parser('list', help='List available groups')

        # Reports command
        # Make subcommand required by argparse itself
        reports_parser = subparsers.add_parser('reports', help='Manage scan reports')
        reports_subparsers = reports_parser.add_subparsers(dest='reports_command', help='Report subcommands', required=True)
        reports_subparsers.add_parser('list', help='List available reports')

        # Compare command
        compare_parser = subparsers.add_parser('compare', help='Compare scan reports')
        compare_parser.add_argument('report1', help='First report file')
        compare_parser.add_argument('report2', help='Second report file')

        # Analyze command
        analyze_parser = subparsers.add_parser('analyze', help='Analyze port behavior')
        analyze_parser.add_argument('report', help='Report file to analyze')
        # --- End of argument definitions ---

        args = parser.parse_args()

        # Map command names to handler methods
        command_handlers = {
            "scan": self._handle_scan_command,
            "policies": self._handle_policies_command,
            "groups": self._handle_groups_command,
            "reports": self._handle_reports_command,
            "compare": self._handle_compare_command,
            "analyze": self._handle_analyze_command,
        }

        try:
            # Get the handler function from the dictionary
            # Argparse with required=True ensures command is valid and in the dict
            handler = command_handlers[args.command] # Use direct access as key is guaranteed

            # Execute the command handler
            handler(args)

        except Exception as e:
            # Use logger if possible, otherwise print
            log_message = f"Error executing command '{args.command}': {str(e)}"
            try:
                # Check if logger was initialized (might fail early in __init__)
                if hasattr(self, 'logger') and self.logger:
                    # Log exception with traceback for debugging
                    self.logger.exception(log_message)
                else:
                    print(log_message, file=sys.stderr)
            except Exception:
                 # Fallback print if logging fails
                 print(log_message, file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    gatekeeper_instance = GateKeeper()
    gatekeeper_instance.main()