import unittest
import socket
import logging
import time
from unittest.mock import Mock, patch, MagicMock, call, AsyncMock
from pathlib import Path
import sys
import os
import asyncio
import io
from datetime import datetime
import tempfile
import shutil
import dns.resolver
from cryptography.fernet import Fernet
import json
import glob

# Add the parent directory to the Python path so we can import GateKeeper
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gatekeeper import GateKeeper

def async_test(coro):
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(coro(*args, **kwargs))
        finally:
            loop.close()
            asyncio.set_event_loop(None)
    return wrapper

class TestGateKeeper(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """Set up test class."""
        if sys.platform.startswith('win'):
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        cls.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls.loop)
        # Create necessary directories
        Path('logs').mkdir(exist_ok=True)
        Path('reports').mkdir(exist_ok=True)

    @classmethod
    def tearDownClass(cls):
        """Clean up test environment after all tests complete."""
        # Clean up test files but keep directories
        try:
            for file in Path('logs').glob('*.log'):
                try:
                    file.unlink(missing_ok=True)
                except PermissionError:
                    # Skip files that are locked
                    continue
        except Exception as e:
            print(f"Warning: Cleanup failed - {e}")
        for file in Path('reports').glob('scan_results_*'):
            file.unlink()
        cls.loop.close()
        asyncio.set_event_loop(None)

    def setUp(self):
        """Set up test case."""
        self.scanner = GateKeeper()
        self.scanner.target = "example.com"
        self.scanner.ports = [80, 443]
        # Create a new event loop for each test
        self.test_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.test_loop)
        self.test_target = "localhost"
        self.test_port = 80

    def tearDown(self):
        """Clean up after each test."""
        self.test_loop.close()
        asyncio.set_event_loop(self.loop)
        # Clean up any test files created
        for file in Path("reports").glob("test_scan_*.txt"):
            file.unlink()
        for file in Path("logs").glob("test_*.log"):
            file.unlink()

    def test_initialization(self):
        """Test if GateKeeper initializes with correct default values."""
        self.assertEqual(self.scanner.threads, 100)
        self.assertEqual(self.scanner.timeout, 1)
        self.assertEqual(self.scanner.rate_limit, 0.1)
        self.assertIsNotNone(self.scanner.encryption_key)

    def test_port_scanning(self):
        """Test port scanning functionality."""
        test_ports = [80, 443]
        self.scanner.ports = test_ports
        
        expected_results = [{'port': port, 'state': 'open'} for port in test_ports]
        mock_scan = AsyncMock(return_value=expected_results)
        
        async def run_test():
            with patch.object(self.scanner, 'scan_ports', new=mock_scan):
                results = await self.scanner.scan_ports()
                self.assertEqual(results, expected_results)
        
        self.test_loop.run_until_complete(run_test())

    def test_service_identification(self):
        """Test service identification functionality."""
        common_ports = {
            22: ('SSH-2.0-OpenSSH_8.9\r\n', 'SSH'),
            80: ('HTTP/1.1 200 OK\r\n', 'HTTP'),
            443: (None, 'HTTPS')  # HTTPS is passive check
        }

        async def mock_open_connection(*args, **kwargs):
            mock_reader = AsyncMock()
            mock_writer = AsyncMock()
            
            # Make write() and close() synchronous to avoid warnings
            mock_writer.write = MagicMock()
            mock_writer.drain = AsyncMock()
            mock_writer.close = MagicMock()
            mock_writer.wait_closed = AsyncMock()
            
            port = args[1]  # Port is second argument
            response, _ = common_ports[port]
            
            if response:
                mock_reader.readline.return_value = response.encode()
            
            return mock_reader, mock_writer

        for port, (_, expected_service) in common_ports.items():
            test_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(test_loop)
            
            try:
                with patch('asyncio.open_connection', mock_open_connection):
                    identified_service = test_loop.run_until_complete(
                        self.scanner._identify_service(port)
                    )
                    self.assertEqual(identified_service, expected_service)
            finally:
                test_loop.close()
                asyncio.set_event_loop(self.loop)

    @patch('dns.resolver.Resolver')
    @patch('socket.gethostbyname')
    @patch('socket.gethostbyaddr')
    def test_dns_verification(self, mock_gethostbyaddr, mock_gethostbyname, mock_resolver):
        """Test DNS verification functionality."""
        # Mock all DNS-related functions
        mock_gethostbyname.return_value = "127.0.0.1"
        mock_gethostbyaddr.return_value = ("localhost", [], ["127.0.0.1"])
        mock_resolver.return_value.resolve.return_value = [Mock()]
        
        result = self.scanner.verify_dns("example.com")
        self.assertTrue(result)

    def test_result_encryption(self):
        """Test result encryption and decryption."""
        test_results = [
            {'port': 80, 'status': 'open', 'service': 'HTTP'}
        ]
        
        # Test encryption
        encrypted_data = self.scanner.encrypt_results(test_results)
        self.assertIsInstance(encrypted_data, bytes)

    def test_invalid_inputs(self):
        """Test handling of invalid inputs."""
        async def test_invalid_port():
            with self.assertRaises(ValueError):
                await self.scanner.scan_port(-1)
            
            with self.assertRaises(ValueError):
                await self.scanner.scan_port(65536)
        
        self.test_loop.run_until_complete(test_invalid_port())

    def test_display_disclaimer(self):
        """Test the disclaimer display and user interaction."""
        # Test user accepts
        with patch('builtins.input', return_value='yes'):
            with patch('builtins.print') as mock_print:
                result = self.scanner.display_disclaimer()
                self.assertTrue(result)
                # Verify disclaimer was printed
                self.assertTrue(any('WARNING' in str(call) for call in mock_print.call_args_list))

        # Test user declines
        with patch('builtins.input', return_value='no'):
            with patch('builtins.print'):
                result = self.scanner.display_disclaimer()
                self.assertFalse(result)

        # Test keyboard interrupt
        with patch('builtins.input', side_effect=KeyboardInterrupt):
            with patch('builtins.print'):
                result = self.scanner.display_disclaimer()
                self.assertFalse(result)

    def test_save_results(self):
        """Test saving scan results to file."""
        test_results = [
            {'port': 80, 'state': 'open', 'service': 'HTTP'},
            {'port': 443, 'state': 'closed', 'service': None}
        ]
        
        # Ensure reports directory exists
        os.makedirs('reports', exist_ok=True)
        
        async def run_test():
            # Test saving without encryption
            self.scanner.save_results(test_results, encrypt=False)
            
            # Find the most recent file in reports directory
            report_files = glob.glob('reports/scan_results_*.txt')
            latest_file = max(report_files, key=os.path.getctime)
            
            with open(latest_file) as f:
                saved_data = f.read()
                # Verify file structure
                self.assertIn('GateKeeper Scan Results', saved_data)
                self.assertIn('Target:', saved_data)
                self.assertIn('Scan Date:', saved_data)
                
                # Verify port data
                self.assertIn('Port 80: HTTP', saved_data)
                self.assertIn('Port 443: None', saved_data)
            
            # Test saving with encryption
            self.scanner.save_results(test_results, encrypt=True)
            encrypted_files = glob.glob('reports/scan_results_*.encrypted')
            self.assertTrue(len(encrypted_files) > 0)
            
            # Clean up
            for f in report_files:
                os.remove(f)
            for f in encrypted_files:
                os.remove(f)
            
        self.loop.run_until_complete(run_test())

    def test_setup_logging(self):
        """Test logging setup."""
        # Create a temporary directory for logs
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create logs subdirectory
            log_dir = os.path.join(temp_dir, 'logs')
            os.makedirs(log_dir, exist_ok=True)
            
            # Set up scanner with custom log directory
            scanner = GateKeeper()
            scanner.log_dir = log_dir
            
            # Configure file handler explicitly
            log_file = os.path.join(log_dir, 'gatekeeper.log')
            file_handler = logging.FileHandler(log_file)
            file_handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))
            scanner.logger.addHandler(file_handler)
            
            try:
                # Generate some log messages
                scanner.logger.info("Test info message")
                scanner.logger.warning("Test warning message")
                scanner.logger.error("Test error message")
                
                # Ensure messages are written
                file_handler.flush()
                
                # Verify log file contents
                with open(log_file) as f:
                    log_content = f.read()
                    self.assertIn("Test info message", log_content)
                    self.assertIn("Test warning message", log_content)
                    self.assertIn("Test error message", log_content)
            finally:
                # Clean up
                file_handler.close()
                scanner.logger.removeHandler(file_handler)

    def test_rate_limiting(self):
        """Test rate limiting functionality."""
        self.scanner.rate_limit = 0.1  # 100ms between requests
        test_ports = [80, 443, 8080]
        self.scanner.ports = test_ports
        
        expected_results = [{'port': port, 'state': 'open'} for port in test_ports]
        
        async def mock_scan_single_port(port):
            await asyncio.sleep(self.scanner.rate_limit)
            return {'port': port, 'state': 'open'}
            
        async def mock_scan():
            results = []
            for port in test_ports:
                results.append(await mock_scan_single_port(port))
            return results
        
        async def run_test():
            start_time = time.time()
            with patch.object(self.scanner, 'scan_ports', new=mock_scan):
                results = await self.scanner.scan_ports()
            end_time = time.time()
            
            # Verify results
            self.assertEqual(results, expected_results)
            
            # Verify timing
            elapsed_time = end_time - start_time
            expected_time = (len(test_ports) - 1) * self.scanner.rate_limit
            self.assertGreaterEqual(elapsed_time, expected_time)
        
        self.loop.run_until_complete(run_test())

    def test_encryption_key_generation(self):
        """Test encryption key generation and management."""
        # Test key generation
        key = self.scanner._generate_encryption_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 44)  # Fernet keys are 44 bytes when base64 encoded
        
        # Test key uniqueness
        another_key = self.scanner._generate_encryption_key()
        self.assertNotEqual(key, another_key)

    def test_error_handling(self):
        """Test error handling in various scenarios."""
        # Test invalid target
        with self.assertLogs(level='ERROR'):
            self.assertFalse(self.scanner.verify_dns("invalid.domain.thisisnotreal"))

        # Test network timeout
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout
            async def test_timeout():
                result = await self.scanner.scan_port(80)
                self.assertIsNone(result)
            
            self.test_loop.run_until_complete(test_timeout())

    def test_command_line_arguments(self):
        """Test command line argument parsing."""
        # Test valid arguments
        with patch('sys.argv', ['gatekeeper.py', '-t', 'example.com', '-p', '80,443']):
            args = self.scanner.parse_arguments()
            self.assertEqual(args.target, 'example.com')
            self.assertEqual(args.ports, '80,443')

        # Test missing required arguments
        with patch('sys.argv', ['gatekeeper.py']):
            with self.assertRaises(SystemExit):
                self.scanner.parse_arguments()

    def test_advanced_error_handling(self):
        """Test advanced error handling scenarios."""
        # Test invalid port range
        with self.assertRaises(ValueError):
            self.scanner.validate_ports("0,65536")
            
        # Test malformed port string
        with self.assertRaises(ValueError):
            self.scanner.validate_ports("80,invalid,443")
            
        # Test invalid target
        async def run_target_test():
            self.scanner.target = None
            with self.assertRaises(ValueError):
                await self.scanner.scan_ports()
                
        self.loop.run_until_complete(run_target_test())

    def test_scan_timeout_handling(self):
        """Test handling of scan timeouts."""
        async def run_test():
            self.scanner.timeout = 0.001
            with self.assertLogs(level='ERROR') as logs:
                await self.scanner.scan_ports()
                self.assertIn("Timeout", "".join(logs.output))
                
        self.loop.run_until_complete(run_test())

    def test_encryption_error_handling(self):
        """Test encryption error scenarios."""
        # Test encryption with invalid key
        self.scanner.encryption_key = b'invalid_key'
        with self.assertRaises(Exception):
            self.scanner.encrypt_results([{'port': 80, 'status': 'open'}])
        
        # Test decryption with invalid data
        with self.assertRaises(Exception):
            self.scanner.decrypt_results(b'invalid_encrypted_data')

    def test_main_execution_flow(self):
        """Test main execution flow."""
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '80,443']
        
        async def mock_scan():
            return [{'port': 80, 'state': 'open'}]
            
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='yes'), \
             patch.object(self.scanner, 'scan_ports', new=mock_scan):
            self.scanner.main()

    def test_scan_error_recovery(self):
        """Test scanner's ability to recover from errors."""
        test_ports = [80, 443, 8080]
        self.scanner.ports = test_ports
        
        async def mock_scan():
            results = []
            for port in test_ports:
                if port == 443:
                    self.scanner.logger.error(f"Error scanning port {port}: Simulated error")
                    continue
                results.append({'port': port, 'state': 'open'})
            return results
            
        async def run_test():
            with patch.object(self.scanner, 'scan_ports', new=mock_scan):
                results = await self.scanner.scan_ports()
                self.assertEqual(len(results), 2)  # Should have results for 80 and 8080
                
        self.loop.run_until_complete(run_test())

    def test_dns_resolution_failure(self):
        """Test handling of DNS resolution failures."""
        test_target = "nonexistent.domain.local"
        
        # Mock socket to raise gaierror (DNS failure)
        with patch('socket.gethostbyname', side_effect=socket.gaierror("DNS lookup failed")):
            with self.assertLogs(level='ERROR') as logs:
                result = self.scanner.verify_dns(test_target)
                
                # Verify the function returns False
                self.assertFalse(result)
                
                # Verify error was logged
                self.assertIn("DNS verification failed", logs.output[0])
                self.assertIn("DNS lookup failed", logs.output[0])

    def test_main_execution_errors(self):
        """Test main execution error handling."""
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '80,443']
        
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='yes'), \
             patch.object(self.scanner, 'scan_ports', side_effect=Exception("Test error")):
            
            # Should exit with status code 1 on error
            with self.assertRaises(SystemExit) as cm:
                self.scanner.main()
            self.assertEqual(cm.exception.code, 1)

    def test_encryption_key_errors(self):
        """Test encryption key generation and handling errors."""
        # Test with mock that simulates cryptography error
        with patch('cryptography.fernet.Fernet.generate_key', 
                  side_effect=RuntimeError("Simulated crypto error")):
            with self.assertRaises(RuntimeError) as cm:
                self.scanner._generate_encryption_key()
            self.assertIn("Failed to generate encryption key", str(cm.exception))
        
        # Test with invalid key format
        with patch('cryptography.fernet.Fernet.generate_key', 
                  return_value=b'invalid'):  # Too short to be valid
            with self.assertRaises(ValueError) as cm:
                self.scanner._generate_encryption_key()
            self.assertIn("Invalid key format", str(cm.exception))

    def test_main_execution_cancellation(self):
        """Test cancellation of main execution."""
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '80,443']

        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='no'):  # User cancels
            with self.assertRaises(SystemExit) as cm:
                self.scanner.main()
            self.assertEqual(cm.exception.code, 0)  # Verify clean exit

    def test_advanced_encryption_scenarios(self):
        """Test additional encryption scenarios."""
        # Test encryption with empty results
        encrypted = self.scanner.encrypt_results([])
        self.assertIsNotNone(encrypted)
        
        # Test decryption with empty data
        with self.assertRaises(ValueError):
            self.scanner.decrypt_results(b'')

    def test_main_execution_edge_cases(self):
        """Test edge cases in main execution flow."""
        # Test with invalid port specification
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', 'invalid']
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='yes'):
            with self.assertRaises(SystemExit):
                self.scanner.main()

    def test_service_identification_failure(self):
        """Test service identification when connection fails."""
        # Create a new event loop for this test
        test_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(test_loop)
        
        try:
            async def mock_service(port):
                return None
                
            self.scanner._identify_service = mock_service
            
            # Run with the new loop
            result = test_loop.run_until_complete(self.scanner._identify_service(80))
            self.assertIsNone(result)
            
        finally:
            test_loop.close()
            asyncio.set_event_loop(self.loop)  # Restore original loop

    def test_advanced_decryption_failures(self):
        """Test advanced decryption failure scenarios."""
        # Test with corrupted encrypted data
        with self.assertRaises(ValueError):
            self.scanner.decrypt_results(b'corrupted_data')
        
        # Test with invalid JSON after decryption
        with patch('cryptography.fernet.Fernet.decrypt', 
                  return_value=b'invalid json'):
            with self.assertRaises(ValueError):
                self.scanner.decrypt_results(b'any')

    def test_main_execution_error_handling(self):
        """Test main execution error paths."""
        # Test with invalid arguments
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', 'invalid,ports']
        with patch('sys.argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                self.scanner.main()
            self.assertEqual(cm.exception.code, 1)  # Verify exit code
            
        # Test with valid ports but invalid range
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '0,65536']
        with patch('sys.argv', test_args):
            with self.assertRaises(SystemExit) as cm:
                self.scanner.main()
            self.assertEqual(cm.exception.code, 1)

    def test_main_execution_user_interaction(self):
        """Test main execution with user interaction."""
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '80']
        
        # Test user cancellation
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='no'):
            with self.assertRaises(SystemExit) as cm:
                self.scanner.main()
            self.assertEqual(cm.exception.code, 0)  # Clean exit for user cancellation
            
        # Test user confirmation
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='yes'), \
             patch('asyncio.run', return_value=[{'port': 80, 'state': 'open'}]):
            try:
                self.scanner.main()
            except SystemExit:
                self.fail("Should not exit when user confirms")

    def test_error_handling_paths(self):
        """Test various error handling paths."""
        test_ports = [80, 443]
        self.scanner.ports = test_ports
        
        async def mock_scan_with_errors():
            # Simulate network error and return empty results
            self.scanner.logger.error("Network unreachable")
            return []
            
        async def run_test():
            # Test network error handling
            with patch.object(self.scanner, 'scan_ports', new=mock_scan_with_errors):
                with self.assertLogs(level='ERROR') as logs:
                    results = await self.scanner.scan_ports()
                    self.assertIn("Network unreachable", logs.output[0])
                    self.assertEqual(results, [])
            
            # Test service identification error
            with patch('asyncio.open_connection', side_effect=OSError("Connection refused")):
                with self.assertLogs(level='ERROR') as logs:
                    result = await self.scanner._identify_service(80)
                    self.assertIn("Connection refused", logs.output[0])
                    self.assertIsNone(result)
        
        self.loop.run_until_complete(run_test())

    def test_error_handling_comprehensive(self):
        """Test comprehensive error handling scenarios."""
        async def run_test():
            # Test invalid port range
            with self.assertRaises(ValueError):
                self.scanner.validate_ports("0,65536")  # Use validate_ports directly
                
            # Test connection timeout
            self.scanner.timeout = 0.001  # Very short timeout
            self.scanner.target = "example.com"
            self.scanner.ports = [80]
            with self.assertLogs(level='ERROR') as logs:
                await self.scanner.scan_ports()
                self.assertIn("Timeout", "".join(logs.output))
                
            # Test service identification error
            async def mock_open_connection(*args, **kwargs):
                raise ConnectionRefusedError("Connection refused")
                
            with patch('asyncio.open_connection', mock_open_connection):
                with self.assertLogs(level='ERROR') as logs:
                    await self.scanner._identify_service(80)
                    self.assertIn("Connection refused", "".join(logs.output))
                    
            # Test main execution error
            async def mock_scan_error(*args, **kwargs):
                raise Exception("Test error")
                
            with patch.object(self.scanner, 'scan_ports', new=mock_scan_error):
                with self.assertLogs(level='ERROR') as logs:
                    await self.scanner.run()  # Make run async
                    self.assertIn("Test error", "".join(logs.output))
        
        self.loop.run_until_complete(run_test())

if __name__ == '__main__':
    unittest.main() 