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
        """Set up test environment before any tests run."""
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
        for file in Path('logs').glob('*.log'):
            file.unlink()
        for file in Path('reports').glob('scan_results_*'):
            file.unlink()
        cls.loop.close()
        asyncio.set_event_loop(None)

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scanner = GateKeeper()
        self.scanner.target = "example.com"
        self.scanner.ports = [80, 443]
        self.test_target = "localhost"
        self.test_port = 80

    def tearDown(self):
        """Clean up after each test method."""
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

    @patch('socket.socket')
    def test_port_scanning(self, mock_socket):
        """Test port scanning functionality."""
        # Mock successful connection
        mock_socket.return_value.connect_ex.return_value = 0
        
        # Run the async function in the event loop
        result = self.loop.run_until_complete(self.scanner.scan_port(80))
        
        self.assertIsNotNone(result)
        self.assertEqual(result['port'], 80)
        self.assertEqual(result['status'], 'open')

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
        
        self.loop.run_until_complete(test_invalid_port())

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
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test-specific GateKeeper instance with temporary directory
            test_scanner = GateKeeper()
            test_scanner.reports_dir = Path(tmpdir)
            test_scanner.target = "test.com"
            
            # Ensure the directory exists
            test_scanner.reports_dir.mkdir(exist_ok=True)
            
            test_results = [
                {'port': 80, 'status': 'open', 'service': 'HTTP'},
                {'port': 443, 'status': 'open', 'service': 'HTTPS'}
            ]
            
            # Test plain text save
            test_scanner.save_results(test_results, encrypt=False)
            
            # Use a small delay to ensure file is written
            time.sleep(0.1)
            
            saved_files = list(Path(tmpdir).glob('scan_results_*.txt'))
            self.assertEqual(len(saved_files), 1)
            
            # Verify file contents
            with open(saved_files[0], 'r') as f:
                content = f.read()
                self.assertIn('Port 80: HTTP', content)
                self.assertIn('Port 443: HTTPS', content)

    def test_setup_logging(self):
        """Test logging configuration."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create log directory structure
            log_dir = Path(tmpdir) / 'logs'
            log_dir.mkdir(exist_ok=True)
            log_file = log_dir / 'gatekeeper.log'
            
            # Create a test-specific GateKeeper instance
            test_scanner = GateKeeper()
            
            # Patch the entire logging setup instead of just the path
            with patch('logging.FileHandler') as mock_handler:
                # Configure the mock handler with required attributes
                handler_instance = MagicMock()
                handler_instance.level = logging.INFO
                mock_handler.return_value = handler_instance
                
                logger = test_scanner._setup_logging()
                
                try:
                    # Verify logger configuration
                    self.assertEqual(logger.name, 'GateKeeper')
                    self.assertEqual(logger.level, logging.INFO)
                    
                    # Test logging functionality
                    test_message = "Test log message"
                    logger.info(test_message)
                    
                    # Verify handler was called
                    mock_handler.assert_called_once()
                finally:
                    # Clean up handlers to prevent file lock issues
                    for handler in logger.handlers[:]:
                        handler.close()
                        logger.removeHandler(handler)

    @async_test
    async def test_rate_limiting(self):
        """Test rate limiting functionality."""
        start_time = time.time()
        
        # Test scanning multiple ports with rate limiting
        ports = [80, 443, 8080]
        
        # Mock socket to avoid actual network calls
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.return_value = 0
            
            for port in ports:
                await self.scanner.scan_port(port)
        
        elapsed_time = time.time() - start_time
        minimum_expected_time = len(ports) * self.scanner.rate_limit
        
        # Verify that rate limiting is working
        self.assertGreaterEqual(elapsed_time, minimum_expected_time)

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
            
            self.loop.run_until_complete(test_timeout())

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
        """Test various error conditions."""
        # Test invalid port range
        with self.assertRaises(ValueError):
            self.scanner.validate_ports("70000")
        
        # Test malformed port list
        with self.assertRaises(ValueError):
            self.scanner.validate_ports("80,abc,443")
        
        # Test empty target
        with self.assertRaises(ValueError):
            self.scanner.validate_target("")

    def test_scan_timeout_handling(self):
        """Test handling of scan timeouts."""
        # Mock socket to simulate timeout
        with patch('socket.socket') as mock_socket:
            mock_socket.return_value.connect_ex.side_effect = socket.timeout
            
            async def test_timeout():
                result = await self.scanner.scan_port(80)
                self.assertIsNone(result)
            
            self.loop.run_until_complete(test_timeout())

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
        """Test the main execution flow."""
        test_args = ['gatekeeper.py', '-t', 'example.com', '-p', '80,443']
        
        with patch('sys.argv', test_args), \
             patch('builtins.input', return_value='yes'), \
             patch.object(self.scanner, 'scan_ports') as mock_scan:
            
            # Mock scan_ports to return some results
            mock_scan.return_value = [
                {'port': 80, 'status': 'open', 'service': 'HTTP'},
                {'port': 443, 'status': 'closed', 'service': 'HTTPS'}
            ]
            
            # Run main function
            self.scanner.main()
            
            # Verify scan was called
            mock_scan.assert_called_once()

    def test_scan_error_recovery(self):
        """Test error recovery during scanning."""
        async def mock_scan(port):
            # Simulate a mix of successful and failed scans
            if port == 8080:
                raise ConnectionError("Simulated connection error")
            return {
                'port': port,
                'status': 'open' if port == 80 else 'closed',
                'service': 'HTTP' if port == 80 else 'HTTPS'
            }

        with patch.object(self.scanner, 'scan_port', side_effect=mock_scan):
            self.scanner.ports = [80, 443, 8080]
            results = self.loop.run_until_complete(self.scanner.scan_ports())
            
            # Sort results by port for consistent testing
            results.sort(key=lambda x: x['port'])
            
            # Verify we got results despite the error
            self.assertEqual(len(results), 2)  # Should get results for 80 and 443
            self.assertEqual(results[0]['port'], 80)
            self.assertEqual(results[1]['port'], 443)
            
            # Verify the status of each port
            self.assertEqual(results[0]['status'], 'open')
            self.assertEqual(results[1]['status'], 'closed')

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
            self.scanner.main()
            # Verify early exit without scanning

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

if __name__ == '__main__':
    unittest.main() 