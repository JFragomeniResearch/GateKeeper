import unittest
import socket
import logging
import time
from unittest.mock import Mock, patch, MagicMock, call
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

    def setUp(self):
        """Set up test fixtures before each test method."""
        self.scanner = GateKeeper()
        self.test_target = "localhost"
        self.test_port = 80
        # Set up event loop for async tests
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

    def tearDown(self):
        """Clean up after each test method."""
        # Clean up any test files created
        for file in Path("reports").glob("test_scan_*.txt"):
            file.unlink()
        for file in Path("logs").glob("test_*.log"):
            file.unlink()
        # Clean up event loop
        self.loop.close()

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
            22: 'SSH',
            80: 'HTTP',
            443: 'HTTPS'
        }
        
        for port, service in common_ports.items():
            identified_service = self.scanner._identify_service(port)
            self.assertEqual(identified_service, service)

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
            
            # Patch the log file path
            with patch('gatekeeper.Path') as mock_path:
                # Configure the mock to return our temporary path
                mock_instance = Mock()
                mock_instance.parent = log_dir
                mock_instance.__str__.return_value = str(log_dir / 'gatekeeper.log')
                mock_path.return_value = mock_instance
                
                # Create a test-specific GateKeeper instance
                test_scanner = GateKeeper()
                logger = test_scanner._setup_logging()
                
                # Verify logger configuration
                self.assertEqual(logger.name, 'GateKeeper')
                self.assertEqual(logger.level, logging.INFO)
                
                # Test logging functionality
                test_message = "Test log message"
                logger.info(test_message)

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

if __name__ == '__main__':
    unittest.main() 