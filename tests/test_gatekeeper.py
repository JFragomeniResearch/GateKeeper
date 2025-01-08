import unittest
import socket
from unittest.mock import Mock, patch
from pathlib import Path
import sys
import os
import asyncio

# Add the parent directory to the Python path so we can import GateKeeper
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from gatekeeper import GateKeeper

class TestGateKeeper(unittest.TestCase):
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

if __name__ == '__main__':
    unittest.main() 