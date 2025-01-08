"""Test configuration settings"""

TEST_CONFIG = {
    'TEST_TARGET': 'localhost',
    'TEST_PORTS': [80, 443, 22],
    'TEST_TIMEOUT': 1,
    'TEST_THREADS': 10,
    'TEST_RATE_LIMIT': 0.1
}

# Test files and directories
TEST_DIRS = {
    'REPORTS_DIR': 'reports',
    'LOGS_DIR': 'logs',
    'TEST_DATA_DIR': 'tests/test_data'
} 