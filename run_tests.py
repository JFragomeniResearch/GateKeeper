#!/usr/bin/env python3

import unittest
import sys
from pathlib import Path

def run_tests():
    """Run all tests and return the result."""
    # Ensure test directories exist
    for dir_name in ['reports', 'logs', 'tests/test_data']:
        Path(dir_name).mkdir(parents=True, exist_ok=True)

    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = 'tests'
    suite = loader.discover(start_dir, pattern='test_*.py')

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    success = run_tests()
    sys.exit(0 if success else 1) 