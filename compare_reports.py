#!/usr/bin/env python3
"""
GateKeeper Report Comparison Tool
A utility for comparing two GateKeeper scan reports to identify changes
in network configuration over time.

This script serves as a convenient entry point for the report comparison functionality.
"""

import sys
from utils.report_compare import main

if __name__ == "__main__":
    # Simply call the main function in the report_compare module
    main() 