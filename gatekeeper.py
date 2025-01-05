#!/usr/bin/env python3

import argparse
import socket
import sys
import concurrent.futures
from datetime import datetime
from pathlib import Path
import logging
from typing import List, Tuple
import time

class GateKeeper:
    def __init__(self):
        self.logger = self._setup_logging()
        self.start_time = None
        self.target = None
        self.ports = []
        self.threads = 100  # Default thread count
        self.timeout = 1    # Default timeout in seconds
        self.rate_limit = 0.1  # Time between connection attempts

    def _setup_logging(self) -> logging.Logger:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('gatekeeper.log'),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger('GateKeeper')

    def display_disclaimer(self):
        disclaimer = """
        WARNING: This tool is for authorized use only.
        Unauthorized network scanning is illegal and may result in civil and criminal penalties.
        By continuing, you confirm you have explicit permission to scan the target system.
        """
        print(disclaimer)
        confirm = input("Do you have authorization to scan this target? (yes/no): ")
        if confirm.lower() != 'yes':
            self.logger.error("Scan aborted due to lack of authorization")
            sys.exit(1) 