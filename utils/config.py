from typing import List, Optional, Dict, Any
from pathlib import Path
import logging
from datetime import datetime
import ipaddress
import re
from dataclasses import dataclass, field
from typing import ClassVar

@dataclass
class ScanConfig:
    """Configuration for a single scan operation."""
    target: Optional[str] = None
    ports: List[int] = field(default_factory=list)
    threads: int = 100
    timeout: float = 1.0
    scan_type: str = "tcp"
    policy_file: Optional[str] = None
    target_group: Optional[str] = None
    output_dir: str = "reports"
    export_formats: List[str] = field(default_factory=lambda: ["json", "csv", "html"])
    encryption_key: Optional[bytes] = None
    notification_config: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanState:
    """State tracking for an active scan."""
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    scan_id: Optional[str] = None
    results: Dict[str, Any] = field(default_factory=dict)
    status: str = "idle"
    progress: float = 0.0
    error_count: int = 0
    warning_count: int = 0

class ConfigManager:
    """Manages GateKeeper's configuration and state."""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.config = ScanConfig()
        self.state = ScanState()
        self._validate_paths()
        
    def _validate_paths(self) -> None:
        """Ensure required directories exist."""
        paths = [
            Path(self.config.output_dir),
            Path("logs"),
            Path("policies"),
            Path("target_groups")
        ]
        
        for path in paths:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                self.logger.debug(f"Created directory: {path}")
    
    def update_config(self, **kwargs) -> None:
        """Update configuration parameters."""
        for key, value in kwargs.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                self.logger.debug(f"Updated config {key} to {value}")
            else:
                self.logger.warning(f"Attempted to update non-existent config key: {key}")
    
    def update_state(self, **kwargs) -> None:
        """Update state parameters."""
        for key, value in kwargs.items():
            if hasattr(self.state, key):
                setattr(self.state, key, value)
                self.logger.debug(f"Updated state {key} to {value}")
            else:
                self.logger.warning(f"Attempted to update non-existent state key: {key}")
    
    def reset_state(self) -> None:
        """Reset the scan state to initial values."""
        self.state = ScanState()
        self.logger.debug("Reset scan state")
    
    def validate_target(self, target: str) -> bool:
        """Validate a target IP or hostname."""
        try:
            # Try parsing as IP address
            ipaddress.ip_address(target)
            return True
        except ValueError:
            # Not an IP, could be a hostname
            if re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', target):
                return True
            return False
    
    def validate_ports(self, ports: List[int]) -> bool:
        """Validate port numbers."""
        return all(0 < port <= 65535 for port in ports)
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get a summary of the current scan configuration and state."""
        return {
            "config": {
                k: v for k, v in self.config.__dict__.items()
                if not k.startswith('_')
            },
            "state": {
                k: v for k, v in self.state.__dict__.items()
                if not k.startswith('_')
            }
        } 