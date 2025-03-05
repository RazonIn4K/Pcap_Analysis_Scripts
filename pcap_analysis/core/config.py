#!/usr/bin/env python3
import json
import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, Optional
import secrets

logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_CONFIG = {
    "output": {
        "directory": "./output",
        "format": "json",
        "visualize": True
    },
    "analysis": {
        "max_workers": 4,
        "cache_ttl": 3600
    },
    "detection": {
        "thresholds": {
            "dns_entropy": 0.8,
            "port_scan": 10,
            "syn_flood": 100,
            "data_exfil": 1000000
        }
    },
    "reporting": {
        "max_items": 100,
        "html_template": "default"
    },
    "security": {
        "api_key_hash": None,
        "allow_remote_resources": False,
        "validate_signatures": True
    }
}

class Config:
    """Configuration manager for PCAP analyzer"""
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file (str, optional): Path to configuration file
        """
        self.config = DEFAULT_CONFIG.copy()
        
        # Load from config file if provided
        if config_file:
            self.load_from_file(config_file)
        
        # Load from environment variables
        self.load_from_env()
        
        # Generate API key hash if not present
        if not self.config["security"]["api_key_hash"]:
            self.config["security"]["api_key_hash"] = self._generate_api_key_hash()
    
    def _generate_api_key_hash(self):
        """Generate a secure API key hash."""
        return secrets.token_hex(16)
    
    def load_from_file(self, config_file: str) -> bool:
        """
        Load configuration from file.
        
        Args:
            config_file (str): Path to configuration file
            
        Returns:
            bool: True if loaded successfully
        """
        if not os.path.exists(config_file):
            logger.warning(f"Configuration file not found: {config_file}")
            return False
        
        try:
            file_ext = os.path.splitext(config_file)[1].lower()
            
            if file_ext in ('.yaml', '.yml'):
                with open(config_file, 'r') as f:
                    loaded_config = yaml.safe_load(f)
            elif file_ext == '.json':
                with open(config_file, 'r') as f:
                    loaded_config = json.load(f)
            else:
                logger.warning(f"Unsupported config file format: {file_ext}")
                return False
            
            # Validate config before applying
            if not self._validate_config(loaded_config):
                logger.warning("Invalid configuration, using defaults")
                return False
            
            # Update config with loaded values
            self._update_nested_dict(self.config, loaded_config)
            logger.info(f"Configuration loaded from {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
            return False
    
    def _validate_config(self, config):
        """
        Validate configuration structure and values.
        
        Args:
            config (dict): Configuration to validate
            
        Returns:
            bool: True if valid
        """
        # Check if it's a dictionary
        if not isinstance(config, dict):
            logger.error("Configuration must be a dictionary")
            return False
        
        # Check for required sections
        required_sections = ["output", "analysis", "detection", "reporting"]
        for section in required_sections:
            if section not in config and section in self.config:
                # Use default if missing
                config[section] = self.config[section]
        
        # Validate specific values
        if "analysis" in config and "max_workers" in config["analysis"]:
            try:
                max_workers = int(config["analysis"]["max_workers"])
                if max_workers < 1:
                    logger.warning("max_workers must be at least 1, using default")
                    config["analysis"]["max_workers"] = self.config["analysis"]["max_workers"]
            except (ValueError, TypeError):
                logger.warning("max_workers must be an integer, using default")
                config["analysis"]["max_workers"] = self.config["analysis"]["max_workers"]
        
        return True
    
    def load_from_env(self) -> None:
        """Load configuration from environment variables"""
        # Look for environment variables with prefix PCAP_
        for key, value in os.environ.items():
            if key.startswith('PCAP_'):
                # Convert PCAP_OUTPUT_DIRECTORY to ['output']['directory']
                parts = key[5:].lower().split('_')
                
                if len(parts) >= 2:
                    section = parts[0]
                    option = '_'.join(parts[1:])
                    
                    if section in self.config and option in self.config[section]:
                        # Convert value to appropriate type
                        orig_value = self.config[section][option]
                        if isinstance(orig_value, bool):
                            self.config[section][option] = value.lower() in ('true', 'yes', '1')
                        elif isinstance(orig_value, int):
                            try:
                                self.config[section][option] = int(value)
                            except ValueError:
                                pass
                        elif isinstance(orig_value, float):
                            try:
                                self.config[section][option] = float(value)
                            except ValueError:
                                pass
                        else:
                            self.config[section][option] = value
                        
                        logger.debug(f"Config from environment: {section}.{option} = {value}")
    
    def save(self, config_file: str) -> bool:
        """
        Save configuration to file.
        
        Args:
            config_file (str): Path to save configuration
            
        Returns:
            bool: True if saved successfully
        """
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(config_file)), exist_ok=True)
            
            file_ext = os.path.splitext(config_file)[1].lower()
            
            if file_ext in ('.yaml', '.yml'):
                with open(config_file, 'w') as f:
                    yaml.dump(self.config, f, default_flow_style=False)
            elif file_ext == '.json':
                with open(config_file, 'w') as f:
                    json.dump(self.config, f, indent=2)
            else:
                logger.warning(f"Unsupported config file format: {file_ext}")
                return False
            
            logger.info(f"Configuration saved to {config_file}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")
            return False
    
    def get(self, section: str, option: str, default: Any = None) -> Any:
        """
        Get configuration value.
        
        Args:
            section (str): Configuration section
            option (str): Configuration option
            default (Any, optional): Default value if not found
            
        Returns:
            Any: Configuration value
        """
        try:
            return self.config[section][option]
        except KeyError:
            return default
    
    def set(self, section: str, option: str, value: Any) -> None:
        """
        Set configuration value.
        
        Args:
            section (str): Configuration section
            option (str): Configuration option
            value (Any): Value to set
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][option] = value
    
    def _update_nested_dict(self, d: Dict, u: Dict) -> Dict:
        """
        Update nested dictionary recursively.
        
        Args:
            d (dict): Dictionary to update
            u (dict): Dictionary with updates
            
        Returns:
            dict: Updated dictionary
        """
        for k, v in u.items():
            if isinstance(v, dict) and k in d and isinstance(d[k], dict):
                d[k] = self._update_nested_dict(d[k], v)
            else:
                d[k] = v
        return d

def save_config(args, config_file):
    """Save current configuration to file"""
    with open(config_file, 'w') as f:
        json.dump(vars(args), f, indent=2)
    print(f"Configuration saved to {config_file}")

def load_config(config_file):
    """Load configuration from file"""
    if not os.path.exists(config_file):
        print(f"Error: Configuration file {config_file} not found")
        return None
        
    with open(config_file, 'r') as f:
        return json.load(f) 