#!/usr/bin/env python3
import json
import os

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