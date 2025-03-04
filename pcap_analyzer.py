#!/usr/bin/env python3
"""
PCAP Analyzer - Advanced Network Security Analysis Tool

This script serves as the command-line entry point for the pcap_analysis package.
It provides a comprehensive set of tools for analyzing PCAP files and detecting
various security threats and anomalies.

Usage:
    python pcap_analyzer.py <pcap_file> [options]

For full usage information, run:
    python pcap_analyzer.py --help
"""

import sys
import os

# Add the parent directory to the path to ensure the package can be imported
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from pcap_analysis.main import main
except ImportError:
    print("Error: Could not import pcap_analysis package.")
    print("Make sure you have all the required dependencies installed.")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

if __name__ == "__main__":
    sys.exit(main()) 