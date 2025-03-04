#!/usr/bin/env python3
from ..core.command import run_command
import yaml
import os

def detect_sql_injection(pcap_file, time_filter=""):
    """Detect potential SQL injection attempts in HTTP traffic"""
    print("\n=== Potential SQL Injection Attempts ===")
    sql_patterns = run_command(
      f"tshark -r {pcap_file} -Y \"http.request.method == \\\"POST\\\" and "
      f"(http.request.uri contains \\\"%27\\\" or "
      f"http.request.uri contains \\\"SELECT\\\" or "
      f"http.request.uri contains \\\"UNION\\\" or "
      f"http.request.uri contains \\\"OR 1=1\\\" or "
      f"http.request.uri contains \\\"--\\\" or "
      f"http.request.uri contains \\\"%20OR%20\\\" or "
      f"http.request.uri contains \\\"information_schema\\\") {time_filter}\" "
      f"-T fields -e frame.number -e frame.time -e ip.src -e http.request.uri"
    )
    print(sql_patterns or "No SQL injection patterns detected")
    return sql_patterns

def detect_xss(pcap_file, time_filter=""):
    """Detect potential cross-site scripting (XSS) attempts"""
    print("\n=== Potential XSS Attacks ===")
    xss_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\"<script>\\\" or "
        f"http contains \\\"%3Cscript%3E\\\" or "
        f"http contains \\\"javascript:\\\" or "
        f"http contains \\\"onerror=\\\" or "
        f"http contains \\\"onload=\\\" or "
        f"http contains \\\"alert(\\\" or "
        f"http contains \\\"document.cookie\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    print(xss_patterns or "No XSS patterns detected")
    return xss_patterns

def detect_command_injection(pcap_file, time_filter=""):
    """Detect potential command injection attempts in HTTP traffic"""
    print("\n=== Potential Command Injection Attempts ===")
    
    cmd_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\";\\\" or "
        f"http contains \\\"|\\\" or "
        f"http contains \\\"&&\\\" or "
        f"http contains \\\"||\\\" or "
        f"http contains \\\"\\\\`\\\" or "  # Note the properly escaped backtick
        f"http contains \\\"%3B\\\" or "
        f"http contains \\\"cat /etc\\\" or "
        f"http contains \\\"ping -c\\\" or "
        f"http contains \\\"wget\\\" or "
        f"http contains \\\"curl\\\" or "
        f"http contains \\\"bash -i\\\" or "
        f"http contains \\\"nc -e\\\" or "
        f"http contains \\\"bash -c\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    
    print(cmd_patterns or "No command injection patterns detected")
    return cmd_patterns

def detect_directory_traversal(pcap_file, time_filter=""):
    """Detect potential directory traversal attempts"""
    print("\n=== Potential Directory Traversal Attempts ===")
    traversal_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\"../\\\" or "
        f"http contains \\\"%2e%2e%2f\\\" or "
        f"http contains \\\"%2e%2e/\\\" or "
        f"http contains \\\"..%2f\\\" or "
        f"http contains \\\"/etc/passwd\\\" or "
        f"http contains \\\"/etc/shadow\\\" or "
        f"http contains \\\"/proc/self/\\\" or "
        f"http contains \\\"C:\\\\Windows\\\\\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    print(traversal_patterns or "No directory traversal attempts detected")
    return traversal_patterns

def load_custom_signatures(signature_file):
    """Load custom detection signatures from file"""
    if not os.path.exists(signature_file):
        print(f"Error: Signature file {signature_file} not found")
        return None
        
    try:
        with open(signature_file, 'r') as f:
            signatures = yaml.safe_load(f)
            
        if 'signatures' not in signatures or not isinstance(signatures['signatures'], list):
            print("Error: Invalid signature format, expecting 'signatures' list")
            return None
            
        return signatures['signatures']
        
    except yaml.YAMLError as e:
        print(f"Error parsing signature file: {str(e)}")
        return None
    except Exception as e:
        print(f"Error loading signature file: {str(e)}")
        return None

def detect_custom_patterns(pcap_file, signatures, time_filter=""):
    """Detect custom patterns defined in signatures"""
    if not signatures:
        return None
        
    results = []
    
    for sig in signatures:
        name = sig.get('name', 'Unnamed signature')
        description = sig.get('description', '')
        filter_expr = sig.get('filter', '')
        fields = sig.get('fields', ['frame.number', 'ip.src', 'ip.dst'])
        severity = sig.get('severity', 'medium')
        
        if not filter_expr:
            print(f"Warning: Skipping signature '{name}' with empty filter")
            continue
            
        print(f"\n=== Custom Detection: {name} ({severity.upper()}) ===")
        print(f"Description: {description}")
        
        # Prepare fields for tshark
        fields_str = ' -e '.join(fields)
        
        # Run the custom detection
        custom_result = run_command(
            f"tshark -r {pcap_file} -Y \"{filter_expr}{time_filter}\" -T fields -e {fields_str}"
        )
        
        print(custom_result or f"No matches found for '{name}'")
        
        if custom_result:
            results.append({
                'name': name,
                'description': description,
                'severity': severity,
                'matches': custom_result
            })
    
    return results 