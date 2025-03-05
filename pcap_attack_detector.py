#!/usr/bin/env python3

import argparse
import subprocess
import os
import re
import json
import sys
import csv
from datetime import datetime
import time
from typing import Dict, List, Tuple, Optional, Union, Any
from pcap_analysis.core.security import sanitize_filter, validate_pcap_file, sanitize_filename, sanitize_output_path

# Define DependencyError in this file instead of importing it
class DependencyError(Exception):
    """Exception raised when a dependency is missing"""
    def __init__(self, dependency: str, install_instructions: Optional[str] = None):
        self.dependency = dependency
        self.install_instructions = install_instructions
        message = f"Required dependency not found: {dependency}"
        if install_instructions:
            message += f"\n{install_instructions}"
        super().__init__(message)

# Global cache for command results
command_cache: Dict[str, Tuple[float, str]] = {}

def run_command(command: str, use_cache: bool = True) -> Optional[str]:
    """
    Execute a shell command and return its output with progress indicator.
    
    Args:
        command: The shell command to execute
        use_cache: Whether to use cached results if available
        
    Returns:
        str or None: Command output or None if error occurred
    """
    # Sanitize the command for security
    command = sanitize_filter(command)
    
    # Check cache
    current_time = time.time()
    if use_cache and command in command_cache:
        cached_time, cached_result = command_cache[command]
        return cached_result
        
    try:
        print("Running analysis...", end="\r")
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        print("                    ", end="\r")  # Clear the line
        if process.returncode != 0:
            print(f"Error running command: {stderr.decode('utf-8')}")
            return None
        result = stdout.decode('utf-8')
        
        if use_cache:
            # Store the result with timestamp - overwrite any existing cache entry
            command_cache[command] = (current_time, result)
        return result
    except Exception as e:
        print(f"Exception while running command: {e}")
        return None

def run_command_with_retry(command: str, max_retries: int = 2) -> Optional[str]:
    """
    Run a command with retries if it fails.
    
    Args:
        command: The command to execute
        max_retries: Maximum number of retry attempts
        
    Returns:
        str or None: Command output or None if all attempts failed
    """
    for attempt in range(max_retries + 1):
        result = run_command(command, use_cache=(attempt == 0))  # Only use cache on first attempt
        if result is not None:
            return result
        
        if attempt < max_retries:
            # Wait before retrying (with exponential backoff)
            retry_delay = 2 ** attempt
            print(f"Command failed, retrying in {retry_delay} seconds... (Attempt {attempt+1}/{max_retries})")
            time.sleep(retry_delay)
    
    print(f"Command failed after {max_retries} retries")
    return None

def verify_dependency(dependency_name):
    """
    Check if a required external dependency is available on the system.
    
    Args:
        dependency_name (str): Name of the dependency to check
        
    Raises:
        DependencyError: If the dependency is not found
        
    Returns:
        bool: True if dependency is available
    """
    try:
        # Platform-specific command to check for dependency
        if os.name == 'nt':  # Windows
            command = ['where', dependency_name]
        else:  # Unix/Linux/Mac
            command = ['which', dependency_name]
            
        subprocess.run(command, 
                      check=True, 
                      stdout=subprocess.PIPE, 
                      stderr=subprocess.PIPE)
        return True
    except subprocess.CalledProcessError:
        # Create platform-specific install instructions
        install_instructions = ""
        if dependency_name == "tshark":
            if os.name == 'nt':  # Windows
                install_instructions = "Install Wireshark from https://www.wireshark.org/download.html"
            elif sys.platform == 'darwin':  # macOS
                install_instructions = "Install Wireshark: brew install wireshark"
            else:  # Linux
                install_instructions = "Install Wireshark: sudo apt install wireshark or sudo yum install wireshark"
        elif dependency_name == "capinfos":
            install_instructions = "This tool is part of the Wireshark package"
        elif dependency_name in ["mergecap", "editcap"]:
            install_instructions = "This tool is part of the Wireshark package"
            
        raise DependencyError(dependency_name, install_instructions)

def detect_sql_injection(pcap_file, time_filter=""):
    """Detect potential SQL injection attempts in HTTP traffic"""
    print("\n=== Potential SQL Injection Attempts ===")
    sql_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http.request and "
        f"(http.request.uri contains \\\"%27\\\" or "
        f"http.request.uri contains \\\"SELECT\\\" or "
        f"http.request.uri contains \\\"UNION\\\" or "
        f"http.request.uri contains \\\"OR 1=1\\\" or "
        f"http.request.uri contains \\\"--\\\" or "
        f"http.request.uri contains \\\"%20OR%20\\\" or "
        f"http.request.uri contains \\\"information_schema\\\"){time_filter}\" "
        f"-T fields -e frame.number -e frame.time -e ip.src -e http.request.uri"
    )
    print(sql_patterns or "No SQL injection patterns detected")
    return sql_patterns

def detect_xss(pcap_file, time_filter=""):
    """Detect potential XSS attacks in HTTP traffic"""
    print("\n=== Potential XSS Attempts ===")
    xss_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\"<script>\\\" or "
        f"http contains \\\"%3Cscript%3E\\\" or "
        f"http contains \\\"javascript:\\\" or "
        f"http contains \\\"onerror=\\\" or "
        f"http contains \\\"onload=\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    print(xss_patterns or "No XSS patterns detected")
    return xss_patterns

def detect_brute_force(pcap_file, threshold=5, time_filter=""):
    """Detect potential brute force login attempts"""
    print("\n=== Potential Brute Force Attempts ===")
    
    # HTTP Basic Auth attempts
    http_auth = run_command(
        f"tshark -r {pcap_file} -Y \"http.authorization contains \\\"Basic\\\"{time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e http.request.uri | "
        f"sort | uniq -c | sort -nr"
    )
    print("HTTP Basic Auth attempts:")
    print(http_auth or "No HTTP Basic Auth attempts detected")
    
    # Regular POST login attempts
    login_attempts = run_command(
        f"tshark -r {pcap_file} -Y \"http.request.method==\\\"POST\\\" and http.request.uri contains \\\"login\\\"{time_filter}\" "
        f"-T fields -e ip.src -e http.request.uri | sort | uniq -c | sort -nr | head -n 20"
    )
    print("\nPOST login attempts:")
    print(login_attempts or "No suspicious login attempts detected")
    
    # SSH login attempts
    ssh_attempts = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.port==22{time_filter}\" -T fields -e ip.src -e ip.dst | "
        f"sort | uniq -c | sort -nr | head -n 10"
    )
    print("\nSSH connection attempts:")
    print(ssh_attempts or "No SSH connection attempts detected")
    
    # FTP login attempts
    ftp_attempts = run_command(
        f"tshark -r {pcap_file} -Y \"ftp.request.command==\\\"USER\\\" or ftp.request.command==\\\"PASS\\\"{time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e ftp.request"
    )
    print("\nFTP login attempts:")
    print(ftp_attempts or "No FTP login attempts detected")
    
    # LDAP authentication attempts (new)
    ldap_auth = run_command(
        f"tshark -r {pcap_file} -Y \"ldap.bindRequest{time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst | sort | uniq -c | sort -nr"
    )
    print("\nLDAP authentication attempts:")
    print(ldap_auth or "No LDAP authentication attempts detected")
    
    return {
        "http_auth": http_auth, 
        "login_attempts": login_attempts, 
        "ssh_attempts": ssh_attempts, 
        "ftp_attempts": ftp_attempts,
        "ldap_auth": ldap_auth
    }

def detect_port_scan(pcap_file, threshold=10, time_filter=""):
    """Detect potential port scanning activity"""
    print("\n=== Potential Port Scanning Activity ===")
    # Look for SYN packets to multiple ports from same source
    port_scan = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.flags.syn==1 and tcp.flags.ack==0{time_filter}\" "
        f"-T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 20"
    )
    print(port_scan or "No port scanning activity detected")
    
    # Check for sequential port access pattern
    sequential_ports = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.flags.syn==1 and tcp.flags.ack==0{time_filter}\" "
        f"-T fields -e ip.src -e ip.dst -e tcp.dstport | sort | head -n 30"
    )
    print("\n=== Sequential Port Access (Port Scan Indicator) ===")
    print(sequential_ports or "No sequential port access detected")
    
    # Analyze port scan timing (fast scan detection)
    fast_scan = run_command_with_retry(
        f"tshark -r {pcap_file} -q -z \"io,stat,0.1,\\\"tcp.flags.syn==1 and tcp.flags.ack==0{time_filter}\\\"\" | "
        f"grep -v \"0.000000\""
    )
    print("\n=== High-Rate Port Scan Detection ===")
    print(fast_scan or "No high-rate port scanning detected")
    
    return {"port_scan": port_scan, "sequential_ports": sequential_ports, "fast_scan": fast_scan}

def detect_ddos(pcap_file, time_filter=""):
    """Detect potential DDoS/DoS activity"""
    print("\n=== Potential DDoS/DoS Activity ===")
    
    # Look for high volume of traffic to same destination
    traffic_volume = run_command(
        f"tshark -r {pcap_file} -q -z conv,ip | sort -k 2nr | head -n 20"
    )
    print(traffic_volume or "No unusual traffic volume detected")
    
    # New: HTTP-based DoS detection
    http_flood = run_command(
        f"tshark -r {pcap_file} -Y \"http.request{time_filter}\" -T fields "
        f"-e ip.src -e http.request.uri | sort | uniq -c | sort -nr | head -n 15"
    )
    print("\n=== HTTP Flood Detection ===")
    print(http_flood or "No HTTP flood detected")
    
    # New: ICMP flood detection
    icmp_flood = run_command(
        f"tshark -r {pcap_file} -Y \"icmp{time_filter}\" -T fields "
        f"-e ip.src -e ip.dst | sort | uniq -c | sort -nr | head -n 15"
    )
    print("\n=== ICMP Flood Detection ===")
    print(icmp_flood or "No ICMP flood detected")
    
    return {"traffic_volume": traffic_volume, "http_flood": http_flood, "icmp_flood": icmp_flood}

def detect_syn_flood(pcap_file, threshold=100, time_filter=""):
    """Detect potential SYN flood attacks"""
    print("\n=== Potential SYN Flood Attacks ===")
    syn_flood = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.flags.syn==1 and not tcp.flags.ack==1 and "
        f"not tcp.flags.rst==1{time_filter}\" -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport | "
        f"sort | uniq -c | sort -nr | head -n 20"
    )
    print(syn_flood or "No SYN flood attacks detected")
    
    # Check for high rate of SYN packets to same destination
    high_rate_syn = run_command(
        f"tshark -r {pcap_file} -q -z \"io,stat,1,\\\"tcp.flags.syn==1 and not tcp.flags.ack==1 and not tcp.flags.rst==1\\\"{time_filter}\\\"\" | "
        f"grep -v \"1.000000\""
    )
    print("\n=== SYN Packet Rate (Possible DoS) ===")
    print(high_rate_syn or "No abnormal SYN packet rates detected")
    
    # SYN-to-host ratio analysis
    syn_ack_ratio = run_command(
        f"tshark -r {pcap_file} -q -z \"io,stat,5,\\\"tcp.flags.syn==1 and not tcp.flags.ack==1 and not tcp.flags.rst==1\\\",\\\"tcp.flags.ack==1\\\"\""
    )
    print("\n=== SYN to ACK Ratio (Flood Indicator) ===")
    print(syn_ack_ratio or "No SYN-ACK ratio data available")
    
    return {"syn_flood": syn_flood, "high_rate_syn": high_rate_syn, "syn_ack_ratio": syn_ack_ratio}

def detect_command_injection(pcap_file, time_filter=""):
    """Detect potential command injection attempts in HTTP traffic"""
    print("\n=== Potential Command Injection Attempts ===")
    
    # Look for command injection patterns
    cmd_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\";\\\" or "
        f"http contains \\\"|\\\" or "
        f"http contains \\\"&&\\\" or "
        f"http contains \\\"||\\\" or "
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
    # Look for directory traversal patterns
    traversal_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\"../\\\" or "
        f"http contains \\\"%2e%2e%2f\\\" or "
        f"http contains \\\"..%255c\\\" or "
        f"http contains \\\"/etc/passwd\\\" or "
        f"http contains \\\"/windows/system32\\\" or "
        f"http contains \\\"boot.ini\\\" or "
        f"http contains \\\"/.git/\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    print(traversal_patterns or "No directory traversal patterns detected")
    return traversal_patterns

def detect_ldap_attacks(pcap_file, time_filter=""):
    """Detect potential LDAP-related attacks"""
    print("\n=== Potential LDAP Attacks ===")
    ldap_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"ldap or tcp.port==389 or tcp.port==636{time_filter}\" "
        f"-T fields -e frame.number -e frame.time -e ip.src -e ip.dst -e ldap"
    )
    print(ldap_patterns or "No LDAP traffic detected")
    
    # LDAP injection patterns
    ldap_injection = run_command(
        f"tshark -r {pcap_file} -Y \"ldap contains \\\"*\\\" or "
        f"ldap contains \\\")\\\" or ldap contains \\\"(|\\\" or "
        f"ldap contains \\\"(&\\\"{time_filter}\" -T fields -e frame.number -e ip.src -e ldap"
    )
    print("\n=== Potential LDAP Injection Attempts ===")
    print(ldap_injection or "No LDAP injection attempts detected")
    
    # New: LDAP unauthorized binds detection
    ldap_bind_failures = run_command(
        f"tshark -r {pcap_file} -Y \"ldap.resultCode != 0 and ldap.resultCode != 14{time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e ldap.resultCode"
    )
    print("\n=== LDAP Bind Failures (Possible Attack) ===")
    print(ldap_bind_failures or "No LDAP bind failures detected")

    return {
        "ldap_traffic": ldap_patterns,
        "ldap_injection": ldap_injection,
        "ldap_bind_failures": ldap_bind_failures
    }

def detect_packet_anomalies(pcap_file, time_filter=""):
    """Detect unusual packet characteristics"""
    print("\n=== Packet Anomalies ===")
    results = {}
    
    # Find unusually large packets
    large_packets = run_command(
        f"tshark -r {pcap_file} -Y 'frame.len > 1500{time_filter}' "
        f"-T fields -e frame.number -e frame.len -e ip.src -e ip.dst | head -n 15"
    )
    print("\n-- Unusually Large Packets --")
    print(large_packets or "No unusually large packets detected")
    results["large_packets"] = large_packets
    
    # Find fragmented packets (potential evasion)
    fragmented = run_command(
        f"tshark -r {pcap_file} -Y 'ip.flags.mf == 1 or ip.frag_offset > 0{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15"
    )
    print("\n-- Fragmented Packets --")
    print(fragmented or "No fragmented packets detected")
    results["fragmented"] = fragmented
    
    # Check for TCP window size anomalies
    window_anomalies = run_command(
        f"tshark -r {pcap_file} -Y 'tcp.window_size == 0 and tcp.flags.reset == 0{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15"
    )
    print("\n-- TCP Window Size Zero (Potential DoS) --")
    print(window_anomalies or "No TCP window size anomalies detected")
    results["window_anomalies"] = window_anomalies
    
    # Unusual TTL values (possible spoofing or covert channel)
    unusual_ttl = run_command(
        f"tshark -r {pcap_file} -Y 'ip.ttl < 10 or ip.ttl > 128{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst -e ip.ttl | head -n 15"
    )
    print("\n-- Unusual TTL Values (Potential Spoofing) --")
    print(unusual_ttl or "No unusual TTL values detected")
    results["unusual_ttl"] = unusual_ttl
    
    return results

def detect_malware_traffic(pcap_file, time_filter=""):
    """Detect potential malware communication patterns"""
    print("\n=== Potential Malware Communication ===")
    results = {}
    
    # Improved malware patterns detection
    malware_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"(dns.qry.name contains \\\".bit\\\" or "
        f"dns.qry.name contains \\\".onion\\\" or dns.qry.name matches \\\"[a-zA-Z0-9]{{25,}}\\\\.(com|net|org)\\\") or "
        f"(http.user_agent contains \\\"MSIE\\\" and http.request.version != \\\"HTTP/1.1\\\") or "
        f"(tcp.flags == 0x02 and tcp.window_size <= 1024){time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e tcp.dstport"
    )
    print(malware_patterns or "No suspicious malware traffic patterns detected")
    results["malware_patterns"] = malware_patterns
    
    # Add beaconing detection
    print("\n=== Potential Beaconing (Regular Interval Communication) ===")
    beaconing = run_command(
        f"tshark -r {pcap_file} -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport "
        f"-Y \"tcp and not tcp.port==80 and not tcp.port==443{time_filter}\" | head -n 100"
    )
    print("To analyze for beaconing, export this data and check for regular time intervals")
    results["potential_beaconing"] = beaconing

    # Add DNS TXT record analysis
    txt_records = run_command(
        f"tshark -r {pcap_file} -Y \"dns.txt{time_filter}\" -T fields "
        f"-e frame.time -e ip.src -e dns.qry.name -e dns.txt"
    )
    print("\n=== DNS TXT Records (Potential C2 Channel) ===")
    print(txt_records or "No suspicious DNS TXT records found")
    results["txt_records"] = txt_records

    return results

def analyze_http_responses(pcap_file, time_filter=""):
    """Analyze HTTP response codes for potential issues"""
    print("\n=== HTTP Response Code Analysis ===")
    http_codes = run_command(
        f"tshark -r {pcap_file} -Y 'http.response.code{time_filter}' -T fields "
        f"-e frame.time -e ip.src -e http.response.code | sort | uniq -c | sort -nr"
    )
    print(http_codes or "No HTTP response codes found")
    
    # Check for error codes that might indicate successful attacks
    error_codes = run_command(
        f"tshark -r {pcap_file} -Y 'http.response.code >= 500{time_filter}' -T fields "
        f"-e frame.time -e ip.src -e ip.dst -e http.response.code -e http.request.uri"
    )
    print("\n=== Server Error Responses (Possible Successful Attacks) ===")
    print(error_codes or "No server error responses detected")
    
    # New: Response size anomalies
    large_responses = run_command(
        f"tshark -r {pcap_file} -Y 'http.response and http.content_length > 100000{time_filter}' "
        f"-T fields -e frame.time -e ip.src -e http.content_length -e http.request.uri"
    )
    print("\n=== Large HTTP Responses (Possible Data Leakage) ===")
    print(large_responses or "No unusually large HTTP responses detected")
    
    # New: Suspicious HTTP response headers
    suspicious_headers = run_command(
        f"tshark -r {pcap_file} -Y 'http.response{time_filter}' -T fields -e http.server | sort | uniq -c | sort -nr"
    )
    print("\n=== HTTP Server Headers (Fingerprinting) ===")
    print(suspicious_headers or "No HTTP server headers detected")
    
    return {
        "http_codes": http_codes, 
        "error_codes": error_codes,
        "large_responses": large_responses,
        "server_headers": suspicious_headers
    }

def analyze_application_protocols(pcap_file, time_filter=""):
    """Detailed analysis of application layer protocols"""
    results = {}
    
    # TLS cipher suites (security check)
    print("\n=== TLS Cipher Suite Analysis ===")
    tls_ciphers = run_command(
        f"tshark -r {pcap_file} -Y 'ssl.handshake.ciphersuite{time_filter}' "
        f"-T fields -e ssl.handshake.ciphersuite | sort | uniq -c | sort -nr"
    )
    print(tls_ciphers or "No TLS cipher suites found")
    results["tls_ciphers"] = tls_ciphers
    
    # TLS versions in use
    tls_versions = run_command(
        f"tshark -r {pcap_file} -Y 'ssl.handshake.version{time_filter}' "
        f"-T fields -e ssl.handshake.version | sort | uniq -c | sort -nr"
    )
    print("\n=== TLS Versions ===")
    print(tls_versions or "No TLS version information found")
    results["tls_versions"] = tls_versions
    
    # DNS query analysis
    dns_queries = run_command(
        f"tshark -r {pcap_file} -Y 'dns.qry.name{time_filter}' "
        f"-T fields -e dns.qry.name | sort | uniq -c | sort -nr | head -n 20"
    )
    print("\n=== Top DNS Queries ===")
    print(dns_queries or "No DNS queries found")
    results["dns_queries"] = dns_queries
    
    # SMB analysis
    smb_traffic = run_command(
        f"tshark -r {pcap_file} -Y 'smb or smb2{time_filter}' "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e smb.cmd -e smb2.cmd | head -n 15"
    )
    print("\n=== SMB/CIFS Traffic Analysis ===")
    print(smb_traffic or "No SMB/CIFS traffic detected")
    results["smb_traffic"] = smb_traffic
    
    return results

def verify_packets(pcap_file, frame_numbers):
    """Verify suspicious packets by examining their full content based on the frame numbers"""
    if not frame_numbers:
        return None
        
    # Convert frame_numbers list to a filter expression
    if isinstance(frame_numbers, str):
        # Extract frame numbers from output
        frames = []
        for line in frame_numbers.strip().split('\n'):
            if line.strip() and line.split()[0].isdigit():
                frames.append(line.split()[0])
        frame_numbers = frames
    
    if not frame_numbers:
        return None
    
    frame_filter = " or ".join([f"frame.number=={num}" for num in frame_numbers])
    
    # Get detailed information about the suspicious packets
    details = run_command(
        f"tshark -r {pcap_file} -Y \"{frame_filter}\" -V"
    )
    return details

def reconstruct_session(pcap_file, ip_src, ip_dst, tcp_stream_index=None):
    """Reconstruct TCP sessions between source and destination IPs"""
    print(f"\n=== TCP Session between {ip_src} and {ip_dst} ===")
    
    # First, identify the TCP stream if not provided
    if not tcp_stream_index:
        stream_cmd = f"tshark -r {pcap_file} -Y \"ip.src == {ip_src} and ip.dst == {ip_dst}\" -T fields -e tcp.stream | head -n 1"
        tcp_stream_index = run_command(stream_cmd).strip()
        
    if not tcp_stream_index:
        print("No TCP stream found between these IPs")
        return None
        
    # Reconstruct the session with content
    session = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.stream eq {tcp_stream_index}\" -T fields -e frame.time -e ip.src -e tcp.srcport -e ip.dst -e tcp.dstport -e data"
    )
    
    # Extract HTTP content if present
    http_content = run_command(
        f"tshark -r {pcap_file} -Y \"tcp.stream eq {tcp_stream_index} and http\" -T fields -e http.request.method -e http.request.uri -e data"
    )
    
    if http_content:
        print("\n-- HTTP Content in Session --")
        print(http_content)
    
    return session

def load_nmap_data(nmap_file):
    """Load service information from Nmap output file"""
    services = {}
    if not os.path.exists(nmap_file):
        return services
        
    with open(nmap_file, 'r') as f:
        current_ip = None
        for line in f:
            if "Nmap scan report for" in line:
                parts = line.split()
                current_ip = parts[-1].strip("()")
                services[current_ip] = {}
            elif current_ip and "/tcp" in line:
                parts = line.split()
                port = parts[0].split("/")[0]
                state = parts[1]
                service = parts[2] if len(parts) > 2 else "unknown"
                services[current_ip][port] = {"state": state, "service": service}
    
    return services
    
def correlate_with_services(attack_results, nmap_data):
    """Add service context to attack results"""
    if not attack_results:
        return []
        
    results = []
    
    # Process attack_results as list of dictionaries if it's a string
    if isinstance(attack_results, str):
        # Convert string output to list of dictionaries
        lines = attack_results.strip().split('\n')
        for line in lines:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 2:
                ip = parts[1] if len(parts) > 1 else "unknown"
                port = parts[2] if len(parts) > 2 else "unknown"
                result = {
                    "count": parts[0],
                    "src_ip": ip,
                    "dst_port": port
                }
                results.append(result)
    else:
        # Already a list of dictionaries
        results = attack_results
    
    # Add service context
    for result in results:
        ip = result.get("dst_ip")
        port = result.get("dst_port")
        
        if ip in nmap_data and port in nmap_data[ip]:
            result["service"] = nmap_data[ip][port]["service"]
            result["context"] = f"Attack targeting {nmap_data[ip][port]['service']} service"
            
            # Adjust severity based on service criticality
            if nmap_data[ip][port]["service"] in ["http", "https", "ftp", "ssh", "ldap"]:
                result["severity"] = "High"  # Critical services
    
    return results

def correlate_attacks(pcap_file, time_filter=""):
    """Find IPs involved in multiple types of attacks"""
    print("\n=== Correlated Attack Sources ===")
    
    # Extract all source IPs with suspicious activity
    correlation = run_command(
        f"tshark -r {pcap_file} -Y \"(http.request.uri contains \\\"%27\\\" or "
        f"http.request.uri contains \\\"SELECT\\\") or "
        f"(http contains \\\"<script>\\\") or "
        f"(http contains \\\";\\\" or http contains \\\"|\\\" or http contains \\\"&&\\\") or "
        f"(tcp.flags.syn==1 and tcp.flags.ack==0){time_filter}\" "
        f"-T fields -e ip.src | sort | uniq -c | sort -nr | head -n 15"
    )
    
    print(correlation or "No correlated attack sources found")
    return correlation

def check_threat_intel(pcap_file):
    """Compare IPs against known malicious sources"""
    print("\n=== Threat Intelligence Check ===")
    
    # Extract all unique IPs
    unique_ips = run_command(
        f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst | sort | uniq"
    )
    
    if unique_ips:
        print("Found IPs to check against threat intelligence:")
        print(unique_ips)
        print("To enhance detection, consider integrating with AbuseIPDB, VirusTotal, or AlienVault OTX APIs")
        
        # Placeholder for actual API integration
        print("For each suspicious IP, consider running:")
        print("  curl -G https://api.abuseipdb.com/api/v2/check --data-urlencode \"ipAddress=[IP]\" -H \"Key: YOUR_API_KEY\" -H \"Accept: application/json\"")
        
        # Provide example AbuseIPDB integration code
        print("\nExample integration code for AbuseIPDB:")
        print('''
def check_ip_reputation(ip_address, api_key):
    """Check IP reputation against AbuseIPDB"""
    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        querystring = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': 'true'
        }
        headers = {
            'Accept': 'application/json',
            'Key': api_key
        }
        response = requests.get(url, headers=headers, params=querystring)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except Exception as e:
        print(f"Error checking IP reputation: {e}")
        return None
''')
    else:
        print("No IPs found to check")
    
    return unique_ips

def calculate_severity(attack_type, count, payload=None):
    """Calculate severity score for detected attack"""
    severity = "Low"
    
    if not count:
        return severity
    
    # Try to convert count to a number
    try:
        if isinstance(count, str):
            # Extract number from string like "15 192.168.1.1"
            count = int(count.strip().split()[0])
        else:
            count = int(count)
    except (ValueError, IndexError):
        # If conversion fails, default to count of 1
        count = 1
    
    # Base severity on count of occurrences
    if count > 20:
        severity = "High"
    elif count > 10:
        severity = "Medium"
    elif count > 0:
        severity = "Low"
        
    # Adjust based on attack type
    if attack_type in ["sql_injection", "command_injection"]:
        severity = "High"  # Always high for these attacks
        
    # Check payload for dangerous patterns
    if payload and any(p in payload for p in ["/etc/passwd", "admin", "root", "SELECT *"]):
        severity = "High"
        
    return severity

def output_results(results, format_type="text", file=None):
    """Output results in the specified format"""
    if not results:
        return
    
    # Sanitize output file path if provided
    safe_file_path = sanitize_output_path(file) if file else None
        
    if format_type == "text":
        # Already printed to console in readable format
        pass
    elif format_type == "json":
        try:
            json_results = json.dumps(results, indent=2)
            if safe_file_path:
                with open(safe_file_path, 'w') as f:
                    f.write(json_results)
                print(f"Results exported to {safe_file_path} in JSON format")
            else:
                print(json_results)
        except Exception as e:
            print(f"Error exporting JSON results: {e}")
    elif format_type == "csv":
        try:
            if safe_file_path:
                with open(safe_file_path, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["Section", "Content"])
                    for section, content in results.items():
                        if content:
                            writer.writerow([section, str(content)])
                print(f"Results exported to {safe_file_path} in CSV format")
            else:
                # Print CSV to console
                print("Section,Content")
                for section, content in results.items():
                    if content:
                        # Truncate content for display
                        display_content = str(content)[:50] + "..." if len(str(content)) > 50 else str(content)
                        print(f"{section},{display_content}")
        except Exception as e:
            print(f"Error exporting CSV results: {e}")
    elif format_type == "html":
        generate_html_report(results, safe_file_path or "pcap_analysis_report.html")

def generate_html_report(results, output_file):
    """Generate a comprehensive HTML report with all findings"""
    # Sanitize the output path
    safe_output_path = sanitize_output_path(output_file)
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>PCAP Security Analysis Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        .section {{ margin-bottom: 20px; padding: 10px; border: 1px solid #ddd; border-radius: 5px; }}
        .high {{ background-color: #ffdddd; }}
        .medium {{ background-color: #ffffcc; }}
        .low {{ background-color: #e6f3ff; }}
        pre {{ background-color: #f8f8f8; padding: 10px; overflow-x: auto; }}
        .timestamp {{ color: #666; font-size: 0.9em; }}
        table {{ border-collapse: collapse; width: 100%; margin-top: 10px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
    </style>
</head>
<body>
    <h1>PCAP Security Analysis Report</h1>
    <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    """
    
    # Add each result section
    for section, content in results.items():
        if content:
            severity_class = "low"
            if any(term in section for term in ["sql_injection", "command_injection", "high"]):
                severity_class = "high"
            elif any(term in section for term in ["brute_force", "port_scan", "medium"]):
                severity_class = "medium"
                
            # Sanitize content before including in HTML
            safe_content = str(content).replace("<", "&lt;").replace(">", "&gt;")
            
            html_content += f"""
    <div class="section {severity_class}">
        <h2>{section.replace('_', ' ').title()}</h2>
        <pre>{safe_content}</pre>
    </div>"""
    
    html_content += """
</body>
</html>"""
    
    try:
        with open(safe_output_path, 'w') as f:
            f.write(html_content)
        
        print(f"HTML report generated: {safe_output_path}")
        return safe_output_path
    except Exception as e:
        print(f"Error writing HTML report: {e}")
        return None

def export_for_visualization(pcap_file, output_file):
    """Export key data for visualization in external tools"""
    # Sanitize the output path
    safe_output_path = sanitize_output_path(output_file)
    
    # Create a structured dataset for visualization tools
    viz_data = run_command_with_retry(f"""
        tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e 
        ip.proto -e tcp.srcport -e tcp.dstport -E header=y -E separator=, > {safe_output_path}
    """)
    
    print(f"Data exported to {safe_output_path} for visualization")
    print("Recommended visualization: Use Wireshark's built-in statistics or import to ELK stack")
    return safe_output_path

def save_config(args, config_file):
    """Save current configuration to file"""
    # Sanitize the file path
    safe_config_path = sanitize_output_path(config_file)
    
    try:
        with open(safe_config_path, 'w') as f:
            json.dump(vars(args), f, indent=2)
        print(f"Configuration saved to {safe_config_path}")
    except Exception as e:
        print(f"Error saving configuration: {e}")

def load_config(config_file):
    """Load configuration from file"""
    try:
        with open(config_file, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading configuration from {config_file}: {e}")
        return {}

def main():
    # Verify that all required dependencies are available
    required_dependencies = ["tshark", "capinfos", "mergecap", "editcap"]
    try:
        for dependency in required_dependencies:
            verify_dependency(dependency)
    except DependencyError as e:
        print(f"Error: {e}")
        if hasattr(e, 'install_instructions') and e.install_instructions:
            print(f"Install instructions: {e.install_instructions}")
        sys.exit(1)
        
    parser = argparse.ArgumentParser(description="Detect common attack patterns in PCAP files")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    
    # Analysis type options
    parser.add_argument("--attack", choices=["sql", "xss", "bruteforce", "portscan", 
                                           "ddos", "command", "traversal", "synflood", 
                                           "ldap", "packet", "malware", "all"], 
                        default="all", help="Specific attack type to detect")
    
    # Output options
    parser.add_argument("--output", choices=["text", "json", "csv", "html"], default="text",
                       help="Output format")
    parser.add_argument("--output-file", help="File to save results to")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Threshold options
    parser.add_argument("--threshold", type=int, default=10,
                       help="Threshold for attack detection (default: 10)")
    parser.add_argument("--brute-threshold", type=int, default=5, 
                       help="Threshold for brute force attempts (default: 5)")
    parser.add_argument("--scan-threshold", type=int, default=10, 
                       help="Threshold for port scan detection (default: 10)")
    parser.add_argument("--syn-threshold", type=int, default=100, 
                       help="Threshold for SYN flood detection (default: 100)")
    
    # Time range filtering
    parser.add_argument("--start-time", help="Start time for analysis (format: YYYY-MM-DD HH:MM:SS)")
    parser.add_argument("--end-time", help="End time for analysis (format: YYYY-MM-DD HH:MM:SS)")
    
    # Visualization export
    parser.add_argument("--export-viz", help="Export data for visualization to specified file")
    
    # Additional analysis options
    parser.add_argument("--verify", action="store_true",
                       help="Verify suspicious packets by examining their full content")
    parser.add_argument("--reconstruct", action="store_true",
                       help="Reconstruct suspicious TCP sessions")
    parser.add_argument("--nmap-file", help="Path to Nmap output file for service correlation")
    parser.add_argument("--correlate", action="store_true",
                       help="Correlate different attack types to find common sources")
    parser.add_argument("--threat-intel", action="store_true",
                       help="Check IPs against threat intelligence guidelines")
    
    # Config file options
    parser.add_argument("--save-config", help="Save current configuration to specified file")
    parser.add_argument("--load-config", help="Load configuration from specified file")
    
    # Cache control
    parser.add_argument("--disable-cache", action="store_true", 
                       help="Disable command output caching")
    
    args = parser.parse_args()
    
    # Load configuration if specified
    if args.load_config and os.path.exists(args.load_config):
        print(f"Loading configuration from {args.load_config}")
        config = load_config(args.load_config)
        parser.set_defaults(**config)
        args = parser.parse_args()
    
    # Validate PCAP file
    if not os.path.exists(args.pcap_file):
        print(f"Error: PCAP file '{args.pcap_file}' does not exist.")
        sys.exit(1)
    
    if not validate_pcap_file(args.pcap_file):
        print(f"Error: '{args.pcap_file}' is not a valid PCAP file")
        sys.exit(1)
    
    # Time filtering - with sanitization
    time_filter = ""
    if args.start_time and args.end_time:
        # Sanitize the time filter values to prevent command injection
        safe_start_time = sanitize_filter(args.start_time)
        safe_end_time = sanitize_filter(args.end_time)
        time_filter = f" and (frame.time >= \"{safe_start_time}\" and frame.time <= \"{safe_end_time}\")"
        print(f"Time filtering applied: {safe_start_time} to {safe_end_time}")
    
    print(f"\n{'='*30} Analyzing {os.path.basename(args.pcap_file)} for attacks {'='*30}")
    
    # Dictionary to store all results
    results = {}
    
    # Perform selected attack detections
    if args.attack in ['sql', 'all']:
        results['sql_injection'] = detect_sql_injection(args.pcap_file, time_filter)
    
    if args.attack in ['xss', 'all']:
        results['xss'] = detect_xss(args.pcap_file, time_filter)
    
    if args.attack in ['bruteforce', 'all']:
        results['brute_force'] = detect_brute_force(args.pcap_file, args.brute_threshold, time_filter)
    
    if args.attack in ['portscan', 'all']:
        results['port_scan'] = detect_port_scan(args.pcap_file, args.scan_threshold, time_filter)
    
    if args.attack in ['ddos', 'all']:
        results['ddos'] = detect_ddos(args.pcap_file, time_filter)
    
    if args.attack in ['synflood', 'all']:
        results['syn_flood'] = detect_syn_flood(args.pcap_file, args.syn_threshold, time_filter)
    
    if args.attack in ['command', 'all']:
        results['command_injection'] = detect_command_injection(args.pcap_file, time_filter)
    
    if args.attack in ['traversal', 'all']:
        results['directory_traversal'] = detect_directory_traversal(args.pcap_file, time_filter)
    
    if args.attack in ['ldap', 'all']:
        results['ldap_attacks'] = detect_ldap_attacks(args.pcap_file, time_filter)
    
    if args.attack in ['packet', 'all']:
        results['packet_anomalies'] = detect_packet_anomalies(args.pcap_file, time_filter)
    
    if args.attack in ['malware', 'all']:
        results['malware_traffic'] = detect_malware_traffic(args.pcap_file, time_filter)
    
    # HTTP response analysis
    results['http_responses'] = analyze_http_responses(args.pcap_file, time_filter)
    
    # Application protocol analysis
    results['application_protocols'] = analyze_application_protocols(args.pcap_file, time_filter)
    
    # Attack correlation if requested
    if args.correlate:
        results['correlated_attacks'] = correlate_attacks(args.pcap_file, time_filter)
    
    # Check threat intelligence if requested
    if args.threat_intel:
        results['threat_intel'] = check_threat_intel(args.pcap_file)
    
    # Load Nmap data if provided
    nmap_data = None
    if args.nmap_file and os.path.exists(args.nmap_file):
        print(f"\n=== Loading Nmap data from {args.nmap_file} ===")
        nmap_data = load_nmap_data(args.nmap_file)
        results['nmap_services'] = nmap_data
        
        # Correlate attacks with services
        if nmap_data:
            print("\n=== Correlating Attacks with Services ===")
            service_context = {}
            for attack_type, attack_data in results.items():
                if attack_data and isinstance(attack_data, dict):
                    for subtype, data in attack_data.items():
                        if data:
                            correlated = correlate_with_services(data, nmap_data)
                            if correlated:
                                service_context[f"{attack_type}_{subtype}"] = correlated
                                print(f"Found service correlation for {attack_type}/{subtype}")
            if service_context:
                results['service_context'] = service_context
    
    # Verify suspicious packets if requested
    if args.verify:
        print("\n=== Verifying Suspicious Packets ===")
        frame_numbers = []
        for attack_type, data in results.items():
            if isinstance(data, str) and data.strip():
                try:
                    frame_lines = data.strip().split('\n')
                    for line in frame_lines:
                        if line.strip() and line.split()[0].isdigit():
                            frame_numbers.append(line.split()[0])
                except:
                    continue
        
        if frame_numbers:
            verification = verify_packets(args.pcap_file, frame_numbers)
            print(verification or "No packets could be verified")
            results['packet_verification'] = verification
    
    # Session reconstruction if requested
    if args.reconstruct:
        print("\n=== Reconstructing Suspicious Sessions ===")
        # Find suspicious IP pairs
        suspicious_sessions = []
        for attack_type, data in results.items():
            if isinstance(data, str):
                lines = data.strip().split('\n')
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4 and '.' in parts[1] and '.' in parts[2]:
                        suspicious_sessions.append((parts[1], parts[2]))
        
        sessions = {}
        for ip_src, ip_dst in suspicious_sessions[:5]:  # Limit to first 5 pairs
            session = reconstruct_session(args.pcap_file, ip_src, ip_dst)
            if session:
                sessions[f"{ip_src}-{ip_dst}"] = session
                print(session)
        
        if sessions:
            results['reconstructed_sessions'] = sessions
    
    # Export data for visualization if requested
    if args.export_viz:
        results['visualization_export'] = export_for_visualization(args.pcap_file, args.export_viz)
    
    # Calculate severity for results
    print("\n=== Attack Severity Assessment ===")
    severity_summary = {}
    for attack_type, data in results.items():
        if data:
            if isinstance(data, str):
                count = len(data.strip().split('\n'))
                severity = calculate_severity(attack_type, count, data)
                severity_summary[attack_type] = severity
                print(f"{attack_type}: {severity} severity ({count} matches)")
            elif isinstance(data, dict):
                for subtype, subdata in data.items():
                    if subdata:
                        count = len(str(subdata).strip().split('\n'))
                        severity = calculate_severity(f"{attack_type}_{subtype}", count, str(subdata))
                        severity_summary[f"{attack_type}_{subtype}"] = severity
                        print(f"{attack_type} - {subtype}: {severity} severity ({count} matches)")
    
    results['severity_summary'] = severity_summary
    
    # Save configuration if requested
    if args.save_config:
        save_config(args, args.save_config)
    
    # Output results in the selected format
    if args.output != "text" or args.output_file:
        output_results(results, args.output, args.output_file)
    
    print(f"\n{'='*30} Analysis Complete {'='*30}")
    print(f"PCAP file: {args.pcap_file}")
    print(f"Analysis types: {args.attack}")
    if args.output_file:
        print(f"Results exported to: {args.output_file}")
    
    # Summary of findings
    print("\n=== Summary of Findings ===")
    high_severity = [k for k, v in severity_summary.items() if v == "High"]
    medium_severity = [k for k, v in severity_summary.items() if v == "Medium"]
    if high_severity:
        print(f"High severity findings: {', '.join(high_severity)}")
    if medium_severity:
        print(f"Medium severity findings: {', '.join(medium_severity)}")
    if not high_severity and not medium_severity:
        print("No significant security issues detected")

if __name__ == "__main__":
    main()