#!/usr/bin/env python3
import argparse
import subprocess
import os
import json
import sys
import csv
import math
import re
from datetime import datetime
import time
from collections import Counter

# Global cache for command results
command_cache = {}

def run_command(command, use_cache=True):
    """Execute a shell command and return its output with progress indicator"""
    if use_cache and command in command_cache:
        return command_cache[command]
        
    try:
        print("Running analysis...", end="\r")
        sys.stdout.flush()  # Ensure the progress indicator is displayed immediately
        process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
        print("                    ", end="\r")  # Clear the line
        if process.returncode != 0:
            print(f"Error running command: {stderr.decode('utf-8')}")
            return None
        result = stdout.decode('utf-8')
        
        if use_cache:
            command_cache[command] = result
        return result
    except Exception as e:
        print(f"Exception while running command: {e}")
        return None

def analyze_pcap(pcap_file, options=None):
    """Analyze a PCAP file for general statistics and information"""
    if options is None:
        options = {}
    
    output_format = options.get('output_format', 'text')
    results = {}
    
    print(f"\n{'='*30} Analyzing {os.path.basename(pcap_file)} {'='*30}")
    
    # Time filtering
    time_filter = ""
    if options.get('start_time') and options.get('end_time'):
        time_filter = f" and (frame.time >= \"{options['start_time']}\" and frame.time <= \"{options['end_time']}\")"
        print(f"Time filtering applied: {options['start_time']} to {options['end_time']}")
    
    # Basic info
    info = run_command(f"capinfos {pcap_file}")
    print("\n=== Basic Information ===")
    print(info)
    results['basic_info'] = info
    
    # Extract capture duration and packet count for progress reporting
    capture_duration = None
    packet_count = None
    if info:
        duration_match = re.search(r"Capture duration:\s+(\d+\.\d+) seconds", info)
        if duration_match:
            capture_duration = float(duration_match.group(1))
            
        packet_match = re.search(r"Number of packets:\s+(\d+)", info)
        if packet_match:
            packet_count = int(packet_match.group(1))
    
    if options.get('verbose'):
        print(f"Capture duration: {capture_duration} seconds, Packets: {packet_count}")
    
    # Protocol hierarchy
    print("\n=== Protocol Hierarchy ===")
    proto_hierarchy = run_command(f"tshark -r {pcap_file} -qz io,phs")
    print(proto_hierarchy)
    results['protocol_hierarchy'] = proto_hierarchy
    
    # Top talkers
    print("\n=== Top Talkers ===")
    top_talkers = run_command(f"tshark -r {pcap_file} -q -z conv,ip | head -n 25")
    print(top_talkers)
    results['top_talkers'] = top_talkers
    
    # HTTP requests if any
    print("\n=== HTTP Requests (if any) ===")
    http_requests = run_command(f"tshark -r {pcap_file} -Y 'http.request{time_filter}' -T fields -e http.request.method -e http.request.uri -e ip.src -e ip.dst | head -n 15")
    print(http_requests or "No HTTP requests found")
    results['http_requests'] = http_requests
    
    # Check for port scans
    print("\n=== Potential Port Scan Activities ===")
    port_scan = run_command(f"tshark -r {pcap_file} -Y 'tcp.flags.syn==1 and tcp.flags.ack==0{time_filter}' -T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 15")
    print(port_scan or "No port scan activities detected")
    results['port_scan'] = port_scan
    
    # DNS queries
    print("\n=== DNS Queries (if any) ===")
    dns_queries = run_command(f"tshark -r {pcap_file} -Y 'dns.flags.response == 0{time_filter}' -T fields -e ip.src -e dns.qry.name | sort | uniq -c | sort -nr | head -n 15")
    print(dns_queries or "No DNS queries found")
    results['dns_queries'] = dns_queries
    
    # New: Packet size distribution
    print("\n=== Packet Size Distribution ===")
    packet_sizes = run_command(f"tshark -r {pcap_file} -T fields -e frame.len | sort -n | uniq -c")
    
    if packet_sizes:
        size_data = {}
        total_packets = 0
        for line in packet_sizes.strip().split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    count = int(parts[0])
                    size = int(parts[1])
                    size_data[size] = count
                    total_packets += count
        
        # Create size categories
        size_categories = {
            "Tiny (<100 bytes)": 0,
            "Small (100-500 bytes)": 0,
            "Medium (500-1000 bytes)": 0,
            "Large (1000-1500 bytes)": 0,
            "Jumbo (>1500 bytes)": 0
        }
        
        for size, count in size_data.items():
            if size < 100:
                size_categories["Tiny (<100 bytes)"] += count
            elif size < 500:
                size_categories["Small (100-500 bytes)"] += count
            elif size < 1000:
                size_categories["Medium (500-1000 bytes)"] += count
            elif size < 1500:
                size_categories["Large (1000-1500 bytes)"] += count
            else:
                size_categories["Jumbo (>1500 bytes)"] += count
        
        print("Packet size distribution:")
        for category, count in size_categories.items():
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            print(f"{category}: {count} packets ({percentage:.2f}%)")
        
        results['packet_size_distribution'] = size_categories
    else:
        print("Unable to analyze packet size distribution")
    
    # Network hosts analysis
    print("\n=== Network Hosts Analysis ===")
    hosts_analysis = run_command(f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst | tr ' ' '\\n' | sort | uniq -c | sort -nr | head -n 20")
    print(hosts_analysis or "No host information found")
    results['hosts_analysis'] = hosts_analysis
    
    if options.get('export_results') and output_format != 'text':
        output_results(results, output_format, options.get('output_file'))
    
    return results

def detect_sql_injection(pcap_file, time_filter=""):
    """Detect potential SQL injection attempts in HTTP traffic"""
    print("\n=== Potential SQL Injection Attempts ===")
    sql_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http.request and "
        f"(http.request.uri contains \\\"%27\\\" or "
        f"http.request.uri contains \\\"SELECT\\\" or "
        f"http.request.uri contains \\\"UNION\\\" or "
        f"http.request.body contains \\\"%27\\\" or "
        f"http.request.body contains \\\"SELECT\\\" or "
        f"http.request.uri contains \\\"OR 1=1\\\" or "
        f"http.request.uri contains \\\"--\\\" or "
        f"http.request.uri contains \\\"%20OR%20\\\" or "
        f"http.request.uri contains \\\"information_schema\\\"){time_filter}\" "
        f"-T fields -e frame.number -e frame.time -e ip.src -e http.request.uri -e http.request.body"
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
        f"http contains \\\"onload=\\\" or "
        f"http contains \\\"alert(\\\" or "
        f"http contains \\\"document.cookie\\\"{time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri"
    )
    print(xss_patterns or "No XSS patterns detected")
    return xss_patterns

def detect_command_injection(pcap_file, time_filter=""):
    """Detect potential command injection attempts"""
    print("\n=== Potential Command Injection Attempts ===")
    cmd_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"http contains \\\";\\\" or "
        f"http contains \\\"|\\\" or "
        f"http contains \\\"&&\\\" or "
        f"http contains \\\"||\\\" or "
        f"http contains \\\"$(\\\" or "
        f"http contains \\\"`\\\" or "
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
    print(traversal_patterns or "No directory traversal patterns detected")
    return traversal_patterns

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
        f"tshark -r {pcap_file} -q -z \"io,stat,1,\\\"tcp.flags.syn==1{time_filter}\\\"\" | "
        f"grep -v \"1.000000\""
    )
    print("\n=== SYN Packet Rate (Possible DoS) ===")
    print(high_rate_syn or "No abnormal SYN packet rates detected")
    
    # New: SYN-to-host ratio analysis
    syn_ack_ratio = run_command(
        f"tshark -r {pcap_file} -q -z \"io,stat,5,\\\"tcp.flags.syn==1\\\",\\\"tcp.flags.ack==1\\\"{time_filter}\""
    )
    print("\n=== SYN to ACK Ratio (Flood Indicator) ===")
    print(syn_ack_ratio or "No SYN-ACK ratio data available")
    
    return {"syn_flood": syn_flood, "high_rate_syn": high_rate_syn, "syn_ack_ratio": syn_ack_ratio}

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
    
    # LDAP authentication attempts
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
        f"-T fields -e frame.time -e ip.src -e ldap.resultCode -e ldap.bindName"
    )
    print("\n=== LDAP Bind Failures (Possible Attack) ===")
    print(ldap_bind_failures or "No LDAP bind failures detected")
    
    return {
        "ldap_traffic": ldap_patterns, 
        "ldap_injection": ldap_injection,
        "ldap_bind_failures": ldap_bind_failures
    }

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
    
    # DNS record types distribution
    dns_types = run_command(
        f"tshark -r {pcap_file} -Y 'dns.qry.type{time_filter}' "
        f"-T fields -e dns.qry.type | sort | uniq -c | sort -nr"
    )
    print("\n=== DNS Record Types ===")
    print(dns_types or "No DNS record types found")
    results["dns_types"] = dns_types
    
    return results

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
        f"tshark -r {pcap_file} -Y 'ip.ttl < 10 or ip.ttl > 250{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst -e ip.ttl | head -n 15"
    )
    print("\n-- Unusual TTL Values (Potential Spoofing) --")
    print(unusual_ttl or "No unusual TTL values detected")
    results["unusual_ttl"] = unusual_ttl
    
    # New: TCP retransmissions (network issues or potential DoS)
    retransmissions = run_command(
        f"tshark -r {pcap_file} -Y 'tcp.analysis.retransmission{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15"
    )
    print("\n-- TCP Retransmissions --")
    print(retransmissions or "No TCP retransmissions detected")
    results["retransmissions"] = retransmissions
    
    return results

def detect_malware_traffic(pcap_file, time_filter=""):
    """Detect traffic patterns associated with malware"""
    print("\n=== Potential Malware Communication ===")
    results = {}
    
    # Look for common C2 patterns, beaconing, and unusual DNS
    malware_patterns = run_command(
        f"tshark -r {pcap_file} -Y \"(dns.qry.name contains \\\".bit\\\" or "
        f"dns.qry.name contains \\\".onion\\\" or dns.qry.name matches \\\"[a-zA-Z0-9]{{25,}}\\\\.(com|net|org)\\\") or "
        f"(http.user_agent contains \\\"MSIE\\\" and http.request.version != \\\"HTTP/1.1\\\") or "
        f"(tcp.flags == 0x02 and tcp.window_size <= 1024){time_filter}\" "
        f"-T fields -e frame.time -e ip.src -e ip.dst -e dns.qry.name -e tcp.dstport"
    )
    
    print(malware_patterns or "No suspicious malware traffic patterns detected")
    results["malware_patterns"] = malware_patterns
    
    # Check for periodic beaconing (regular interval communication)
    print("\n=== Potential Beaconing (Regular Interval Communication) ===")
    beaconing = run_command(
        f"tshark -r {pcap_file} -T fields -e frame.time -e ip.src -e ip.dst -e tcp.dstport "
        f"-Y \"tcp and not tcp.port==80 and not tcp.port==443{time_filter}\" | head -n 100"
    )
    
    print("To analyze for beaconing, export this data and check for regular time intervals")
    results["potential_beaconing"] = beaconing
    
    # Unusual DNS TXT records (often used for C2)
    txt_records = run_command(
        f"tshark -r {pcap_file} -Y \"dns.txt{time_filter}\" -T fields "
        f"-e frame.time -e ip.src -e dns.qry.name -e dns.txt"
    )
    print("\n=== DNS TXT Records (Potential C2 Channel) ===")
    print(txt_records or "No suspicious DNS TXT records found")
    results["txt_records"] = txt_records
    
    # Entropy analysis of DNS queries (potential DGA detection)
    dns_names = run_command(
        f"tshark -r {pcap_file} -Y \"dns.qry.name{time_filter}\" -T fields -e dns.qry.name | sort | uniq"
    )
    if dns_names:
        print("\n=== DNS Query Name Entropy (Potential DGA Detection) ===")
        high_entropy_domains = []
        dns_name_list = dns_names.strip().split('\n')
        for domain in dns_name_list[:50]:  # Limit analysis to first 50 domains
            if domain and len(domain) > 8:
                entropy = calculate_entropy(domain)
                if entropy > 4.0:  # High entropy threshold
                    high_entropy_domains.append(f"{domain}: {entropy:.2f}")
        
        if high_entropy_domains:
            print("Potential algorithmically generated domains (high entropy):")
            for domain in high_entropy_domains:
                print(domain)
            results["high_entropy_domains"] = high_entropy_domains
        else:
            print("No high entropy domain names detected")
    
    # New: Check for uncommon ports
    uncommon_ports = run_command(
        f"tshark -r {pcap_file} -Y \"!(tcp.port in {{80 443 21 22 25 53 110 143 993 995 3389}}) and tcp{time_filter}\" "
        f"-T fields -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport | sort | uniq -c | sort -nr | head -n 15"
    )
    print("\n=== Uncommon Port Usage (Potential C2) ===")
    print(uncommon_ports or "No uncommon port usage detected")
    results["uncommon_ports"] = uncommon_ports
    
    return results

def calculate_entropy(string):
    """Calculate Shannon entropy of a string - useful for DGA detection"""
    if not string:
        return 0
        
    prob = {}
    for char in string:
        if char in prob:
            prob[char] += 1
        else:
            prob[char] = 1
    
    entropy = 0
    for char in prob:
        p = prob[char] / len(string)
        entropy -= p * (math.log(p) / math.log(2))
    
    return entropy

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
    
    # New: Analyze attack types per IP
    if correlation:
        print("\n=== Attack Types Per IP ===")
        ips = []
        for line in correlation.strip().split('\n'):
            if line.strip():
                parts = line.strip().split()
                if len(parts) >= 2:
                    ips.append(parts[1])
        
        for ip in ips[:5]:  # Limit to top 5 IPs
            print(f"\nAttack types for IP: {ip}")
            
            # SQL injection attempts
            sql = run_command(
                f"tshark -r {pcap_file} -Y \"ip.src == {ip} and (http.request.uri contains \\\"%27\\\" or "
                f"http.request.uri contains \\\"SELECT\\\"){time_filter}\" | wc -l"
            )
            sql = sql.strip() if sql else "0"
            
            # XSS attempts
            xss = run_command(
                f"tshark -r {pcap_file} -Y \"ip.src == {ip} and (http contains \\\"<script>\\\" or "
                f"http contains \\\"%3Cscript%3E\\\"){time_filter}\" | wc -l"
            )
            xss = xss.strip() if xss else "0"
            
            # Command injection attempts
            cmd = run_command(
                f"tshark -r {pcap_file} -Y \"ip.src == {ip} and (http contains \\\";\\\" or "
                f"http contains \\\"|\\\" or http contains \\\"&&\\\"){time_filter}\" | wc -l"
            )
            cmd = cmd.strip() if cmd else "0"
            
            # Port scan attempts
            scan = run_command(
                f"tshark -r {pcap_file} -Y \"ip.src == {ip} and tcp.flags.syn==1 and tcp.flags.ack==0{time_filter}\" | wc -l"
            )
            scan = scan.strip() if scan else "0"
            
            print(f"SQL Injection: {sql}, XSS: {xss}, Command Injection: {cmd}, Port Scan: {scan}")
    
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
        import requests
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
        f"tshark -r {pcap_file} -Y \"tcp.stream eq {tcp_stream_index} and http\" -T fields -e http.request.method -e http.request.uri -e http.file_data"
    )
    
    if http_content:
        print("\n-- HTTP Content in Session --")
        print(http_content)
    
    return session

def verify_packets(pcap_file, frame_numbers):
    """Verify suspicious packets by examining their full content"""
    if not frame_numbers:
        return None
        
    # Convert frame_numbers list to a filter expression
    if isinstance(frame_numbers, str):
        # Extract frame numbers from output
        frame_numbers = [line.split()[0] for line in frame_numbers.strip().split('\n') if line.strip()]
    
    if not frame_numbers:
        return None
    
    frame_filter = " or ".join([f"frame.number=={num}" for num in frame_numbers])
    
    # Get detailed information about the suspicious packets
    details = run_command(
        f"tshark -r {pcap_file} -Y \"{frame_filter}\" -V"
    )
    return details

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
        
    if format_type == "text":
        # Already printed to console in readable format
        pass
    elif format_type == "json":
        json_results = json.dumps(results, indent=2)
        if file:
            with open(file, 'w') as f:
                f.write(json_results)
            print(f"Results exported to {file} in JSON format")
        else:
            print(json_results)
    elif format_type == "csv":
        if file:
            with open(file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Section", "Content"])
                for section, content in results.items():
                    if content:
                        writer.writerow([section, content])
            print(f"Results exported to {file} in CSV format")
        else:
            # Print CSV to console
            print("Section,Content")
            for section, content in results.items():
                if content:
                    print(f"{section},{content[:50]}...")
    elif format_type == "html":
        generate_html_report(results, file or "pcap_analysis_report.html")

def generate_html_report(results, output_file):
    """Generate a comprehensive HTML report with all findings"""
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
        .summary {{ padding: 15px; background-color: #f7f7f7; border-left: 5px solid #2c3e50; margin-bottom: 20px; }}
        .chart-container {{ height: 300px; margin: 20px 0; }}
        footer {{ margin-top: 30px; padding-top: 10px; border-top: 1px solid #eee; font-size: 0.9em; color: #666; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
</head>
<body>
    <h1>PCAP Security Analysis Report</h1>
    <p class="timestamp">Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary">
        <h2>Analysis Summary</h2>
        <div id="severity-summary">
            <h3>Severity Distribution</h3>
            <canvas id="severityChart" width="400" height="200"></canvas>
        </div>
    </div>
    """
    
    # Security findings summary
    severity_counts = {"High": 0, "Medium": 0, "Low": 0}
    
    # Add each result section
    for section, content in results.items():
        if content:
            severity_class = "low"
            severity = "Low"
            
            if any(term in section for term in ["sql_injection", "command_injection", "high"]):
                severity_class = "high"
                severity = "High"
                severity_counts["High"] += 1
            elif any(term in section for term in ["brute_force", "port_scan", "medium"]):
                severity_class = "medium"
                severity = "Medium"
                severity_counts["Medium"] += 1
            else:
                severity_counts["Low"] += 1
                
            html_content += f"""
    <div class="section {severity_class}">
        <h2>{section.replace('_', ' ').title()} ({severity})</h2>
        <pre>{content}</pre>
    </div>"""
    
    # Add JavaScript for charts
    html_content += f"""
    <footer>
        <p>Report generated by pcapng_analyzer.py</p>
    </footer>
    
    <script>
    document.addEventListener('DOMContentLoaded', function() {{
        // Severity Distribution Chart
        var severityCtx = document.getElementById('severityChart').getContext('2d');
        var severityChart = new Chart(severityCtx, {{
            type: 'pie',
            data: {{
                labels: ['High', 'Medium', 'Low'],
                datasets: [{{
                    data: [{severity_counts["High"]}, {severity_counts["Medium"]}, {severity_counts["Low"]}],
                    backgroundColor: ['#ffdddd', '#ffffcc', '#e6f3ff']
                }}]
            }},
            options: {{
                responsive: true,
                legend: {{
                    position: 'bottom'
                }},
                title: {{
                    display: true,
                    text: 'Finding Severity Distribution'
                }}
            }}
        }});
    }});
    </script>
</body>
</html>"""
    
    with open(output_file, 'w') as f:
        f.write(html_content)
    
    print(f"HTML report generated: {output_file}")
    return output_file

def export_for_visualization(pcap_file, output_file):
    """Export key data for visualization in external tools"""
    # Create a structured dataset for visualization tools
    viz_data = run_command(f"""
        tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e 
        ip.proto -e tcp.srcport -e tcp.dstport -E header=y -E separator=, > {output_file}
    """)
    
    print(f"Data exported to {output_file} for visualization")
    print("Recommended visualization: Use Wireshark's built-in statistics or import to ELK stack")
    return output_file

def save_config(args, config_file):
    """Save current configuration to file"""
    with open(config_file, 'w') as f:
        json.dump(vars(args), f, indent=2)
    print(f"Configuration saved to {config_file}")

def load_config(config_file):
    """Load configuration from file"""
    with open(config_file, 'r') as f:
        return json.load(f)

def analyze_timing_patterns(pcap_file, ip_addr=None, time_filter=""):
    """Analyze timing patterns between packets for regular intervals (C2 beaconing)"""
    print("\n=== Timing Pattern Analysis (Beaconing Detection) ===")
    
    # Construct filter for specific IP if provided
    ip_filter = f" and ip.addr == {ip_addr}" if ip_addr else ""
    
    # Get packet timestamps for analysis
    timestamps = run_command(
        f"tshark -r {pcap_file} -Y \"tcp{ip_filter}{time_filter}\" -T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport"
    )
    
    if not timestamps:
        print("No packets found for timing analysis")
        return None
    
    # Process timestamp data
    lines = timestamps.strip().split('\n')
    time_data = {}
    
    for line in lines:
        if not line.strip():
            continue
            
        parts = line.split()
        if len(parts) >= 4:
            try:
                ts = float(parts[0])
                src = parts[1]
                dst = parts[2]
                port = parts[3]
                key = f"{src}:{dst}:{port}"
                
                if key not in time_data:
                    time_data[key] = []
                    
                time_data[key].append(ts)
            except:
                continue
    
    # Analyze intervals for regular patterns
    beacon_candidates = []
    
    for connection, times in time_data.items():
        if len(times) < 5:  # Need enough samples
            continue
            
        # Sort timestamps
        times.sort()
        
        # Calculate intervals
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        
        # Skip if no intervals
        if not intervals:
            continue
            
        # Calculate statistics
        avg_interval = sum(intervals) / len(intervals)
        
        # Calculate variance of intervals
        if len(intervals) > 1:
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            stdev = math.sqrt(variance)
            
            # Low standard deviation suggests regular beaconing
            regularity = stdev / avg_interval if avg_interval > 0 else float('inf')
            
            if regularity < 0.1:  # Highly regular
                src, dst, port = connection.split(':')
                beacon_candidates.append({
                    "connection": connection,
                    "avg_interval": avg_interval,
                    "regularity": regularity,
                    "samples": len(times)
                })
    
    if beacon_candidates:
        print("Potential beaconing behavior detected:")
        for bc in beacon_candidates:
            print(f"Connection: {bc['connection']}")
            print(f"  Average interval: {bc['avg_interval']:.2f} seconds")
            print(f"  Regularity: {bc['regularity']:.4f} (lower is more regular)")
            print(f"  Samples: {bc['samples']}")
    else:
        print("No regular communication patterns detected")
    
    return beacon_candidates

def extract_http_payloads(pcap_file, output_dir, time_filter=""):
    """Extract HTTP payloads from PCAP file for offline analysis"""
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    print("\n=== Extracting HTTP Payloads ===")
    
    # Extract HTTP objects
    objects = run_command(
        f"tshark -r {pcap_file} -Y \"http.request or http.response{time_filter}\" -T fields -e http.file_data -e http.request.uri -e http.content_type"
    )
    
    if not objects:
        print("No HTTP objects found")
        return None
    
    # Write extracted data to files
    lines = objects.strip().split('\n')
    file_count = 0
    
    for i, line in enumerate(lines):
        if not line.strip():
            continue
            
        parts = line.split('\t')
        if len(parts) >= 1 and parts[0]:
            file_path = os.path.join(output_dir, f"http_object_{i}.txt")
            
            uri = parts[1] if len(parts) > 1 else "unknown"
            content_type = parts[2] if len(parts) > 2 else "unknown"
            
            # Create metadata file
            meta_path = os.path.join(output_dir, f"http_object_{i}_meta.txt")
            with open(meta_path, 'w') as f:
                f.write(f"URI: {uri}\nContent-Type: {content_type}\n")
            
            # Write payload data
            with open(file_path, 'w') as f:
                f.write(parts[0])
                
            file_count += 1
    
    print(f"Extracted {file_count} HTTP objects to {output_dir}")
    return file_count

def main():
    parser = argparse.ArgumentParser(description="Enhanced PCAP file analyzer for security analysis")
    parser.add_argument("pcap_file", help="Path to the PCAP file to analyze")
    
    # Analysis type options
    parser.add_argument("--attack", choices=["sql", "xss", "bruteforce", "portscan", 
                                           "directory", "command", "synflood", "ldap", 
                                           "packet", "malware", "all"], 
                        default="all", help="Specific attack type to detect")
    
    # Output options
    parser.add_argument("--output-format", choices=["text", "json", "csv", "html"], default="text",
                       help="Output format")
    parser.add_argument("--output-file", help="File to save results to")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    
    # Threshold options
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
    
    # Advanced analysis options
    parser.add_argument("--verify-packets", action="store_true", 
                       help="Verify suspicious packets by examining their full content")
    parser.add_argument("--threat-intel", action="store_true",
                       help="Check IPs against threat intelligence guidelines")
    parser.add_argument("--reconstruct-sessions", action="store_true",
                       help="Reconstruct suspicious TCP sessions")
    parser.add_argument("--extract-http", help="Directory to extract HTTP payloads to")
    parser.add_argument("--timing-analysis", action="store_true",
                       help="Analyze packet timing for beaconing detection")
    parser.add_argument("--nmap-file", help="Path to Nmap output file for service correlation")
    
    # Config file options
    parser.add_argument("--save-config", help="Save current configuration to specified file")
    parser.add_argument("--load-config", help="Load configuration from specified file")
    
    # Cache control
    parser.add_argument("--disable-cache", action="store_true", 
                       help="Disable command output caching")
    
    # Reporting options
    parser.add_argument("--summary-only", action="store_true",
                       help="Show only the summary of findings, not full details")
    
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
    
    # Time filtering
    time_filter = ""
    if args.start_time and args.end_time:
        time_filter = f" and (frame.time >= \"{args.start_time}\" and frame.time <= \"{args.end_time}\")"
        print(f"Time filtering applied: {args.start_time} to {args.end_time}")
    
    # Set up options dictionary
    options = {
        'output_format': args.output_format,
        'output_file': args.output_file,
        'verbose': args.verbose,
        'export_results': args.output_file is not None,
        'start_time': args.start_time,
        'end_time': args.end_time,
        'use_cache': not args.disable_cache
    }
    
    # Run basic analysis first
    results = analyze_pcap(args.pcap_file, options)
    
    if not args.summary_only:
        # Run attack-specific analysis based on user selection
        if args.attack in ['sql', 'all']:
            results['sql_injection'] = detect_sql_injection(args.pcap_file, time_filter)
        
        if args.attack in ['xss', 'all']:
            results['xss'] = detect_xss(args.pcap_file, time_filter)
        
        if args.attack in ['command', 'all']:
            results['command_injection'] = detect_command_injection(args.pcap_file, time_filter)
        
        if args.attack in ['directory', 'all']:
            results['directory_traversal'] = detect_directory_traversal(args.pcap_file, time_filter)
        
        if args.attack in ['synflood', 'all']:
            results['syn_flood'] = detect_syn_flood(args.pcap_file, args.syn_threshold, time_filter)
        
        if args.attack in ['bruteforce', 'all']:
            results['brute_force'] = detect_brute_force(args.pcap_file, args.brute_threshold, time_filter)
        
        if args.attack in ['ldap', 'all']:
            results['ldap_attacks'] = detect_ldap_attacks(args.pcap_file, time_filter)
        
        if args.attack in ['packet', 'all']:
            results['packet_anomalies'] = detect_packet_anomalies(args.pcap_file, time_filter)
        
        if args.attack in ['malware', 'all']:
            results['malware_traffic'] = detect_malware_traffic(args.pcap_file, time_filter)
        
        # Additional analysis
        results['http_responses'] = analyze_http_responses(args.pcap_file, time_filter)
        results['application_protocols'] = analyze_application_protocols(args.pcap_file, time_filter)
    
    # Correlate attacks to find common sources
    results['correlated_attacks'] = correlate_attacks(args.pcap_file, time_filter)
    
    # Check threat intelligence if requested
    if args.threat_intel:
        results['threat_intel'] = check_threat_intel(args.pcap_file)
    
    # Analyze timing patterns if requested
    if args.timing_analysis:
        results['timing_patterns'] = analyze_timing_patterns(args.pcap_file, time_filter=time_filter)
    
    # Extract HTTP payloads if requested
    if args.extract_http:
        results['http_payloads'] = extract_http_payloads(args.pcap_file, args.extract_http, time_filter)
    
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
    if args.verify_packets:
        print("\n=== Verifying Suspicious Packets ===")
        frame_numbers = []
        for attack_type, data in results.items():
            if isinstance(data, str) and 'frame.number' in data:
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
    if args.reconstruct_sessions:
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
    
    # Final output if not already exported
    if args.output_file:
        output_results(results, args.output_format, args.output_file)
    
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