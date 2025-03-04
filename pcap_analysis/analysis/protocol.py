#!/usr/bin/env python3
from ..core.command import run_command

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
    
    # Response size anomalies
    large_responses = run_command(
        f"tshark -r {pcap_file} -Y 'http.response and http.content_length > 100000{time_filter}' "
        f"-T fields -e frame.time -e ip.src -e http.content_length -e http.request.uri"
    )
    print("\n=== Large HTTP Responses (Possible Data Leakage) ===")
    print(large_responses or "No unusually large HTTP responses detected")
    
    # Suspicious HTTP response headers
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