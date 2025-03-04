#!/usr/bin/env python3
import os
import re
from ..core.command import run_command
from ..core.utils import format_time_filter

def analyze_pcap(pcap_file, options=None):
    """Analyze a PCAP file for general statistics and information"""
    if options is None:
        options = {}
    
    output_format = options.get('output_format', 'text')
    results = {}
    
    print(f"\n{'='*30} Analyzing {os.path.basename(pcap_file)} {'='*30}")
    
    # Time filtering
    time_filter = format_time_filter(options.get('start_time'), options.get('end_time'))
    if time_filter:
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
    
    # Packet size distribution
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
    hosts_analysis = run_command(f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst | tr ' ' '\n' | sort | uniq -c | sort -nr | head -n 20")
    print(hosts_analysis or "No host information found")
    results['hosts_analysis'] = hosts_analysis
    
    return results 