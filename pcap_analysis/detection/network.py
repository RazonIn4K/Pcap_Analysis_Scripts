#!/usr/bin/env python3
from ..core.command import run_command

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
    fast_scan = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0.1 | grep -v \"0.000000\""
    )
    print("\n=== High-Rate Port Scan Detection ===")
    print(fast_scan or "No high-rate port scanning detected")
    
    return {"port_scan": port_scan, "sequential_ports": sequential_ports, "fast_scan": fast_scan}

def detect_ddos(pcap_file, time_filter=""):
    """Detect potential DDoS/DoS activity"""
    print("\n=== Potential DDoS/DoS Activity ===")
    
    # Look for high volume of traffic to same destination
    traffic_volume = run_command(
        f"tshark -r {pcap_file} -q -z ip.dst,tree | sort -k 2nr | head -n 20"
    )
    print(traffic_volume or "No unusual traffic volume detected")
    
    # HTTP-based DoS detection
    http_flood = run_command(
        f"tshark -r {pcap_file} -Y \"http.request{time_filter}\" -T fields "
        f"-e ip.src -e http.request.uri | sort | uniq -c | sort -nr | head -n 15"
    )
    print("\n=== HTTP Flood Detection ===")
    print(http_flood or "No HTTP flood detected")
    
    # ICMP flood detection
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
        f"tshark -r {pcap_file} -q -z io,stat,1 | grep -v \"1.000000\""
    )
    print("\n=== SYN Packet Rate (Possible DoS) ===")
    print(high_rate_syn or "No abnormal SYN packet rates detected")
    
    # SYN-to-host ratio analysis
    syn_ack_ratio = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,5"
    )
    print("\n=== SYN to ACK Ratio (Flood Indicator) ===")
    print(syn_ack_ratio or "No SYN-ACK ratio data available")
    
    return {"syn_flood": syn_flood, "high_rate_syn": high_rate_syn, "syn_ack_ratio": syn_ack_ratio}

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