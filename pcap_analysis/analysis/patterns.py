#!/usr/bin/env python3
import math
from ..core.command import run_command

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

def detect_beaconing(pcap_file, time_filter=""):
    """Detect C2 beaconing using time series analysis"""
    print("\n=== Beaconing Detection (C2 Communication) ===")
    
    # Extract timestamps per connection
    conn_data = run_command(
        f"tshark -r {pcap_file} -Y \"tcp and not tcp.port==80 and not tcp.port==443{time_filter}\" "
        f"-T fields -e frame.time_epoch -e ip.src -e ip.dst -e tcp.dstport"
    )
    
    if not conn_data:
        print("No data found for beaconing analysis")
        return None
    
    # Process data into time series per connection
    connections = {}
    for line in conn_data.strip().split('\n'):
        parts = line.split()
        if len(parts) >= 4:
            try:
                ts = float(parts[0])
                src = parts[1]
                dst = parts[2]
                port = parts[3]
                
                conn_key = f"{src}:{dst}:{port}"
                if conn_key not in connections:
                    connections[conn_key] = []
                connections[conn_key].append(ts)
            except:
                continue
    
    # Analyze time intervals for regularity
    beaconing_results = []
    for conn_key, timestamps in connections.items():
        if len(timestamps) < 5:  # Need enough samples
            continue
        
        # Sort timestamps and calculate intervals
        timestamps.sort()
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        # Basic statistics
        avg_interval = sum(intervals) / len(intervals)
        
        # Calculate coefficient of variation (CV) - lower means more regular
        if len(intervals) > 1:
            stdev = (sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)) ** 0.5
            cv = stdev / avg_interval if avg_interval > 0 else float('inf')
            
            # CV under 0.1 indicates high regularity (potential beaconing)
            if cv < 0.1 and len(timestamps) >= 10:  # At least 10 samples
                src, dst, port = conn_key.split(':')
                beaconing_results.append({
                    'connection': conn_key,
                    'interval': avg_interval,
                    'cv': cv,
                    'count': len(timestamps),
                    'src': src,
                    'dst': dst,
                    'port': port
                })
    
    # Sort by regularity (CV)
    beaconing_results.sort(key=lambda x: x['cv'])
    
    if beaconing_results:
        print(f"Found {len(beaconing_results)} potential beaconing connections")
        for result in beaconing_results[:10]:  # Show top 10
            print(f"{result['src']} → {result['dst']}:{result['port']}: "
                  f"interval={result['interval']:.2f}s, regularity={1-result['cv']:.2%}, "
                  f"samples={result['count']}")
    else:
        print("No beaconing patterns detected")
    
    return beaconing_results 