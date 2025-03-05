#!/usr/bin/env python3
import math
from ..core.command import run_command
from typing import Dict, List, Tuple, Optional, Union, Any
import numpy as np
import logging

logger = logging.getLogger(__name__)

def analyze_timing_patterns(
    pcap_file: str, 
    ip_addr: Optional[str] = None, 
    time_filter: str = ""
) -> Dict[str, Any]:
    """
    Analyze timing patterns between packets to detect potential C2 beaconing.
    
    This function examines the time intervals between packets to identify
    regular communication patterns that might indicate command and control
    beaconing activity.
    
    Args:
        pcap_file: Path to the PCAP file to analyze
        ip_addr: Optional IP address to filter on
        time_filter: Additional time filter in Wireshark display filter format
        
    Returns:
        Dictionary containing timing analysis results with the following keys:
        - intervals: List of time intervals between packets
        - regular_intervals: List of detected regular intervals
        - potential_beaconing: Boolean indicating if beaconing was detected
        - cv_values: Coefficient of variation values for detected intervals
        
    Raises:
        FileNotFoundError: If the PCAP file does not exist
    """
    print("\n=== Timing Pattern Analysis ===")
    results: Dict[str, Any] = {}
    
    # Build filter
    ip_filter = f" and ip.addr == {ip_addr}" if ip_addr else ""
    filter_expr = f"ip{ip_filter}{time_filter}"
    
    # Extract packet timestamps
    timestamps_str = run_command(
        f"tshark -r {pcap_file} -Y \"{filter_expr}\" "
        f"-T fields -e frame.time_epoch | sort",
        verbose=False
    )
    
    if not timestamps_str:
        print("No packets found for timing analysis")
        return {"error": "No packets found for timing analysis"}
    
    # Convert to float and calculate intervals
    try:
        timestamps = [float(ts) for ts in timestamps_str.strip().split('\n')]
        intervals = [timestamps[i+1] - timestamps[i] for i in range(len(timestamps)-1)]
        
        if not intervals:
            print("Not enough packets for timing analysis")
            return {"error": "Not enough packets for timing analysis"}
        
        results["intervals"] = intervals
        
        # Calculate statistics
        mean_interval = np.mean(intervals)
        std_interval = np.std(intervals)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        
        print(f"Mean interval: {mean_interval:.6f} seconds")
        print(f"Standard deviation: {std_interval:.6f} seconds")
        print(f"Coefficient of variation: {cv:.6f}")
        
        results["mean_interval"] = mean_interval
        results["std_interval"] = std_interval
        results["cv"] = cv
        
        # Detect regular intervals (potential beaconing)
        regular_intervals = []
        for interval in set(intervals):
            # Count occurrences with small tolerance
            tolerance = 0.01  # 10ms tolerance
            count = sum(1 for i in intervals if abs(i - interval) < tolerance)
            if count >= 3:  # At least 3 occurrences
                regular_intervals.append((interval, count))
        
        if regular_intervals:
            print("\n-- Regular Intervals Detected (Potential Beaconing) --")
            for interval, count in sorted(regular_intervals, key=lambda x: x[1], reverse=True):
                print(f"Interval: {interval:.6f} seconds, Occurrences: {count}")
            
            results["regular_intervals"] = regular_intervals
            results["potential_beaconing"] = True
        else:
            print("No regular intervals detected")
            results["potential_beaconing"] = False
        
        return results
        
    except Exception as e:
        logger.exception(f"Error analyzing timing patterns: {e}")
        return {"error": str(e)}

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