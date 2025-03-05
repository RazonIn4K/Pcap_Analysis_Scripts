#!/usr/bin/env python3
from ..core.command import run_command

def detect_packet_anomalies(pcap_file, time_filter=""):
    """Detect unusual packet characteristics"""
    print("\n=== Packet Anomalies ===")
    results = {}
    
    # Find unusually large packets
    large_packets = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y 'frame.len > 1500{time_filter}' "
        f"-T fields -e frame.number -e frame.len -e ip.src -e ip.dst | head -n 15",
        verbose=False
    )
    print("\n-- Unusually Large Packets --")
    print(large_packets or "No unusually large packets detected")
    results["large_packets"] = large_packets
    
    # Find fragmented packets (potential evasion)
    fragmented = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y 'ip.flags.mf == 1 or ip.frag_offset > 0{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15",
        verbose=False
    )
    print("\n-- Fragmented Packets --")
    print(fragmented or "No fragmented packets detected")
    results["fragmented"] = fragmented
    
    # Check for TCP window size anomalies
    window_anomalies = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y 'tcp.window_size == 0 and tcp.flags.reset == 0{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15",
        verbose=False
    )
    print("\n-- TCP Window Size Zero (Potential DoS) --")
    print(window_anomalies or "No TCP window size anomalies detected")
    results["window_anomalies"] = window_anomalies
    
    # Unusual TTL values (possible spoofing or covert channel)
    unusual_ttl = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y 'ip.ttl < 10 or ip.ttl > 250{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst -e ip.ttl | head -n 15",
        verbose=False
    )
    print("\n-- Unusual TTL Values (Potential Spoofing) --")
    print(unusual_ttl or "No unusual TTL values detected")
    results["unusual_ttl"] = unusual_ttl
    
    # TCP retransmissions (network issues or potential DoS)
    retransmissions = run_command(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y 'tcp.analysis.retransmission{time_filter}' "
        f"-T fields -e frame.number -e ip.src -e ip.dst | head -n 15",
        verbose=False
    )
    print("\n-- TCP Retransmissions --")
    print(retransmissions or "No TCP retransmissions detected")
    results["retransmissions"] = retransmissions
    
    return results

def detect_anomalies(pcap_file, time_filter=""):
    """Use statistical methods to detect traffic anomalies"""
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
        ML_AVAILABLE = True
    except ImportError:
        print("Error: scikit-learn and numpy are required for ML analysis. Install with 'pip install scikit-learn numpy'")
        return None
        
    print("\n=== Machine Learning Anomaly Detection ===")
    
    # Extract features for anomaly detection
    packet_data = run_command(
        f"tshark -r {pcap_file} -T fields -e frame.time_epoch -e ip.src -e ip.dst -e frame.len "
        f"-e tcp.window_size -e _ws.col.Protocol{time_filter}",
        verbose=False
    )
    
    if not packet_data:
        print("No packet data found for anomaly detection")
        return None
    
    # Process the data
    features = []
    connections = {}
    timestamps = []
    
    for line in packet_data.strip().split("\n"):
        parts = line.split()
        if len(parts) >= 6:
            try:
                ts = float(parts[0])
                src = parts[1]
                dst = parts[2]
                length = int(parts[3])
                window = int(parts[4]) if parts[4] else 0
                protocol = parts[5]
                
                connection_key = f"{src}:{dst}"
                if connection_key not in connections:
                    connections[connection_key] = []
                
                connections[connection_key].append(length)
                timestamps.append(ts)
                features.append([length, window, hash(protocol) % 100])  # Protocol as numeric feature
            except Exception:
                continue
    
    if not features:
        print("Could not extract valid features for anomaly detection")
        return None
    
    # Convert to numpy array for ML processing
    X = np.array(features)
    
    # Run Isolation Forest for outlier detection
    print("Training anomaly detection model...")
    model = IsolationForest(contamination=0.05, random_state=42)
    predictions = model.fit_predict(X)
    
    # Find anomalous packets
    anomaly_indices = np.where(predictions == -1)[0]
    print(f"Detected {len(anomaly_indices)} potentially anomalous packets")
    
    # Extract anomalous connections
    anomalous_connections = set()
    for idx in anomaly_indices:
        if idx < len(packet_data.strip().split("\n")):
            line = packet_data.strip().split("\n")[idx]
            parts = line.split()
            if len(parts) >= 3:
                anomalous_connections.add(f"{parts[1]}:{parts[2]}")
    
    # Generate statistics about anomalous connections
    connection_stats = {}
    for conn in anomalous_connections:
        src, dst = conn.split(":")
        sizes = connections.get(conn, [])
        if sizes:
            connection_stats[conn] = {
                "packet_count": len(sizes),
                "avg_size": sum(sizes) / len(sizes),
                "max_size": max(sizes),
                "src": src,
                "dst": dst
            }
    
    # Sort by packet count
    sorted_connections = sorted(connection_stats.items(), 
                              key=lambda x: x[1]["packet_count"], 
                              reverse=True)
    
    print("\n=== Top Anomalous Connections ===")
    for conn, stats in sorted_connections[:10]:  # Top 10 anomalous connections
        print(f"{conn}: {stats['packet_count']} packets, avg size: {stats['avg_size']:.1f}, max size: {stats['max_size']}")
    
    return {
        "anomaly_count": len(anomaly_indices),
        "anomalous_connections": connection_stats
    } 