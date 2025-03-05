#!/usr/bin/env python3
from ..core.command import run_command, run_command_with_retry
from ..core.security import sanitize_filter
import logging
import os
import re

logger = logging.getLogger(__name__)

def detect_port_scan(pcap_file, threshold=10, time_filter=""):
    """
    Detect potential port scanning activity.
    
    Args:
        pcap_file: Path to the PCAP file
        threshold: Minimum number of ports accessed to consider as scan
        time_filter: Optional time filter
        
    Returns:
        dict: Different port scan detection results
    """
    logger.info(f"Detecting port scanning activity (threshold: {threshold})")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    results = {}
    
    try:
        # Look for SYN packets to multiple ports from same source
        port_scan = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"tcp.flags.syn==1 and tcp.flags.ack==0{safe_time_filter}\" "
            f"-T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 20",
            verbose=False
        )
        
        if port_scan:
            port_scan_lines = port_scan.strip().split('\n')
            logger.info(f"Detected {len(port_scan_lines)} potential port scanning activities")
            
            # Analyze port scan data to find scanners above threshold
            scanners = []
            for line in port_scan_lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        count = int(parts[0])
                        if count >= threshold:
                            src_ip = parts[1]
                            dst_ip = parts[2]
                            scanners.append({"src_ip": src_ip, "dst_ip": dst_ip, "port_count": count})
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error parsing port scan data: {line}")
            
            if scanners:
                logger.info(f"Identified {len(scanners)} port scanners above threshold {threshold}")
                results["scanners"] = scanners
        else:
            logger.info("No port scanning activity detected")
        
        results["port_scan"] = port_scan
        
        # Check for sequential port access pattern
        sequential_ports = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"tcp.flags.syn==1 and tcp.flags.ack==0{safe_time_filter}\" "
            f"-T fields -e ip.src -e ip.dst -e tcp.dstport | sort | head -n 30",
            verbose=False
        )
        
        results["sequential_ports"] = sequential_ports
        
        # Analyze port scan timing (fast scan detection)
        fast_scan = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0.1 | grep -v \"0.000000\"",
            verbose=False
        )
        
        if fast_scan:
            logger.info("Detected high-rate port scanning activity")
        
        results["fast_scan"] = fast_scan
        
        return results
    
    except Exception as e:
        logger.error(f"Error in port scan detection: {str(e)}")
        return {"error": str(e)}

def detect_ddos(pcap_file, time_filter=""):
    """
    Detect potential DDoS/DoS activity.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        dict: Different DDoS/DoS detection results
    """
    logger.info("Detecting DDoS/DoS activity")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    results = {}
    
    try:
        # Look for high volume of traffic to same destination
        traffic_volume = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z ip.dst,tree | sort -k 2nr | head -n 20",
            verbose=False
        )
        
        results["traffic_volume"] = traffic_volume
        
        # HTTP-based DoS detection
        http_flood = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"http.request{safe_time_filter}\" -T fields "
            f"-e ip.src -e http.request.uri | sort | uniq -c | sort -nr | head -n 15",
            verbose=False
        )
        
        results["http_flood"] = http_flood
        
        # DNS amplification detection
        dns_amplification = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"dns.qry.type == 255 or dns.qry.class == 255{safe_time_filter}\" "
            f"-T fields -e ip.src -e ip.dst -e dns.qry.name",
            verbose=False
        )
        
        results["dns_amplification"] = dns_amplification
        
        # ICMP flood detection
        icmp_flood = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"icmp{safe_time_filter}\" -T fields "
            f"-e ip.src -e ip.dst | sort | uniq -c | sort -nr | head -n 15",
            verbose=False
        )
        
        results["icmp_flood"] = icmp_flood
        
        # Analyze the results to identify potential DoS attacks
        if traffic_volume or http_flood or dns_amplification or icmp_flood:
            logger.info("Detected potential DDoS/DoS activity")
            
            # Advanced analysis: Calculate packets per second to identify DoS
            pps_analysis = run_command_with_retry(
                f"tshark -r {pcap_file} -q -z io,stat,1,ip.dst,ip.proto,COUNT(frame)",
                verbose=False
            )
            
            if pps_analysis:
                results["packets_per_second"] = pps_analysis
        else:
            logger.info("No significant DDoS/DoS activity detected")
        
        return results
    
    except Exception as e:
        logger.error(f"Error in DDoS detection: {str(e)}")
        return {"error": str(e)}

def detect_syn_flood(pcap_file, threshold=100, time_filter=""):
    """
    Detect potential SYN flood attacks.
    
    Args:
        pcap_file: Path to the PCAP file
        threshold: Minimum number of SYN packets to consider as flood
        time_filter: Optional time filter
        
    Returns:
        dict: SYN flood detection results
    """
    logger.info(f"Detecting SYN flood attacks (threshold: {threshold})")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    results = {}
    
    try:
        # Look for high volume of SYN packets to same destination
        syn_packets = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"tcp.flags.syn==1 and tcp.flags.ack==0{safe_time_filter}\" "
            f"-T fields -e ip.src -e ip.dst -e tcp.dstport | sort | uniq -c | sort -nr | head -n 20",
            verbose=False
        )
        
        if syn_packets:
            syn_flood_lines = syn_packets.strip().split('\n')
            logger.info(f"Detected {len(syn_flood_lines)} potential SYN flood sources")
            
            # Analyze SYN packet data to find attackers above threshold
            syn_flooders = []
            for line in syn_flood_lines:
                parts = line.strip().split()
                if len(parts) >= 4:
                    try:
                        count = int(parts[0])
                        if count >= threshold:
                            src_ip = parts[1]
                            dst_ip = parts[2]
                            dst_port = parts[3]
                            syn_flooders.append({
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "dst_port": dst_port,
                                "syn_count": count
                            })
                    except (ValueError, IndexError) as e:
                        logger.warning(f"Error parsing SYN flood data: {line}")
            
            if syn_flooders:
                logger.info(f"Identified {len(syn_flooders)} SYN flooders above threshold {threshold}")
                results["syn_flooders"] = syn_flooders
        else:
            logger.info("No SYN flood activity detected")
        
        results["syn_packets"] = syn_packets
        
        # Check for incomplete TCP handshakes (SYN without SYN-ACK or ACK)
        incomplete_handshakes = run_command_with_retry(
            f"tshark -r {pcap_file} -q -Y \"tcp.flags.syn==1 and not tcp.flags.ack==1{safe_time_filter}\" | wc -l",
            verbose=False
        )
        
        if incomplete_handshakes:
            try:
                incomplete_count = int(incomplete_handshakes.strip())
                results["incomplete_handshakes_count"] = incomplete_count
                if incomplete_count > threshold:
                    logger.info(f"High number of incomplete TCP handshakes: {incomplete_count}")
            except ValueError:
                logger.warning(f"Error parsing incomplete handshakes count: {incomplete_handshakes}")
        
        return results
    
    except Exception as e:
        logger.error(f"Error in SYN flood detection: {str(e)}")
        return {"error": str(e)}

def correlate_attacks(pcap_file, time_filter=""):
    """
    Correlate different attacks to identify complex attack patterns.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        dict: Correlated attack analysis results
    """
    logger.info("Correlating attacks to identify complex patterns")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    results = {}
    
    try:
        # Get all source IPs involved in potential attacks
        attack_sources = run_command_with_retry(
            f"tshark -r {pcap_file} -q -Y \"(tcp.flags.syn==1 and not tcp.flags.ack==1) or "
            f"(http.request and http.request.method=='POST') or "
            f"(icmp) or (dns.flags.response == 0){safe_time_filter}\" "
            f"-T fields -e ip.src | sort | uniq",
            verbose=False
        )
        
        if attack_sources:
            sources = attack_sources.strip().split('\n')
            logger.info(f"Identified {len(sources)} potential attack sources")
            
            correlated_attacks = []
            
            for source in sources:
                source = source.strip()
                if not source:
                    continue
                
                source_attacks = {}
                source_attacks["ip"] = source
                
                # Check for port scanning from this source
                port_scan = run_command_with_retry(
                    f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"ip.src == {source} and tcp.flags.syn==1 "
                    f"and tcp.flags.ack==0{safe_time_filter}\" | wc -l",
                    verbose=False
                )
                
                # Check for HTTP attacks from this source
                http_attacks = run_command_with_retry(
                    f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"ip.src == {source} and http.request{safe_time_filter}\" "
                    f"-T fields -e http.request.uri | wc -l",
                    verbose=False
                )
                
                # Check for DNS queries from this source
                dns_queries = run_command_with_retry(
                    f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"ip.src == {source} and dns.flags.response == 0"
                    f"{safe_time_filter}\" | wc -l",
                    verbose=False
                )
                
                # Calculate the attack phase timeline
                timeline = run_command_with_retry(
                    f"tshark -r {pcap_file} -q -Y \"ip.src == {source}{safe_time_filter}\" -T fields "
                    f"-e frame.time -e frame.protocols | head -n 10",
                    verbose=False
                )
                
                try:
                    source_attacks["port_scan_count"] = int(port_scan.strip() or "0")
                    source_attacks["http_attacks_count"] = int(http_attacks.strip() or "0")
                    source_attacks["dns_queries_count"] = int(dns_queries.strip() or "0")
                    source_attacks["timeline"] = timeline
                    
                    # Determine attack profile
                    attack_types = []
                    if source_attacks["port_scan_count"] > 10:
                        attack_types.append("port_scan")
                    if source_attacks["http_attacks_count"] > 10:
                        attack_types.append("http_flood")
                    if source_attacks["dns_queries_count"] > 10:
                        attack_types.append("dns_attack")
                    
                    source_attacks["attack_types"] = attack_types
                    
                    if attack_types:
                        correlated_attacks.append(source_attacks)
                
                except (ValueError, TypeError) as e:
                    logger.warning(f"Error processing attack data for source {source}: {str(e)}")
            
            if correlated_attacks:
                logger.info(f"Identified {len(correlated_attacks)} correlated attack patterns")
                results["correlated_attacks"] = correlated_attacks
        else:
            logger.info("No significant attack sources identified for correlation")
        
        # Check for attack progression (reconnaissance -> exploitation -> persistence)
        attack_progression = run_command_with_retry(
            f"tshark -r {pcap_file} -q -z io,stat,30 -T fields -e _ws.col.Protocol | sort | uniq -c",
            verbose=False
        )
        
        results["attack_progression"] = attack_progression
        
        return results
    
    except Exception as e:
        logger.error(f"Error in attack correlation: {str(e)}")
        return {"error": str(e)}

def verify_packets(pcap_file, frame_numbers):
    """
    Verify packets by extracting their details.
    
    Args:
        pcap_file: Path to the PCAP file
        frame_numbers: List of frame numbers to verify
        
    Returns:
        str: Packet details
    """
    if not frame_numbers:
        logger.warning("No frame numbers provided for verification")
        return None
    
    try:
        # Convert frame numbers to string
        if isinstance(frame_numbers, list):
            frame_numbers = " or ".join([f"frame.number == {num}" for num in frame_numbers])
        
        # Sanitize the frame numbers
        frame_numbers = re.sub(r'[^0-9\s\=\|\(\)]', '', str(frame_numbers))
        
        # Get packet details
        packet_details = run_command_with_retry(
            f"tshark -r {pcap_file} -Y \"{frame_numbers}\" -V",
            verbose=False
        )
        
        if packet_details:
            logger.info(f"Retrieved packet details for frame(s) {frame_numbers}")
            return packet_details
        else:
            logger.warning(f"No packet details found for frame(s) {frame_numbers}")
            return None
    
    except Exception as e:
        logger.error(f"Error verifying packets: {str(e)}")
        return None

def reconstruct_session(pcap_file, ip_src, ip_dst, tcp_stream_index=None):
    """
    Reconstruct a TCP session between two IP addresses.
    
    Args:
        pcap_file: Path to the PCAP file
        ip_src: Source IP address
        ip_dst: Destination IP address
        tcp_stream_index: Optional TCP stream index to specify a particular stream
        
    Returns:
        str: Reconstructed session data
    """
    logger.info(f"Reconstructing session between {ip_src} and {ip_dst}")
    
    try:
        # Sanitize IP addresses
        ip_src = re.sub(r'[^0-9\.]', '', ip_src)
        ip_dst = re.sub(r'[^0-9\.]', '', ip_dst)
        
        if tcp_stream_index is not None:
            # Sanitize TCP stream index
            tcp_stream_index = re.sub(r'[^0-9]', '', str(tcp_stream_index))
            
            # Get session data for specific TCP stream
            session_data = run_command_with_retry(
                f"tshark -r {pcap_file} -q -z \"follow,tcp,ascii,{tcp_stream_index}\"",
                verbose=False
            )
        else:
            # Find TCP stream indexes for the IP pair
            stream_indexes = run_command_with_retry(
                f"tshark -r {pcap_file} -q -Y \"(ip.src == {ip_src} and ip.dst == {ip_dst}) or "
                f"(ip.src == {ip_dst} and ip.dst == {ip_src})\" -T fields -e tcp.stream | sort -n | uniq",
                verbose=False
            )
            
            if not stream_indexes:
                logger.warning(f"No TCP streams found between {ip_src} and {ip_dst}")
                return None
            
            # Use the first stream index
            first_stream = stream_indexes.strip().split('\n')[0]
            
            # Get session data
            session_data = run_command_with_retry(
                f"tshark -r {pcap_file} -q -z \"follow,tcp,ascii,{first_stream}\"",
                verbose=False
            )
        
        if session_data:
            logger.info(f"Successfully reconstructed session data")
            return session_data
        else:
            logger.warning(f"No session data reconstructed")
            return None
    
    except Exception as e:
        logger.error(f"Error reconstructing session: {str(e)}")
        return None 