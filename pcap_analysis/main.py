#!/usr/bin/env python3
import os
import sys
import argparse
import json
from datetime import datetime

# Import core modules
from .core.command import run_command
from .core.config import load_config, save_config
from .core.utils import calculate_entropy, check_dependencies

# Import analysis modules
from .analysis.patterns import analyze_timing_patterns, detect_beaconing
from .analysis.anomalies import detect_packet_anomalies, detect_anomalies

# Import detection modules
from .detection.web import (
    detect_sql_injection, detect_xss, detect_command_injection,
    detect_directory_traversal, load_custom_signatures, detect_custom_patterns
)
from .detection.network import (
    detect_port_scan, detect_ddos, detect_syn_flood,
    verify_packets, reconstruct_session
)
from .detection.malware import (
    detect_dns_tunneling, detect_c2_traffic, 
    detect_data_exfiltration, check_known_bad_hosts
)

# Import threat intelligence modules
from .threat_intelligence.ioc import (
    load_iocs_from_file, save_iocs_to_file, 
    fetch_iocs_from_api, merge_ioc_sources
)

# Import reporting modules
from .reporting.formatter import (
    format_json, format_yaml, format_csv,
    generate_html_report, generate_visualizations
)

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='Advanced PCAP Analysis Tool')
    
    # Input options
    parser.add_argument('pcap_file', help='Path to the PCAP file to analyze')
    parser.add_argument('--config', help='Path to configuration file')
    
    # Analysis options
    parser.add_argument('--basic', action='store_true', help='Perform basic analysis only')
    parser.add_argument('--full', action='store_true', help='Perform full analysis (all modules)')
    parser.add_argument('--time-filter', help='Time filter for analysis (Wireshark display filter format)')
    
    # Detection modules
    parser.add_argument('--detect-web', action='store_true', help='Detect web-based attacks')
    parser.add_argument('--detect-network', action='store_true', help='Detect network-based attacks')
    parser.add_argument('--detect-malware', action='store_true', help='Detect malware activity')
    parser.add_argument('--custom-signatures', help='Path to custom detection signatures file')
    
    # Threat intelligence options
    parser.add_argument('--ioc-file', help='Path to IOC file for checking')
    parser.add_argument('--fetch-iocs', help='URL to fetch IOCs from')
    parser.add_argument('--api-key', help='API key for IOC service')
    
    # Output options
    parser.add_argument('--output-dir', default='./output', help='Directory for output files')
    parser.add_argument('--output-format', choices=['json', 'yaml', 'csv', 'html', 'all'], 
                        default='json', help='Output format')
    parser.add_argument('--visualize', action='store_true', help='Generate visualizations')
    
    return parser.parse_args()

def perform_basic_analysis(pcap_file, time_filter=""):
    """Perform basic analysis of the PCAP file"""
    print("\n=== Basic PCAP Analysis ===")
    
    # Check if file exists
    if not os.path.exists(pcap_file):
        print(f"Error: PCAP file {pcap_file} not found")
        return None
    
    # Get basic file info
    file_info = run_command(f"ls -lh {pcap_file}")
    print(f"File info: {file_info}")
    
    # Get PCAP summary
    pcap_summary = run_command(f"capinfos {pcap_file}")
    print("\n=== PCAP Summary ===")
    print(pcap_summary)
    
    # Get protocol hierarchy
    protocol_hierarchy = run_command(f"tshark -r {pcap_file} -q -z io,phs")
    print("\n=== Protocol Hierarchy ===")
    print(protocol_hierarchy)
    
    # Get conversation statistics
    conversations = run_command(f"tshark -r {pcap_file} -q -z conv,ip")
    print("\n=== IP Conversations ===")
    print(conversations)
    
    # Get HTTP requests if present
    http_requests = run_command(
        f"tshark -r {pcap_file} -Y \"http.request{time_filter}\" -T fields "
        f"-e frame.time -e ip.src -e http.host -e http.request.method -e http.request.uri | head -n 20"
    )
    if http_requests:
        print("\n=== HTTP Requests ===")
        print(http_requests)
    
    # Get DNS queries if present
    dns_queries = run_command(
        f"tshark -r {pcap_file} -Y \"dns.qry.name{time_filter}\" -T fields "
        f"-e frame.time -e ip.src -e dns.qry.name | head -n 20"
    )
    if dns_queries:
        print("\n=== DNS Queries ===")
        print(dns_queries)
    
    # Return results as a dictionary
    return {
        "file_info": file_info,
        "pcap_summary": pcap_summary,
        "protocol_hierarchy": protocol_hierarchy,
        "conversations": conversations,
        "http_requests": http_requests,
        "dns_queries": dns_queries
    }

def main():
    """Main entry point for the PCAP analyzer"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Check dependencies
    if not check_dependencies():
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    os.makedirs(args.output_dir, exist_ok=True)
    
    # Load configuration if provided
    config = {}
    if args.config:
        config = load_config(args.config)
    
    # Initialize results dictionary
    results = {
        "metadata": {
            "pcap_file": args.pcap_file,
            "analysis_time": datetime.now().isoformat(),
            "command_line_args": vars(args)
        }
    }
    
    # Perform basic analysis
    basic_results = perform_basic_analysis(args.pcap_file, args.time_filter)
    if basic_results:
        results["basic_analysis"] = basic_results
    else:
        print("Error performing basic analysis")
        sys.exit(1)
    
    # Determine which modules to run
    run_web = args.detect_web or args.full
    run_network = args.detect_network or args.full
    run_malware = args.detect_malware or args.full
    
    # Run selected detection modules
    if run_web:
        print("\n=== Running Web Attack Detection ===")
        web_results = {}
        
        # SQL Injection detection
        sql_results = detect_sql_injection(args.pcap_file, time_filter=args.time_filter)
        if sql_results:
            web_results["sql_injection"] = sql_results
        
        # XSS detection
        xss_results = detect_xss(args.pcap_file, time_filter=args.time_filter)
        if xss_results:
            web_results["xss"] = xss_results
        
        # Command injection detection
        cmd_results = detect_command_injection(args.pcap_file, time_filter=args.time_filter)
        if cmd_results:
            web_results["command_injection"] = cmd_results
        
        # Directory traversal detection
        dir_results = detect_directory_traversal(args.pcap_file, time_filter=args.time_filter)
        if dir_results:
            web_results["directory_traversal"] = dir_results
        
        # Custom pattern detection
        if args.custom_signatures:
            signatures = load_custom_signatures(args.custom_signatures)
            if signatures:
                custom_results = detect_custom_patterns(args.pcap_file, signatures, time_filter=args.time_filter)
                if custom_results:
                    web_results["custom_patterns"] = custom_results
        
        results["web_attacks"] = web_results
    
    if run_network:
        print("\n=== Running Network Attack Detection ===")
        network_results = {}
        
        # Port scan detection
        port_scan_results = detect_port_scan(args.pcap_file, time_filter=args.time_filter)
        if port_scan_results:
            network_results["port_scan"] = port_scan_results
        
        # DDoS detection
        ddos_results = detect_ddos(args.pcap_file, time_filter=args.time_filter)
        if ddos_results:
            network_results["ddos"] = ddos_results
        
        # SYN flood detection
        syn_flood_results = detect_syn_flood(args.pcap_file, time_filter=args.time_filter)
        if syn_flood_results:
            network_results["syn_flood"] = syn_flood_results
        
        results["network_attacks"] = network_results
    
    if run_malware:
        print("\n=== Running Malware Activity Detection ===")
        malware_results = {}
        
        # DNS tunneling detection
        dns_tunnel_results = detect_dns_tunneling(args.pcap_file, time_filter=args.time_filter)
        if dns_tunnel_results:
            malware_results["dns_tunneling"] = dns_tunnel_results
        
        # C2 traffic detection
        c2_results = detect_c2_traffic(args.pcap_file, time_filter=args.time_filter)
        if c2_results:
            malware_results["c2_traffic"] = c2_results
        
        # Data exfiltration detection
        exfil_results = detect_data_exfiltration(args.pcap_file, time_filter=args.time_filter)
        if exfil_results:
            malware_results["data_exfiltration"] = exfil_results
        
        # Check for known bad hosts
        if args.ioc_file:
            bad_hosts_results = check_known_bad_hosts(args.pcap_file, args.ioc_file)
            if bad_hosts_results:
                malware_results["known_bad_hosts"] = bad_hosts_results
        
        # Timing pattern analysis for beaconing detection
        timing_results = analyze_timing_patterns(args.pcap_file, time_filter=args.time_filter)
        if timing_results:
            malware_results["timing_patterns"] = timing_results
        
        # Packet anomaly detection
        anomaly_results = detect_packet_anomalies(args.pcap_file, time_filter=args.time_filter)
        if anomaly_results:
            malware_results["packet_anomalies"] = anomaly_results
        
        results["malware_activity"] = malware_results
    
    # Generate output in the requested format
    output_base = os.path.join(args.output_dir, os.path.basename(args.pcap_file).split('.')[0])
    
    if args.output_format == 'json' or args.output_format == 'all':
        json_file = f"{output_base}_analysis.json"
        format_json(results, json_file)
    
    if args.output_format == 'yaml' or args.output_format == 'all':
        yaml_file = f"{output_base}_analysis.yaml"
        format_yaml(results, yaml_file)
    
    if args.output_format == 'csv' or args.output_format == 'all':
        csv_file = f"{output_base}_analysis.csv"
        format_csv(results, csv_file)
    
    if args.output_format == 'html' or args.output_format == 'all':
        html_file = f"{output_base}_analysis.html"
        generate_html_report(results, html_file)
    
    # Generate visualizations if requested
    if args.visualize:
        vis_dir = os.path.join(args.output_dir, "visualizations")
        visualizations = generate_visualizations(results, vis_dir)
        if visualizations:
            print(f"\nGenerated {len(visualizations)} visualizations in {vis_dir}")
    
    print(f"\nAnalysis complete. Results saved to {args.output_dir}")
    return 0

if __name__ == "__main__":
    sys.exit(main()) 