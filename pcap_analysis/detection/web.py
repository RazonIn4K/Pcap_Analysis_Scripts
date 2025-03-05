#!/usr/bin/env python3
from ..core.command import run_command, run_command_with_retry
from ..core.security import sanitize_filter
import yaml
import os
import logging

logger = logging.getLogger(__name__)

def detect_sql_injection(pcap_file, time_filter=""):
    """
    Detect potential SQL injection attempts in HTTP traffic.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        str: Detected SQL injection patterns or None if none detected
    """
    logger.info("Detecting SQL injection attempts")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    sql_patterns = run_command_with_retry(
      f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"http.request.method == \\\"POST\\\" and "
      f"(http.request.uri contains \\\"%27\\\" or "
      f"http.request.uri contains \\\"SELECT\\\" or "
      f"http.request.uri contains \\\"UNION\\\" or "
      f"http.request.uri contains \\\"OR 1=1\\\" or "
      f"http.request.uri contains \\\"--\\\" or "
      f"http.request.uri contains \\\"%20OR%20\\\" or "
      f"http.request.uri contains \\\"information_schema\\\") {safe_time_filter}\" "
      f"-T fields -e frame.number -e frame.time -e ip.src -e http.request.uri",
      verbose=False
    )
    
    if sql_patterns:
        logger.info(f"Detected {sql_patterns.count(os.linesep) + 1} potential SQL injection attempts")
    else:
        logger.info("No SQL injection patterns detected")
        
    return sql_patterns

def detect_xss(pcap_file, time_filter=""):
    """
    Detect potential cross-site scripting (XSS) attempts.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        str: Detected XSS patterns or None if none detected
    """
    logger.info("Detecting XSS attacks")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    xss_patterns = run_command_with_retry(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"http contains \\\"<script>\\\" or "
        f"http contains \\\"%3Cscript%3E\\\" or "
        f"http contains \\\"javascript:\\\" or "
        f"http contains \\\"onerror=\\\" or "
        f"http contains \\\"onload=\\\" or "
        f"http contains \\\"alert(\\\" or "
        f"http contains \\\"document.cookie\\\"{safe_time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri",
        verbose=False
    )
    
    if xss_patterns:
        logger.info(f"Detected {xss_patterns.count(os.linesep) + 1} potential XSS attacks")
    else:
        logger.info("No XSS patterns detected")
        
    return xss_patterns

def detect_command_injection(pcap_file, time_filter=""):
    """
    Detect potential command injection attempts in HTTP traffic.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        str: Detected command injection patterns or None if none detected
    """
    logger.info("Detecting command injection attempts")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    # Single command to detect various command injection patterns
    cmd_patterns = run_command_with_retry(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"http contains \\\";\\\" or "
        f"http contains \\\"|\\\" or "
        f"http contains \\\"&&\\\" or "
        f"http contains \\\"||\\\" or "
        f"http contains \\\"\\\\`\\\" or "  # Properly escaped backtick
        f"http contains \\\"%3B\\\" or "
        f"http contains \\\"cat /etc\\\" or "
        f"http contains \\\"ping -c\\\" or "
        f"http contains \\\"wget\\\" or "
        f"http contains \\\"curl\\\" or "
        f"http contains \\\"bash -i\\\" or "
        f"http contains \\\"nc -e\\\" or "
        f"http contains \\\"bash -c\\\"{safe_time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri",
        verbose=False
    )
    
    if cmd_patterns:
        logger.info(f"Detected {cmd_patterns.count(os.linesep) + 1} potential command injection attempts")
    else:
        logger.info("No command injection patterns detected")
        
    return cmd_patterns

def detect_directory_traversal(pcap_file, time_filter=""):
    """
    Detect potential directory traversal attempts.
    
    Args:
        pcap_file: Path to the PCAP file
        time_filter: Optional time filter
        
    Returns:
        str: Detected directory traversal patterns or None if none detected
    """
    logger.info("Detecting directory traversal attempts")
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    traversal_patterns = run_command_with_retry(
        f"tshark -r {pcap_file} -q -z io,stat,0 -Y \"http contains \\\"../\\\" or "
        f"http contains \\\"%2e%2e%2f\\\" or "
        f"http contains \\\"..\\\\\\\" or "
        f"http contains \\\"%2e%2e%5c\\\" or "
        f"http contains \\\"etc/passwd\\\" or "
        f"http contains \\\"etc/shadow\\\" or "
        f"http contains \\\"boot.ini\\\" or "
        f"http contains \\\"win.ini\\\"{safe_time_filter}\" "
        f"-T fields -e frame.number -e ip.src -e http.request.uri",
        verbose=False
    )
    
    if traversal_patterns:
        logger.info(f"Detected {traversal_patterns.count(os.linesep) + 1} potential directory traversal attempts")
    else:
        logger.info("No directory traversal patterns detected")
        
    return traversal_patterns

def load_custom_signatures(signatures_file):
    """
    Load custom attack signatures from a YAML file.
    
    Args:
        signatures_file: Path to the YAML signatures file
        
    Returns:
        dict: Custom attack signatures or None if loading failed
    """
    if not signatures_file or not os.path.exists(signatures_file):
        logger.error(f"Signatures file not found: {signatures_file}")
        return None
    
    try:
        with open(signatures_file, 'r') as f:
            signatures = yaml.safe_load(f)
        
        logger.info(f"Loaded {len(signatures)} custom signatures from {signatures_file}")
        return signatures
    except yaml.YAMLError as e:
        logger.error(f"Error parsing YAML signatures file: {e}")
        return None
    except Exception as e:
        logger.error(f"Error loading signatures file: {e}")
        return None

def detect_custom_patterns(pcap_file, signatures, time_filter=""):
    """
    Detect custom attack patterns in PCAP file using provided signatures.
    
    Args:
        pcap_file: Path to the PCAP file
        signatures: Dictionary of signature definitions
        time_filter: Optional time filter
        
    Returns:
        dict: Results of custom pattern detection
    """
    if not signatures:
        logger.warning("No signatures provided for custom pattern detection")
        return None
    
    # Sanitize the time filter
    safe_time_filter = sanitize_filter(time_filter)
    
    results = {}
    
    try:
        for sig_name, sig_def in signatures.items():
            logger.info(f"Running custom detection: {sig_name}")
            
            # Get filter and fields from signature definition
            sig_filter = sig_def.get('filter', '')
            sig_fields = sig_def.get('fields', ['frame.number', 'ip.src'])
            
            # Skip invalid signatures
            if not sig_filter:
                logger.warning(f"Skipping invalid signature '{sig_name}': no filter defined")
                continue
            
            # Convert fields list to tshark -e parameters
            fields_param = ' '.join([f"-e {field}" for field in sig_fields])
            
            # Run detection
            sig_results = run_command_with_retry(
                f"tshark -r {pcap_file} -q -Y \"{sig_filter}{safe_time_filter}\" "
                f"-T fields {fields_param}",
                verbose=False
            )
            
            if sig_results:
                results[sig_name] = {
                    'count': sig_results.count(os.linesep) + 1,
                    'results': sig_results,
                    'filter': sig_filter
                }
                logger.info(f"Detected {results[sig_name]['count']} matches for '{sig_name}'")
            else:
                logger.info(f"No matches for '{sig_name}'")
        
        return results if results else None
    except Exception as e:
        logger.error(f"Error in custom pattern detection: {e}")
        return None 