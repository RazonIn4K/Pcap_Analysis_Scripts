#!/usr/bin/env python3
"""
Security-related functions for PCAP analysis.
"""
import os
import re
import logging
import hashlib
from pathlib import Path
from typing import Optional, Dict, Any, List, Set, Pattern, Match

from .errors import FileNotFoundError, FormatError, PermissionError

logger = logging.getLogger(__name__)

# Regular expressions for validation
VALID_PCAP_EXTENSIONS = {'.pcap', '.pcapng', '.cap', '.dmp', '.5vw', '.TRC0', '.TRC1', '.eth', '.tr', '.trace'}

# More comprehensive regex pattern for valid Wireshark display filter characters
VALID_FILTER_PATTERN = re.compile(r'^[\w\s\.\(\)\-\=\!\|\&\<\>\[\]\:\_\;\,\"\'\*\+\?\{\}\/\%\$\@\#]+$')

# Potentially dangerous patterns that could be used for command injection
POTENTIALLY_DANGEROUS_PATTERNS = [
    # Command separators and execution
    ';', '&&', '||', '`', '$(',
    # Redirection
    '>', '<', '>>', '2>', '2>&1',
    # Shell expansion
    '$(', '${', '{', '}',
    # Function calls and code execution
    'eval', 'exec', 'system', '/bin/sh', '/bin/bash', 'cmd.exe',
    # Escapes and special characters
    '\\', '\n', '\r', '\0',
    # Network-related commands that might be used in attacks
    'wget', 'curl', 'nc ', 'netcat', 'telnet',
    # File operations that might be harmful
    'rm ', 'mv ', 'dd ', 'mkfifo', '> /dev/tcp/'
]

# Regular expression to identify common attack patterns in user input
ATTACK_PATTERN = re.compile(
    r'(?:\b(?:eval|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec)\s*\()|'  # Function calls
    r'(?:(?:;|&&|\|\||\|)\s*(?:bash|sh|ksh|csh|cat|wget|curl|nc|netcat))|'              # Command injection
    r'(?:\/(?:bin|etc|usr|tmp|var)\/[a-z]+)|'                                           # Path traversal
    r'(?:(?:\.\.\/|\.\.\\)+)|'                                                          # Directory traversal
    r'(?:\/(?:dev|proc|sys)\/[a-z]+)|'                                                  # System file access
    r'(?:\$(?:\(|{)[a-zA-Z0-9_]+(?:\)|}))',                                             # Variable expansion
    re.IGNORECASE
)

def sanitize_filter(filter_text: str) -> str:
    """
    Sanitize a Wireshark display filter to prevent command injection.
    
    Args:
        filter_text: The filter text to sanitize
        
    Returns:
        str: Sanitized filter string
    """
    if not filter_text:
        return ""
    
    # Initial logging for audit trail
    logger.debug(f"Sanitizing filter: {filter_text[:100]}{'...' if len(filter_text) > 100 else ''}")
    
    # Check for potentially dangerous patterns
    for pattern in POTENTIALLY_DANGEROUS_PATTERNS:
        if pattern in filter_text:
            logger.warning(f"Potentially dangerous pattern '{pattern}' found in filter, removing")
            filter_text = filter_text.replace(pattern, '')
    
    # Check for attack patterns using regex
    if ATTACK_PATTERN.search(filter_text):
        logger.warning(f"Attack pattern detected in filter: {filter_text}")
        # Remove all matches
        filter_text = ATTACK_PATTERN.sub('', filter_text)
    
    # Validate against allowed pattern
    if not VALID_FILTER_PATTERN.match(filter_text):
        logger.warning("Filter contains invalid characters, sanitizing")
        # Keep only allowed characters
        filter_text = ''.join(c for c in filter_text if c.isalnum() or c in ' .()-=!|&<>[]:_;,"\'*+?{}/%$@#')
    
    # Validate filter length (prevent DoS through extremely long filters)
    if len(filter_text) > 1000:
        logger.warning("Filter too long, truncating to 1000 characters")
        filter_text = filter_text[:1000]
    
    # Balance quotes
    if filter_text.count('"') % 2 != 0:
        logger.warning("Unbalanced quotes in filter, adding closing quote")
        filter_text = filter_text + '"'
    
    # Ensure filter is properly quoted for tshark if it contains spaces
    if ' ' in filter_text and not (filter_text.startswith('"') and filter_text.endswith('"')):
        filter_text = f'"{filter_text}"'
    
    logger.debug(f"Sanitized filter result: {filter_text[:100]}{'...' if len(filter_text) > 100 else ''}")
    
    return filter_text

def validate_pcap_file(file_path: str) -> bool:
    """
    Validate that a file exists and is a valid PCAP file.
    
    Args:
        file_path: Path to the file to validate
        
    Returns:
        bool: True if file is valid
        
    Raises:
        FileNotFoundError: If the file does not exist
        FormatError: If the file is not a valid PCAP file
        PermissionError: If the file cannot be read
    """
    path = Path(file_path)
    
    # Check if file exists
    if not path.exists():
        logger.error(f"File not found: {file_path}")
        raise FileNotFoundError(file_path)
    
    # Check if it's a file (not a directory or other special file)
    if not path.is_file():
        logger.error(f"Not a regular file: {file_path}")
        raise FormatError(file_path, "regular file", "not a regular file")
    
    # Check if file is readable
    if not os.access(path, os.R_OK):
        logger.error(f"File not readable: {file_path}")
        raise PermissionError(file_path, "read")
    
    # Check file extension
    if path.suffix.lower() not in VALID_PCAP_EXTENSIONS:
        logger.warning(f"File has non-standard PCAP extension: {path.suffix}")
        # We don't raise an error here to allow non-standard extensions that might still be valid PCAP files
    
    # Check file size
    if path.stat().st_size == 0:
        logger.error(f"File is empty: {file_path}")
        raise FormatError(file_path, "non-empty PCAP file", "file is empty")
    
    # Basic check for minimum PCAP file size
    if path.stat().st_size < 24:  # PCAP files need at least a header
        logger.error(f"File too small to be a valid PCAP: {file_path}")
        raise FormatError(file_path, "valid PCAP file", "file too small")
    
    # Check PCAP magic number (basic validation)
    try:
        with open(path, 'rb') as f:
            header = f.read(4)
            
            # Common PCAP magic numbers
            pcap_magic_numbers = [
                b'\xd4\xc3\xb2\xa1',  # PCAP big-endian
                b'\xa1\xb2\xc3\xd4',  # PCAP little-endian
                b'\x0a\x0d\x0d\x0a',  # PCAPNG
            ]
            
            if header not in pcap_magic_numbers:
                logger.warning(f"File {file_path} does not have a standard PCAP magic number")
                # We don't raise an error here because some valid PCAP files might have different headers
    except IOError as e:
        logger.error(f"Error reading file: {file_path}, {str(e)}")
        raise PermissionError(file_path, "read")
    
    logger.debug(f"PCAP file validated: {file_path}")
    return True

def calculate_file_hash(file_path: str, algorithm: str = 'sha256') -> str:
    """
    Calculate the hash of a file.
    
    Args:
        file_path: Path to the file
        algorithm: Hash algorithm to use
        
    Returns:
        str: Hex digest of the file hash
        
    Raises:
        FileNotFoundError: If the file does not exist
        PermissionError: If the file cannot be read
    """
    path = Path(file_path)
    
    if not path.exists():
        raise FileNotFoundError(file_path)
    
    if not os.access(path, os.R_OK):
        raise PermissionError(file_path, "read")
    
    hash_function = getattr(hashlib, algorithm)()
    
    try:
        with open(path, 'rb') as f:
            # Process the file in chunks to avoid loading large files into memory
            for chunk in iter(lambda: f.read(4096), b''):
                hash_function.update(chunk)
    except IOError as e:
        logger.error(f"Error reading file for hashing: {file_path}, {str(e)}")
        raise PermissionError(file_path, "read")
    
    return hash_function.hexdigest()

def check_file_integrity(file_path: str, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """
    Check the integrity of a file by comparing its hash.
    
    Args:
        file_path: Path to the file
        expected_hash: Expected hash value
        algorithm: Hash algorithm to use
        
    Returns:
        bool: True if the file hash matches the expected hash
    """
    try:
        actual_hash = calculate_file_hash(file_path, algorithm)
        match = actual_hash.lower() == expected_hash.lower()
        
        if not match:
            logger.warning(
                f"File integrity check failed for {file_path}: "
                f"Expected {expected_hash}, got {actual_hash}"
            )
        
        return match
    except Exception as e:
        logger.error(f"Error checking file integrity: {str(e)}")
        return False

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to ensure it's safe to use.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: Sanitized filename
    """
    if not filename:
        return "unnamed_file"
    
    # Remove path separators and common shell escape characters
    filename = re.sub(r'[/\\:*?"<>|]', '_', filename)
    
    # Remove any control characters
    filename = re.sub(r'[\x00-\x1f\x7f]', '', filename)
    
    # Remove any leading/trailing whitespace
    filename = filename.strip()
    
    # Remove any leading dots or spaces (prevents hidden files)
    filename = filename.lstrip(' .')
    
    # Limit length (most filesystems have limits around 255 bytes)
    if len(filename) > 255:
        name, ext = os.path.splitext(filename)
        filename = name[:255-len(ext)] + ext
    
    # If filename became empty after sanitization, provide a default
    if not filename:
        filename = "unnamed_file"
    
    # Check for common evasion techniques
    if '..' in filename:
        filename = filename.replace('..', '__')
    
    logger.debug(f"Sanitized filename from {filename} to {filename}")
    return filename

def sanitize_output_path(output_path: str) -> str:
    """
    Sanitize an output path to ensure it's safe to use.
    
    Args:
        output_path: The output path to sanitize
        
    Returns:
        str: Sanitized output path
    """
    if not output_path:
        return "output"
    
    try:
        path = Path(output_path)
        
        # Get absolute path to prevent relative path tricks
        abs_path = path.absolute()
        
        # Check for path traversal attempts
        if '..' in str(abs_path):
            logger.warning(f"Path traversal attempt detected in path: {output_path}")
            # Replace with safe path
            return "output"
        
        # Sanitize each component of the path
        components = []
        for part in path.parts:
            if part == path.drive or part == '/':
                components.append(part)
            else:
                components.append(sanitize_filename(part))
        
        # Reconstruct the path
        sanitized_path = os.path.join(*components)
        
        # Ensure the resulting path is safe (doesn't go outside working directory)
        if os.path.isabs(sanitized_path):
            # For absolute paths, ensure they're under a safe location
            return sanitized_path
        else:
            # For relative paths, ensure they don't go above current directory
            # by replacing any remaining .. references
            while '..' in sanitized_path:
                sanitized_path = sanitized_path.replace('..', '__')
        
        logger.debug(f"Sanitized output path from {output_path} to {sanitized_path}")
        return sanitized_path
    except Exception as e:
        logger.error(f"Error sanitizing output path {output_path}: {str(e)}")
        # Return a safe default on error
        return "output"

def is_safe_command(command: str) -> bool:
    """
    Check if a command is safe to execute.
    
    Args:
        command: The command to check
        
    Returns:
        bool: True if the command appears safe
    """
    # Check for common dangerous patterns
    for pattern in POTENTIALLY_DANGEROUS_PATTERNS:
        if pattern in command:
            logger.warning(f"Potentially dangerous pattern '{pattern}' found in command")
            return False
    
    # Check for attack patterns using regex
    if ATTACK_PATTERN.search(command):
        logger.warning(f"Attack pattern detected in command: {command}")
        return False
    
    # Additional checks for command injection attempts
    suspicious_patterns = [
        r'`.*`',                # Backtick execution
        r'\$\(.*\)',            # Command substitution
        r';\s*\w+',             # Command chaining
        r'\|\s*\w+',            # Pipe to another command
        r'>\s*[^"\']*',         # Redirection to file
        r'<\s*[^"\']*',         # Input from file
        r'&\s*$',               # Background execution
        r'\bwget\b|\bcurl\b',   # Download utilities
        r'\brm\b|\bmv\b|\bcp\b' # File manipulation
    ]
    
    for pattern in suspicious_patterns:
        if re.search(pattern, command):
            logger.warning(f"Suspicious pattern found in command: {command}")
            return False
    
    return True
