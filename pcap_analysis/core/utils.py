#!/usr/bin/env python3
import math
import os
import platform
import subprocess
import logging
import time
import random
import re
import socket
import json
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Dict, Any, Optional, Callable, TypeVar, Generic, Union, List, Tuple

logger = logging.getLogger(__name__)

T = TypeVar('T')

class RetryableOperation(Generic[T]):
    """A class to handle retryable operations with exponential backoff and jitter"""
    
    def __init__(
        self,
        operation: Callable[[], T],
        max_retries: int = 3,
        initial_backoff: float = 1.0,
        backoff_factor: float = 2.0,
        max_backoff: float = 30.0,
        jitter: float = 0.1,
        retryable_errors: Optional[tuple] = None
    ):
        """
        Initialize a retryable operation.
        
        Args:
            operation: The function to retry
            max_retries: Maximum number of retry attempts
            initial_backoff: Initial backoff time in seconds
            backoff_factor: Factor to increase backoff time between retries
            max_backoff: Maximum backoff time in seconds
            jitter: Random jitter factor to add to backoff (0-1)
            retryable_errors: Tuple of exception types that should trigger a retry
        """
        self.operation = operation
        self.max_retries = max_retries
        self.initial_backoff = initial_backoff
        self.backoff_factor = backoff_factor
        self.max_backoff = max_backoff
        self.jitter = jitter
        
        # Import these locally to avoid circular imports
        from .errors import CommandError, TimeoutError, NetworkError
        
        self.retryable_errors = retryable_errors or (
            CommandError, 
            TimeoutError, 
            NetworkError, 
            DependencyError,
            subprocess.CalledProcessError,
            ConnectionError,
            socket.timeout,
            IOError
        )
    
    def execute(self) -> T:
        """
        Execute the operation with retries and exponential backoff.
        
        Returns:
            The result of the operation
            
        Raises:
            The last exception encountered if all retries fail
        """
        last_error = None
        backoff = self.initial_backoff
        
        for attempt in range(self.max_retries + 1):
            try:
                result = self.operation()
                if attempt > 0:
                    logger.info(f"Operation succeeded on attempt {attempt + 1} after previous failures")
                return result
            except self.retryable_errors as e:
                last_error = e
                
                # Don't sleep after the last attempt
                if attempt < self.max_retries:
                    # Add jitter to prevent thundering herd problem
                    jitter_amount = random.uniform(0, self.jitter * backoff) if self.jitter > 0 else 0
                    sleep_time = backoff + jitter_amount
                    
                    logger.warning(
                        f"Attempt {attempt + 1}/{self.max_retries + 1} failed: {e}. "
                        f"Retrying in {sleep_time:.2f} seconds."
                    )
                    time.sleep(sleep_time)
                    backoff = min(backoff * self.backoff_factor, self.max_backoff)
                else:
                    logger.error(f"All {self.max_retries + 1} attempts failed. Last error: {e}")
        
        # If we get here, all retries failed
        assert last_error is not None
        raise last_error

# Keep track of verified dependencies and versions
_verified_dependencies = {}
_dependency_versions = {}

class DependencyError(Exception):
    """Exception raised when a dependency is missing or version incompatible"""
    def __init__(self, dependency: str, install_instructions: str = None, required_version: str = None):
        self.dependency = dependency
        self.install_instructions = install_instructions
        self.required_version = required_version
        
        message = f"Required dependency not found: {dependency}"
        if required_version:
            message = f"Required dependency version not met: {dependency} (need {required_version})"
        if install_instructions:
            message += f"\n{install_instructions}"
        super().__init__(message)

@lru_cache(maxsize=32)
def get_dependency_version(dependency: str) -> Optional[str]:
    """
    Get the version of an installed dependency.
    
    Args:
        dependency: The dependency to check
        
    Returns:
        str: Version string or None if not found/error
    """
    try:
        if dependency == "tshark":
            output = subprocess.check_output(["tshark", "--version"], text=True)
            match = re.search(r"TShark \(Wireshark\) (\d+\.\d+\.\d+)", output)
            if match:
                return match.group(1)
        elif dependency == "python":
            import sys
            return sys.version.split()[0]
        # Add more dependencies as needed
        
        return None
    except Exception as e:
        logger.debug(f"Error getting version for {dependency}: {e}")
        return None

def check_min_version(current: str, minimum: str) -> bool:
    """
    Check if a version meets the minimum required version.
    
    Args:
        current: Current version string (e.g., "3.2.1")
        minimum: Minimum required version string (e.g., "3.0.0")
        
    Returns:
        bool: True if current version meets or exceeds minimum
    """
    if not current or not minimum:
        return False
        
    # Parse version strings into numeric components
    try:
        current_parts = [int(x) for x in current.split(".")]
        minimum_parts = [int(x) for x in minimum.split(".")]
        
        # Pad with zeros if needed
        while len(current_parts) < len(minimum_parts):
            current_parts.append(0)
        while len(minimum_parts) < len(current_parts):
            minimum_parts.append(0)
        
        # Compare each component
        for c, m in zip(current_parts, minimum_parts):
            if c > m:
                return True
            if c < m:
                return False
        
        # If we get here, they're equal
        return True
    except (ValueError, AttributeError):
        logger.warning(f"Invalid version format: {current} or {minimum}")
        return False

def verify_dependency(dependency: str, min_version: str = None) -> bool:
    """
    Verify that a dependency is installed and optionally check its version.
    
    Args:
        dependency: The dependency command to check
        min_version: Minimum required version if applicable
        
    Returns:
        bool: True if the dependency is available and meets version requirements
        
    Raises:
        DependencyError: If the dependency is not available or version is insufficient
    """
    # Check if we've already verified this dependency
    dependency_key = f"{dependency}_{min_version}" if min_version else dependency
    if dependency_key in _verified_dependencies:
        return _verified_dependencies[dependency_key]
    
    # Prepare platform-specific command
    system = platform.system()
    
    try:
        if system == "Windows":
            # Use where on Windows
            cmd = f"where {dependency}"
            use_shell = True
        else:
            # Use which on Unix-like systems
            cmd = f"which {dependency}"
            use_shell = True
        
        # Run the verification command
        process = subprocess.run(
            cmd,
            shell=use_shell,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        # Check if the command succeeded
        dependency_exists = process.returncode == 0
        
        if dependency_exists:
            # Check version if needed
            if min_version:
                version = get_dependency_version(dependency)
                if version:
                    _dependency_versions[dependency] = version
                    version_ok = check_min_version(version, min_version)
                    if not version_ok:
                        logger.error(f"Dependency '{dependency}' version {version} is below required {min_version}")
                        _verified_dependencies[dependency_key] = False
                        
                        # Prepare install upgrade instructions
                        install_instructions = f"Please upgrade {dependency} to version {min_version} or higher"
                        raise DependencyError(dependency, install_instructions, min_version)
                else:
                    logger.warning(f"Could not determine version for '{dependency}', continuing anyway")
            
            logger.debug(f"Dependency '{dependency}' verified")
            _verified_dependencies[dependency_key] = True
            return True
        else:
            logger.error(f"Dependency '{dependency}' not found")
            _verified_dependencies[dependency_key] = False
            
            # Prepare install instructions based on platform and dependency
            install_instructions = None
            if dependency == "tshark":
                if system == "Darwin":  # macOS
                    install_instructions = "Install with: brew install wireshark"
                elif system == "Linux":
                    install_instructions = "Install with: sudo apt-get install wireshark-common or equivalent for your distribution"
                elif system == "Windows":
                    install_instructions = "Download and install from https://www.wireshark.org/download.html"
            
            raise DependencyError(dependency, install_instructions)
    
    except Exception as e:
        if isinstance(e, DependencyError):
            raise
        logger.error(f"Error verifying dependency '{dependency}': {e}")
        _verified_dependencies[dependency_key] = False
        raise DependencyError(dependency)

def calculate_entropy(string: str) -> float:
    """
    Calculate Shannon entropy of a string - useful for DGA detection.
    
    Args:
        string: The string to calculate entropy for
        
    Returns:
        float: Shannon entropy value (higher means more random/complex)
    """
    if not string:
        return 0
        
    prob = {}
    for char in string:
        if char in prob:
            prob[char] += 1
        else:
            prob[char] = 1
    
    entropy = 0
    for char in prob:
        p = prob[char] / len(string)
        entropy -= p * (math.log(p) / math.log(2))
    
    return entropy

def ensure_dir(directory: str) -> str:
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory: Directory path to create if it doesn't exist
        
    Returns:
        str: Path to the directory
        
    Raises:
        OSError: If directory cannot be created or accessed
    """
    try:
        if directory:
            path = Path(directory)
            path.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Ensured directory exists: {directory}")
        else:
            # Use default temp directory if none specified
            directory = tempfile.mkdtemp(prefix="pcap_analyzer_")
            logger.info(f"Created temporary directory: {directory}")
        return directory
    except Exception as e:
        logger.error(f"Error creating directory {directory}: {e}")
        raise OSError(f"Failed to create directory {directory}: {e}")

def format_time_filter(start_time=None, end_time=None) -> str:
    """
    Format a time filter string for tshark commands.
    
    Args:
        start_time: Start time string in format tshark understands
        end_time: End time string in format tshark understands
        
    Returns:
        str: Formatted time filter string for tshark
    """
    time_filter = ""
    try:
        if start_time and end_time:
            # Ensure properly quoted
            start_time = start_time.replace('"', '\\"')
            end_time = end_time.replace('"', '\\"')
            time_filter = f" and (frame.time >= \"{start_time}\" and frame.time <= \"{end_time}\")"
        elif start_time:
            start_time = start_time.replace('"', '\\"')
            time_filter = f" and (frame.time >= \"{start_time}\")"
        elif end_time:
            end_time = end_time.replace('"', '\\"')
            time_filter = f" and (frame.time <= \"{end_time}\")"
    except Exception as e:
        logger.warning(f"Error formatting time filter: {e}")
    
    return time_filter

def is_valid_pcap(filepath: str) -> bool:
    """
    Check if a file is a valid PCAP/PCAPNG file.
    
    Args:
        filepath: Path to the file to check
        
    Returns:
        bool: True if valid PCAP/PCAPNG file
    """
    if not os.path.isfile(filepath):
        logger.error(f"File not found: {filepath}")
        return False
    
    try:
        # Check file signature (magic bytes)
        with open(filepath, 'rb') as f:
            magic = f.read(4)
        
        # PCAP magic bytes: 0xd4c3b2a1 or 0xa1b2c3d4
        # PCAPNG magic bytes: 0x0a0d0d0a
        valid_pcap_magic = magic in [
            b'\xd4\xc3\xb2\xa1',  # PCAP (little endian)
            b'\xa1\xb2\xc3\xd4',  # PCAP (big endian)
            b'\x0a\x0d\x0d\x0a'   # PCAPNG
        ]
        
        if valid_pcap_magic:
            return True
        
        # If magic check fails, try running capinfos as a backup check
        if verify_dependency("capinfos", raise_on_error=False):
            process = subprocess.run(
                ["capinfos", "-t", filepath],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            if process.returncode == 0:
                return True
        
        logger.error(f"Not a valid PCAP/PCAPNG file: {filepath}")
        return False
    
    except Exception as e:
        logger.error(f"Error checking if {filepath} is a valid PCAP file: {e}")
        return False

def verify_dependency(dependency: str, min_version: str = None, raise_on_error: bool = True) -> bool:
    """
    Verify that a dependency is installed and optionally check its version.
    
    Args:
        dependency: The dependency command to check
        min_version: Minimum required version if applicable
        raise_on_error: Whether to raise an exception on error
        
    Returns:
        bool: True if the dependency is available and meets version requirements
    """
    try:
        return _verify_dependency(dependency, min_version)
    except DependencyError as e:
        if raise_on_error:
            raise
        logger.error(str(e))
        return False

def get_file_hash(filepath: str, algorithm: str = 'sha256') -> str:
    """
    Calculate the hash of a file.
    
    Args:
        filepath: Path to the file
        algorithm: Hash algorithm to use ('md5', 'sha1', 'sha256')
        
    Returns:
        str: Hex digest of the file hash or empty string on error
    """
    try:
        import hashlib
        
        algorithms = {
            'md5': hashlib.md5,
            'sha1': hashlib.sha1,
            'sha256': hashlib.sha256
        }
        
        if algorithm not in algorithms:
            logger.warning(f"Unsupported hash algorithm: {algorithm}, using sha256 instead")
            algorithm = 'sha256'
        
        hash_obj = algorithms[algorithm]()
        
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {e}")
        return ""

def get_ip_info(ip_address: str) -> Dict[str, Any]:
    """
    Get information about an IP address.
    
    Args:
        ip_address: The IP address to look up
        
    Returns:
        dict: IP information including geolocation if available
    """
    result = {
        'ip': ip_address,
        'is_private': is_private_ip(ip_address),
        'type': 'Unknown'
    }
    
    try:
        # Classify the IP
        if result['is_private']:
            result['type'] = 'Private'
        elif ip_address.startswith('127.'):
            result['type'] = 'Localhost'
        elif ip_address.startswith('169.254.'):
            result['type'] = 'Link-local'
        elif ip_address.startswith('224.') or ip_address.startswith('239.'):
            result['type'] = 'Multicast'
        else:
            result['type'] = 'Public'
        
        # Try to get hostname
        try:
            result['hostname'] = socket.gethostbyaddr(ip_address)[0]
        except socket.herror:
            result['hostname'] = None
        
        # For internet-facing analysis, you could integrate with IP geolocation APIs here
        # This is left as a placeholder
        
        return result
    except Exception as e:
        logger.error(f"Error getting IP info for {ip_address}: {e}")
        return result

def is_private_ip(ip_address: str) -> bool:
    """
    Check if an IP address is in a private range.
    
    Args:
        ip_address: The IP address to check
        
    Returns:
        bool: True if the IP is in a private range
    """
    try:
        # Convert string IP to a packed format
        packed_ip = socket.inet_aton(ip_address)
        ip_int = int.from_bytes(packed_ip, byteorder='big')
        
        # Check private IP ranges
        private_ranges = [
            (int.from_bytes(socket.inet_aton('10.0.0.0'), byteorder='big'),
             int.from_bytes(socket.inet_aton('10.255.255.255'), byteorder='big')),
            (int.from_bytes(socket.inet_aton('172.16.0.0'), byteorder='big'),
             int.from_bytes(socket.inet_aton('172.31.255.255'), byteorder='big')),
            (int.from_bytes(socket.inet_aton('192.168.0.0'), byteorder='big'),
             int.from_bytes(socket.inet_aton('192.168.255.255'), byteorder='big'))
        ]
        
        return any(start <= ip_int <= end for start, end in private_ranges)
    except Exception as e:
        logger.error(f"Error checking if {ip_address} is private: {e}")
        return False

def save_json(data: Any, filepath: str) -> bool:
    """
    Save data to a JSON file.
    
    Args:
        data: Data to save
        filepath: Output file path
        
    Returns:
        bool: True if successful
    """
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Data saved to {filepath}")
        return True
    except Exception as e:
        logger.error(f"Error saving data to {filepath}: {e}")
        return False

def load_json(filepath: str) -> Any:
    """
    Load data from a JSON file.
    
    Args:
        filepath: Input file path
        
    Returns:
        The loaded data or None on error
    """
    try:
        with open(filepath, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Error loading data from {filepath}: {e}")
        return None

# Rename the internal function to avoid recursion
_verify_dependency = verify_dependency 