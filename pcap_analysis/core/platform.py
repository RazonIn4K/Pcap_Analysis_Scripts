import os
import sys
import platform
import logging
import shutil
from pathlib import Path

logger = logging.getLogger(__name__)

def get_platform_info():
    """
    Get information about the current platform.
    
    Returns:
        dict: Platform information
    """
    return {
        "system": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation()
    }

def is_windows():
    """Check if the current platform is Windows."""
    return platform.system() == "Windows"

def is_macos():
    """Check if the current platform is macOS."""
    return platform.system() == "Darwin"

def is_linux():
    """Check if the current platform is Linux."""
    return platform.system() == "Linux"

def get_config_dir():
    """
    Get the platform-specific configuration directory.
    
    Returns:
        Path: Path to the configuration directory
    """
    if is_windows():
        base_dir = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(base_dir) / "pcap-analyzer"
    elif is_macos():
        return Path.home() / "Library" / "Application Support" / "pcap-analyzer"
    else:  # Linux and others
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
        return Path(xdg_config_home) / "pcap-analyzer"

def get_cache_dir():
    """
    Get the platform-specific cache directory.
    
    Returns:
        Path: Path to the cache directory
    """
    if is_windows():
        base_dir = os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local"))
        return Path(base_dir) / "pcap-analyzer" / "cache"
    elif is_macos():
        return Path.home() / "Library" / "Caches" / "pcap-analyzer"
    else:  # Linux and others
        xdg_cache_home = os.environ.get("XDG_CACHE_HOME", str(Path.home() / ".cache"))
        return Path(xdg_cache_home) / "pcap-analyzer"

def get_data_dir():
    """
    Get the platform-specific data directory.
    
    Returns:
        Path: Path to the data directory
    """
    if is_windows():
        base_dir = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
        return Path(base_dir) / "pcap-analyzer" / "data"
    elif is_macos():
        return Path.home() / "Library" / "Application Support" / "pcap-analyzer" / "data"
    else:  # Linux and others
        xdg_data_home = os.environ.get("XDG_DATA_HOME", str(Path.home() / ".local" / "share"))
        return Path(xdg_data_home) / "pcap-analyzer"

def ensure_dir_exists(directory):
    """
    Ensure a directory exists, creating it if necessary.
    
    Args:
        directory (str or Path): Directory to ensure exists
        
    Returns:
        Path: Path to the directory
    """
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    return directory

def find_executable(name):
    """
    Find the path to an executable.
    
    Args:
        name (str): Name of the executable
        
    Returns:
        str or None: Path to the executable or None if not found
    """
    path = shutil.which(name)
    if path:
        logger.debug(f"Found executable {name} at {path}")
    else:
        logger.warning(f"Executable {name} not found in PATH")
    return path

def get_tshark_path():
    """
    Get the path to tshark, with platform-specific fallbacks.
    
    Returns:
        str or None: Path to tshark or None if not found
    """
    # First, check in PATH
    tshark_path = find_executable("tshark")
    if tshark_path:
        return tshark_path
    
    # Platform-specific fallbacks
    if is_windows():
        # Common Wireshark installation paths on Windows
        common_paths = [
            "C:\\Program Files\\Wireshark\\tshark.exe",
            "C:\\Program Files (x86)\\Wireshark\\tshark.exe"
        ]
        for path in common_paths:
            if os.path.exists(path):
                logger.debug(f"Found tshark at {path}")
                return path
    elif is_macos():
        # Common Wireshark installation paths on macOS
        common_paths = [
            "/Applications/Wireshark.app/Contents/MacOS/tshark",
            "/usr/local/bin/tshark"
        ]
        for path in common_paths:
            if os.path.exists(path):
                logger.debug(f"Found tshark at {path}")
                return path
    
    logger.warning("tshark not found")
    return None
