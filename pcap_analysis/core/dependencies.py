import subprocess
import re
import logging
import shutil
from .utils import DependencyError

logger = logging.getLogger(__name__)

def check_dependency(command, min_version=None):
    """
    Check if a dependency is installed and meets the minimum version.
    
    Args:
        command (str): Command to check
        min_version (tuple, optional): Minimum version required (major, minor, patch)
        
    Returns:
        bool: True if dependency is available and meets version requirements
        
    Raises:
        DependencyError: If dependency is missing or version is too low
    """
    # Check if command exists
    if shutil.which(command) is None:
        raise DependencyError(command)
    
    # Check version if required
    if min_version:
        try:
            # Get version string
            version_output = subprocess.run(
                [command, "--version"], 
                capture_output=True, 
                text=True, 
                check=False
            ).stdout
            
            # Extract version number
            version_match = re.search(r'(\d+)\.(\d+)\.(\d+)', version_output)
            if not version_match:
                logger.warning(f"Could not determine version for {command}")
                return True
            
            version = tuple(map(int, version_match.groups()))
            
            # Compare versions
            if version < min_version:
                raise DependencyError(
                    f"{command} version {'.'.join(map(str, version))} is lower than required {'.'.join(map(str, min_version))}"
                )
        except subprocess.SubprocessError as e:
            logger.warning(f"Error checking version for {command}: {e}")
            return True
    
    return True

def check_all_dependencies():
    """
    Check all required dependencies.
    
    Returns:
        bool: True if all dependencies are available
        
    Raises:
        DependencyError: If any dependency is missing
    """
    dependencies = [
        ("tshark", (3, 2, 0)),
        ("capinfos", None)
    ]
    
    for command, min_version in dependencies:
        check_dependency(command, min_version)
    
    logger.info("All dependencies are available")
    return True
