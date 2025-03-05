#!/usr/bin/env python3
import subprocess
import sys
import threading
import queue
import time
import logging
import platform
import os
import shlex
from pathlib import Path
from typing import Dict, Tuple, Optional, Union, List, Any, Callable
import hashlib

# Import our custom error classes
from .errors import (
    CommandError, 
    TimeoutError as PcapTimeoutError
)
from .utils import verify_dependency, DependencyError, RetryableOperation
from .security import is_safe_command

logger = logging.getLogger(__name__)

# Global cache for command results with TTL and performance metrics
command_cache: Dict[str, Tuple[float, str, float]] = {}  # timestamp, result, execution_time
CACHE_TTL = 3600  # Cache time-to-live in seconds
MAX_CACHE_SIZE = 100  # Maximum number of items in the cache
CACHE_FILENAME = "command_cache.json"
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".pcap_analyzer")

# Create cache directory if it doesn't exist
os.makedirs(CACHE_DIR, exist_ok=True)

def cache_key(command: str) -> str:
    """
    Generate a secure and unique cache key for a command.
    
    Args:
        command: The command string
        
    Returns:
        str: A hashed cache key
    """
    # Create a hash of the command for shorter keys
    return hashlib.md5(command.encode()).hexdigest()

def clean_cache() -> None:
    """
    Clean expired or excess entries from the command cache.
    """
    global command_cache
    
    current_time = time.time()
    # First, remove expired entries
    expired_keys = [
        key for key, (timestamp, _, _) in command_cache.items() 
        if current_time - timestamp > CACHE_TTL
    ]
    
    for key in expired_keys:
        del command_cache[key]
    
    # If still too large, remove oldest entries
    if len(command_cache) > MAX_CACHE_SIZE:
        # Sort by timestamp (oldest first)
        sorted_items = sorted(command_cache.items(), key=lambda x: x[1][0])
        # Keep only the MAX_CACHE_SIZE newest items
        command_cache = dict(sorted_items[-MAX_CACHE_SIZE:])
    
    logger.debug(f"Cleaned cache: {len(expired_keys)} expired entries removed, {len(command_cache)} entries remaining")

def run_command_with_retry(
    command: str,
    max_retries: int = 3,
    use_cache: bool = True,
    verbose: bool = False,
    timeout: int = 300,
    retry_on_error_codes: List[int] = None
) -> str:
    """
    Execute a command with automatic retries in case of failure.
    
    Args:
        command: The command to execute
        max_retries: Maximum number of retry attempts
        use_cache: Whether to use cached results if available
        verbose: Whether to print verbose output
        timeout: Command timeout in seconds
        retry_on_error_codes: List of error codes that should trigger a retry
        
    Returns:
        str: Command output
        
    Raises:
        CommandError: If the command fails after all retries
        TimeoutError: If the command times out after all retries
    """
    # Set default retry error codes if not provided
    if retry_on_error_codes is None:
        retry_on_error_codes = [1, 2, 126, 127, 137, 143]
    
    # Validate command security first
    if not is_safe_command(command):
        error_msg = f"Command failed security validation: {command}"
        logger.error(error_msg)
        raise CommandError(command, error_msg, -1)
    
    # Create the operation to retry
    def operation():
        try:
            return run_command(
                command, 
                use_cache=use_cache, 
                verbose=verbose, 
                timeout=timeout,
                raise_on_error=True
            )
        except CommandError as e:
            # Only retry on specific error codes
            if e.exit_code in retry_on_error_codes:
                logger.warning(f"Retryable error encountered (code {e.exit_code}): {e.message}")
                raise  # Re-raise to trigger retry
            else:
                logger.error(f"Non-retryable error encountered (code {e.exit_code}): {e.message}")
                raise  # Re-raise to fail immediately
    
    # Create the retryable operation with exponential backoff
    retry_op = RetryableOperation(
        operation=operation,
        max_retries=max_retries,
        initial_backoff=1.0,
        backoff_factor=2.0,
        max_backoff=15.0,
        jitter=0.1
    )
    
    # Execute with retries
    return retry_op.execute()

def run_command(
    command: str, 
    use_cache: bool = True, 
    verbose: bool = False, 
    timeout: int = 300,
    raise_on_error: bool = False,
    capture_stderr: bool = False
) -> Optional[str]:
    """
    Execute a shell command with improved performance and error handling.
    
    Args:
        command: The command to execute
        use_cache: Whether to use cached results if available
        verbose: Whether to print verbose output
        timeout: Command timeout in seconds
        raise_on_error: Whether to raise exceptions on error
        capture_stderr: Whether to include stderr in the output
        
    Returns:
        str: Command output or None if error and raise_on_error is False
        
    Raises:
        CommandError: If the command fails and raise_on_error is True
        TimeoutError: If the command times out and raise_on_error is True
        DependencyError: If a required dependency is missing
    """
    # Validate command security
    if not is_safe_command(command):
        error_msg = f"Command failed security validation: {command}"
        logger.error(error_msg)
        if raise_on_error:
            raise CommandError(command, error_msg, -1)
        return None
    
    # Check for missing dependencies in the command
    # Extract the command executable from the command
    cmd_parts = shlex.split(command)
    if cmd_parts:
        executable = cmd_parts[0]
        
        # If the executable is commonly used in our tool, verify it exists
        if executable in ["tshark", "capinfos", "editcap", "mergecap"]:
            try:
                verify_dependency(executable)
            except DependencyError as e:
                if raise_on_error:
                    raise
                logger.error(f"Dependency error: {str(e)}")
                return None
    
    # Generate cache key
    cache_cmd_key = cache_key(command)
    
    # Platform-specific command adaptations
    system = platform.system()
    
    # Determine if we need to use shell
    # Only use shell=True when absolutely necessary
    force_shell = "|" in command or ">" in command or "<" in command or "&&" in command
    
    # Prepare command arguments
    if force_shell:
        # For piped commands, we need to use shell=True for proper execution
        cmd_args = command
        use_shell = True
    else:
        # Try to split command safely for safer execution
        try:
            if system == "Windows":
                # Windows-specific handling
                # First handle the command executable
                parts = command.split(" ", 1)
                exec_name = parts[0]
                
                if len(parts) > 1:
                    # Convert remaining part to list of arguments
                    remaining = parts[1]
                    # Handle quoted arguments properly
                    if '"' in remaining or "'" in remaining:
                        # Use built-in Windows argument parser if available
                        try:
                            import win32api
                            cmd_args = [exec_name] + win32api.CommandLineToArgvW(remaining)
                        except ImportError:
                            # Fall back to simple shlex parsing
                            cmd_args = [exec_name] + shlex.split(remaining)
                    else:
                        # Simple space-separated arguments
                        cmd_args = [exec_name] + remaining.split()
                else:
                    cmd_args = [exec_name]
                
                # Replace forward slashes with backslashes in file paths
                if "tshark -r" in command:
                    for i, arg in enumerate(cmd_args):
                        if i > 0 and cmd_args[i-1] == "-r" and "/" in arg:
                            cmd_args[i] = arg.replace("/", "\\")
            else:
                # Unix systems - use shlex for proper handling of quotes
                cmd_args = shlex.split(command)
            
            use_shell = False
        except Exception as e:
            # If parsing fails, fall back to shell execution
            logger.warning(f"Command parsing failed, falling back to shell: {e}")
            cmd_args = command
            use_shell = True
    
    # Check cache with TTL
    current_time = time.time()
    if use_cache and cache_cmd_key in command_cache:
        cache_time, result, exec_time = command_cache[cache_cmd_key]
        if current_time - cache_time < CACHE_TTL:
            logger.debug(f"Using cached result for: {command} (execution time was {exec_time:.2f}s)")
            return result
    
    # Set up logging
    if verbose:
        logger.info(f"Running command: {command}")
    else:
        logger.debug(f"Running command: {command}")
        if sys.stdout.isatty():  # Only show progress indicator on terminals
            print("Running analysis...", end="\r")
            sys.stdout.flush()
    
    # Use a separate thread for progress indication
    stop_progress = threading.Event()
    progress_queue = queue.Queue()
    
    def progress_indicator():
        chars = "|/-\\"
        i = 0
        while not stop_progress.is_set():
            if not verbose and sys.stdout.isatty():  # Only show on terminals
                print(f"Processing... {chars[i % len(chars)]}", end="\r")
                sys.stdout.flush()
                i += 1
            time.sleep(0.1)
        progress_queue.put(True)
    
    # Start progress thread if not verbose and stdout is a terminal
    progress_thread = None
    if not verbose and sys.stdout.isatty():
        progress_thread = threading.Thread(target=progress_indicator)
        progress_thread.daemon = True
        progress_thread.start()
    
    start_time = time.time()
    result = None
    
    try:
        # Execute command with timeout
        process = subprocess.Popen(
            cmd_args, 
            shell=use_shell, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE if not capture_stderr else subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=os.environ.copy()  # Use current environment
        )
        
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()
            exec_time = time.time() - start_time
            logger.error(f"Command timed out after {timeout} seconds: {command}")
            
            # Stop progress indicator
            if progress_thread:
                stop_progress.set()
                progress_queue.get(timeout=1)
                if sys.stdout.isatty():
                    print(" " * 30, end="\r")  # Clear progress line
            
            if raise_on_error:
                raise PcapTimeoutError(f"Command execution timed out: {command}", timeout)
            return None
        
        # Stop progress indicator
        if progress_thread:
            stop_progress.set()
            progress_queue.get(timeout=1)
            if sys.stdout.isatty():
                print(" " * 30, end="\r")  # Clear progress line
        
        exec_time = time.time() - start_time
        
        # Handle command errors
        if process.returncode != 0:
            error_msg = stderr.strip() if stderr else stdout.strip()
            exit_code = process.returncode
            
            if "Some fields aren't valid" in error_msg:
                logger.error(f"Field error in tshark command: {error_msg}")
            elif "Couldn't register io,stat tap" in error_msg:
                logger.error(f"io,stat tap error in tshark command: {error_msg}")
            elif "The file doesn't exist" in error_msg:
                logger.error(f"File not found: {error_msg}")
            else:
                logger.error(f"Command failed with exit code {exit_code}: {error_msg}")
            
            if raise_on_error:
                raise CommandError(command, error_msg, exit_code)
            return None
        
        result = stdout.strip()
        
        # Cache the result with timestamp and execution time
        if use_cache and result:
            command_cache[cache_cmd_key] = (current_time, result, exec_time)
            # Clean the cache periodically
            if len(command_cache) > MAX_CACHE_SIZE * 1.1:  # Allow 10% overflow before cleaning
                clean_cache()
        
        if verbose:
            logger.info(f"Command completed in {exec_time:.2f}s")
        else:
            logger.debug(f"Command completed in {exec_time:.2f}s")
        
        return result
    
    except Exception as e:
        # Stop progress indicator on unexpected errors
        if progress_thread:
            stop_progress.set()
            try:
                progress_queue.get(timeout=1)
                if sys.stdout.isatty():
                    print(" " * 30, end="\r")  # Clear progress line
            except queue.Empty:
                pass  # Ignore if progress indicator already stopped
        
        exec_time = time.time() - start_time
        logger.error(f"Error executing command ({exec_time:.2f}s): {str(e)}")
        
        if raise_on_error:
            if isinstance(e, (CommandError, PcapTimeoutError, DependencyError)):
                raise
            raise CommandError(command, str(e), -1)
        return None
    
    finally:
        # Ensure progress thread is always stopped
        if progress_thread and progress_thread.is_alive():
            stop_progress.set()

def save_cache() -> bool:
    """
    Save the command cache to disk.
    
    Returns:
        bool: True if successful, False otherwise
    """
    import json
    
    try:
        cache_path = os.path.join(CACHE_DIR, CACHE_FILENAME)
        
        # Convert the cache to a JSON-serializable format
        serializable_cache = {}
        for key, (timestamp, result, exec_time) in command_cache.items():
            serializable_cache[key] = {
                "timestamp": timestamp,
                "result": result,
                "exec_time": exec_time
            }
        
        with open(cache_path, 'w') as f:
            json.dump(serializable_cache, f)
        
        logger.debug(f"Saved command cache with {len(command_cache)} entries to {cache_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error saving command cache: {str(e)}")
        return False

def load_cache() -> bool:
    """
    Load the command cache from disk.
    
    Returns:
        bool: True if successful, False otherwise
    """
    import json
    
    try:
        cache_path = os.path.join(CACHE_DIR, CACHE_FILENAME)
        
        if not os.path.exists(cache_path):
            logger.debug("No command cache file found")
            return False
        
        with open(cache_path, 'r') as f:
            serialized_cache = json.load(f)
        
        # Convert the serialized cache back to the internal format
        global command_cache
        command_cache = {}
        for key, data in serialized_cache.items():
            command_cache[key] = (data["timestamp"], data["result"], data["exec_time"])
        
        # Clean the cache after loading to remove expired entries
        clean_cache()
        
        logger.debug(f"Loaded command cache with {len(command_cache)} entries from {cache_path}")
        return True
    
    except Exception as e:
        logger.error(f"Error loading command cache: {str(e)}")
        return False

# Try to load the cache when the module is imported
try:
    load_cache()
except Exception as e:
    logger.warning(f"Failed to load command cache: {str(e)}")

# Register an atexit handler to save the cache when the program exits
import atexit
atexit.register(save_cache) 