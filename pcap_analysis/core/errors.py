import logging
import sys
import time
from enum import Enum
from typing import Dict, Any, Optional, Callable, TypeVar, Generic, Union

logger = logging.getLogger(__name__)

class ErrorCode(Enum):
    """Error codes for the application"""
    SUCCESS = 0
    COMMAND_FAILED = 1
    FILE_NOT_FOUND = 2
    DEPENDENCY_MISSING = 3
    INVALID_FORMAT = 4
    PERMISSION_DENIED = 5
    TIMEOUT = 6
    NETWORK_ERROR = 7
    RESOURCE_EXHAUSTED = 8
    INVALID_ARGUMENT = 9
    INTERRUPTED = 10
    UNSUPPORTED_OS = 11
    UNKNOWN_ERROR = 99

class PcapAnalysisError(Exception):
    """Base exception class for PCAP analysis errors"""
    def __init__(self, message: str, error_code: ErrorCode = ErrorCode.UNKNOWN_ERROR, details: Optional[Dict[str, Any]] = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        self.timestamp = time.time()
        super().__init__(self.message)
        
    def __str__(self) -> str:
        if self.details:
            detail_str = ', '.join(f"{k}={v}" for k, v in self.details.items())
            return f"{self.message} (Error code: {self.error_code.name}, Details: {detail_str})"
        else:
            return f"{self.message} (Error code: {self.error_code.name})"
    
    def get_help_text(self) -> str:
        """Return helpful text on how to resolve the error"""
        return "An error occurred during PCAP analysis."

class CommandError(PcapAnalysisError):
    """Exception raised when a command fails"""
    def __init__(self, command: str, stderr: str, exit_code: int):
        details = {
            'command': command,
            'stderr': stderr,
            'exit_code': exit_code
        }
        super().__init__(
            f"Command failed with exit code {exit_code}", 
            ErrorCode.COMMAND_FAILED, 
            details
        )
    
    def get_help_text(self) -> str:
        stderr = self.details.get('stderr', '')
        
        # Provide specific help based on error patterns
        if "not found" in stderr and "command not found" in stderr:
            return "The command was not found. Make sure it is installed and in your PATH."
        elif "permission denied" in stderr.lower():
            return "Permission denied. Try running with higher privileges or check file permissions."
        elif "invalid option" in stderr.lower() or "unknown option" in stderr.lower():
            return "The command contains invalid options. Check the syntax and try again."
        else:
            return f"Command execution failed. Check the error output for details."

class FileNotFoundError(PcapAnalysisError):
    """Exception raised when a file is not found"""
    def __init__(self, file_path: str):
        super().__init__(
            f"File not found: {file_path}", 
            ErrorCode.FILE_NOT_FOUND, 
            {'file_path': file_path}
        )
    
    def get_help_text(self) -> str:
        file_path = self.details.get('file_path', '')
        return f"The file '{file_path}' could not be found. Verify the file path and try again."

# DependencyError has been moved to utils.py

class TimeoutError(PcapAnalysisError):
    """Exception raised when an operation times out"""
    def __init__(self, operation: str, timeout_seconds: int):
        super().__init__(
            f"Operation timed out: {operation} (after {timeout_seconds} seconds)", 
            ErrorCode.TIMEOUT, 
            {'operation': operation, 'timeout_seconds': timeout_seconds}
        )
    
    def get_help_text(self) -> str:
        operation = self.details.get('operation', '')
        timeout = self.details.get('timeout_seconds', 0)
        
        return (
            f"The operation '{operation}' timed out after {timeout} seconds. "
            "This could be because the operation takes too long or there's a problem with the system. "
            "Try increasing the timeout value or check system resources."
        )

class FormatError(PcapAnalysisError):
    """Exception raised when a file has an invalid format"""
    def __init__(self, file_path: str, expected_format: str, details: Optional[str] = None):
        error_details = {
            'file_path': file_path,
            'expected_format': expected_format
        }
        if details:
            error_details['format_details'] = details
            
        super().__init__(
            f"Invalid file format for {file_path}: expected {expected_format}", 
            ErrorCode.INVALID_FORMAT, 
            error_details
        )
    
    def get_help_text(self) -> str:
        file_path = self.details.get('file_path', '')
        expected = self.details.get('expected_format', '')
        
        return (
            f"The file '{file_path}' has an invalid format. Expected {expected}. "
            "Make sure you're using the correct file type and it's not corrupted."
        )

class PermissionError(PcapAnalysisError):
    """Exception raised when permission is denied"""
    def __init__(self, resource: str, operation: str):
        super().__init__(
            f"Permission denied: cannot {operation} {resource}", 
            ErrorCode.PERMISSION_DENIED, 
            {'resource': resource, 'operation': operation}
        )
    
    def get_help_text(self) -> str:
        resource = self.details.get('resource', '')
        operation = self.details.get('operation', '')
        
        return (
            f"Permission denied when trying to {operation} {resource}. "
            "Make sure you have the necessary permissions. "
            "You may need to run the program with higher privileges."
        )

class NetworkError(PcapAnalysisError):
    """Exception raised when a network operation fails"""
    def __init__(self, operation: str, error_details: str):
        super().__init__(
            f"Network error during {operation}: {error_details}", 
            ErrorCode.NETWORK_ERROR, 
            {'operation': operation, 'error_details': error_details}
        )
    
    def get_help_text(self) -> str:
        return (
            "A network error occurred. Check your internet connection and try again. "
            "If the problem persists, there might be a firewall or proxy issue."
        )

T = TypeVar('T')

# RetryableOperation has been moved to utils.py

def handle_error(error: Exception, exit_program: bool = False) -> int:
    """
    Handle errors consistently throughout the application.
    
    Args:
        error (Exception): The error to handle
        exit_program (bool): Whether to exit the program
        
    Returns:
        int: Error code if not exiting
    """
    if isinstance(error, PcapAnalysisError):
        logger.error(f"{error}")
        
        # Print help text
        help_text = error.get_help_text()
        if help_text:
            logger.info(f"Help: {help_text}")
            
        error_code = error.error_code.value
    else:
        logger.exception(f"Unexpected error: {error}")
        error_code = ErrorCode.UNKNOWN_ERROR.value
    
    if exit_program:
        sys.exit(error_code)
    
    return error_code
