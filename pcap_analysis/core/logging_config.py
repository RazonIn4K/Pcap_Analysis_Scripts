import logging
import logging.handlers
import os
from datetime import datetime

def configure_logging(log_level=logging.INFO, log_file=None, log_to_console=True):
    """
    Configure logging for the application.
    
    Args:
        log_level (int): Logging level
        log_file (str, optional): Path to log file
        log_to_console (bool): Whether to log to console
    """
    # Create logger
    logger = logging.getLogger('pcap_analysis')
    logger.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Add console handler if requested
    if log_to_console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # Add file handler if log file is specified
    if log_file:
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        
        # Create file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, 
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    # Prevent propagation to root logger
    logger.propagate = False
    
    return logger
