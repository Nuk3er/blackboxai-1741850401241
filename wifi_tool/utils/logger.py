import logging
import os
from datetime import datetime

def setup_logger(name='wifi_pentester', log_file=None):
    """
    Set up and configure the logger.
    
    Args:
        name (str): Logger name
        log_file (str): Path to log file (optional)
        
    Returns:
        logging.Logger: Configured logger instance
    """
    try:
        # Create logger
        logger = logging.getLogger(name)
        
        # Only configure if it hasn't been configured before
        if not logger.handlers:
            logger.setLevel(logging.INFO)
            
            # Create formatters
            file_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_formatter = logging.Formatter(
                '%(levelname)s: %(message)s'
            )
            
            # Create console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_handler.setFormatter(console_formatter)
            logger.addHandler(console_handler)
            
            # Create file handler if log_file is specified
            if log_file is None:
                # Create logs directory if it doesn't exist
                os.makedirs('logs', exist_ok=True)
                
                # Generate default log filename with timestamp
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                log_file = f'logs/wifi_pentester_{timestamp}.log'
            
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
            
            logger.info(f"Logger initialized. Log file: {log_file}")
        
        return logger

    except Exception as e:
        # If logging setup fails, create a basic console-only logger
        basic_logger = logging.getLogger(name)
        if not basic_logger.handlers:
            basic_logger.setLevel(logging.INFO)
            console_handler = logging.StreamHandler()
            console_handler.setFormatter(
                logging.Formatter('%(levelname)s: %(message)s')
            )
            basic_logger.addHandler(console_handler)
            basic_logger.error(f"Failed to setup full logging: {str(e)}")
        
        return basic_logger

def get_logger(name='wifi_pentester'):
    """
    Get an existing logger instance.
    
    Args:
        name (str): Logger name
        
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)
