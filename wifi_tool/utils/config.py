import json
import os
from datetime import datetime
from utils.logger import setup_logger

logger = setup_logger()

def save_config(config, filepath):
    """
    Save configuration to a JSON file.
    
    Args:
        config (dict): Configuration dictionary to save
        filepath (str): Path to save the configuration file
        
    Returns:
        bool: True if successful, False otherwise
    """
    try:
        # Add metadata
        config['metadata'] = {
            'timestamp': datetime.now().isoformat(),
            'version': '1.0'
        }
        
        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        # Write configuration to file
        with open(filepath, 'w') as f:
            json.dump(config, f, indent=4)
            
        logger.info(f"Configuration saved to {filepath}")
        return True

    except Exception as e:
        logger.error(f"Error saving configuration: {str(e)}")
        raise

def load_config(filepath):
    """
    Load configuration from a JSON file.
    
    Args:
        filepath (str): Path to the configuration file
        
    Returns:
        dict: Loaded configuration
    """
    try:
        with open(filepath, 'r') as f:
            config = json.load(f)
        
        # Validate configuration
        if not _validate_config(config):
            raise ValueError("Invalid configuration format")
            
        logger.info(f"Configuration loaded from {filepath}")
        return config

    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        raise

def _validate_config(config):
    """
    Validate configuration structure.
    
    Args:
        config (dict): Configuration to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Check for required sections
        required_sections = ['metadata']
        for section in required_sections:
            if section not in config:
                logger.error(f"Missing required section: {section}")
                return False
        
        # Validate metadata
        metadata = config['metadata']
        if 'version' not in metadata:
            logger.error("Missing version in metadata")
            return False
            
        if 'timestamp' not in metadata:
            logger.error("Missing timestamp in metadata")
            return False
        
        return True

    except Exception as e:
        logger.error(f"Error validating configuration: {str(e)}")
        return False

def get_default_config():
    """
    Get default configuration settings.
    
    Returns:
        dict: Default configuration
    """
    return {
        'metadata': {
            'version': '1.0',
            'timestamp': datetime.now().isoformat()
        },
        'scanning': {
            'auto_refresh': False,
            'refresh_interval': 30
        },
        'attacks': {
            'deauth': {
                'default_interface': 'wlan0',
                'packet_count': 10,
                'interval': 0.1
            },
            'password': {
                'min_length': 8,
                'max_length': 12,
                'default_charset': 'alphanumeric'
            }
        },
        'logging': {
            'level': 'INFO',
            'file_logging': True,
            'console_logging': True
        }
    }
