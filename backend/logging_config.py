import logging
import logging.handlers
import os
from datetime import datetime

def setup_logging():
    """Setup comprehensive logging for the application"""
    
    # Create logs directory if it doesn't exist
    logs_dir = os.path.join(os.path.dirname(__file__), 'logs')
    os.makedirs(logs_dir, exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(name)s | %(filename)s:%(lineno)d | %(funcName)s | %(message)s'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s | %(levelname)s | %(message)s'
    )
    
    # File handlers
    # Main application log
    app_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logs_dir, 'app.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    app_handler.setLevel(logging.INFO)
    app_handler.setFormatter(detailed_formatter)
    
    # Error log
    error_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logs_dir, 'error.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(detailed_formatter)
    
    # Debug log
    debug_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logs_dir, 'debug.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=3
    )
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(detailed_formatter)
    
    # Access log
    access_handler = logging.handlers.RotatingFileHandler(
        os.path.join(logs_dir, 'access.log'),
        maxBytes=10*1024*1024,  # 10MB
        backupCount=5
    )
    access_handler.setLevel(logging.INFO)
    access_handler.setFormatter(simple_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    
    # Add handlers to root logger
    root_logger.addHandler(app_handler)
    root_logger.addHandler(error_handler)
    root_logger.addHandler(debug_handler)
    root_logger.addHandler(access_handler)
    root_logger.addHandler(console_handler)
    
    # Create specific loggers
    app_logger = logging.getLogger('chatroom')
    app_logger.setLevel(logging.DEBUG)
    
    db_logger = logging.getLogger('chatroom.database')
    db_logger.setLevel(logging.DEBUG)
    
    socket_logger = logging.getLogger('chatroom.socketio')
    socket_logger.setLevel(logging.DEBUG)
    
    auth_logger = logging.getLogger('chatroom.auth')
    auth_logger.setLevel(logging.DEBUG)
    
    return {
        'app': app_logger,
        'database': db_logger,
        'socketio': socket_logger,
        'auth': auth_logger
    }

def log_request_info(request, logger):
    """Log detailed request information"""
    logger.info(f"Request: {request.method} {request.url}")
    logger.info(f"Remote IP: {request.remote_addr}")
    logger.info(f"User Agent: {request.headers.get('User-Agent', 'Unknown')}")
    logger.info(f"Referer: {request.headers.get('Referer', 'None')}")

def log_error_with_context(error, logger, context=None):
    """Log error with additional context"""
    logger.error(f"Error: {str(error)}")
    logger.error(f"Error Type: {type(error).__name__}")
    if context:
        logger.error(f"Context: {context}")
    import traceback
    logger.error(f"Traceback: {traceback.format_exc()}") 