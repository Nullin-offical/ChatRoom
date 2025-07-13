#!/usr/bin/env python3
"""
Secure ChatRoom Application Runner
Includes security middleware and proper configuration
"""

import os
import sys
from flask import g
from app import app, socketio
from config import get_config
from middleware import SecurityMiddleware
from security import security_manager

def main():
    """Main application entry point"""
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Initialize security middleware
    security_middleware = SecurityMiddleware(app)
    # Store middleware in Flask's g object for access in decorators
    app.before_request(lambda: setattr(g, 'security_middleware', security_middleware))
    
    # Set environment variables
    os.environ['FLASK_ENV'] = os.environ.get('FLASK_ENV', 'development')
    
    # Security checks
    if app.config['ENV'] == 'production':
        if not app.config.get('SECRET_KEY') or app.config['SECRET_KEY'] == 'dev-secret-key-change-in-production':
            print("ERROR: SECRET_KEY environment variable is required for production!")
            sys.exit(1)
    
    # Print startup information
    print(f"Starting ChatRoom in {app.config['ENV']} mode")
    print(f"Debug mode: {app.config.get('DEBUG', False)}")
    print(f"Security middleware: Enabled")
    
    # Run the application
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=app.config.get('DEBUG', False),
            use_reloader=app.config.get('DEBUG', False),
            log_output=True
        )
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 