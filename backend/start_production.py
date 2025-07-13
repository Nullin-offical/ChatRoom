#!/usr/bin/env python3
"""
Production startup script for ChatRoom
This can be used to manually start the application if needed
"""

import os
import sys

# Set production environment
os.environ['FLASK_ENV'] = 'production'

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import and initialize
from app import app, socketio
from db.init_db import init_db

def main():
    """Start the production server"""
    print("Starting ChatRoom in production mode...")
    
    # Initialize database
    try:
        init_db()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Database initialization error: {e}")
        return 1
    
    # Start the server
    try:
        socketio.run(
            app,
            host='0.0.0.0',
            port=5000,
            debug=False,
            use_reloader=False
        )
    except KeyboardInterrupt:
        print("\nShutting down gracefully...")
    except Exception as e:
        print(f"Error starting server: {e}")
        return 1
    
    return 0

if __name__ == '__main__':
    sys.exit(main()) 