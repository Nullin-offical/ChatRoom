#!/usr/bin/env python3
"""
WSGI entry point for cPanel deployment
This file is used by cPanel to serve the Flask application
"""

import os
import sys
import traceback

# Add the backend directory to Python path
backend_dir = '/home/digiveei/ChatRoom/backend'
sys.path.insert(0, backend_dir)

# Set environment variables for production
os.environ['FLASK_ENV'] = 'production'
os.environ['PYTHONPATH'] = backend_dir

# Setup logging first
try:
    from logging_config import setup_logging
    loggers = setup_logging()
    app_logger = loggers['app']
    app_logger.info("=== ChatRoom Application Starting on digivee.ir ===")
    app_logger.info(f"Python version: {sys.version}")
    app_logger.info(f"Working directory: {os.getcwd()}")
    app_logger.info(f"Backend directory: {backend_dir}")
except Exception as e:
    print(f"Failed to setup logging: {e}")
    traceback.print_exc()

# Import the Flask app
try:
    from app import app, socketio, start_background_tasks
    app_logger.info("Flask app imported successfully")
except Exception as e:
    app_logger.error(f"Failed to import Flask app: {e}")
    traceback.print_exc()
    raise

# Initialize database on startup
try:
    from db.init_db import init_db
    init_db()
    app_logger.info("Database initialized successfully for production")
except Exception as e:
    app_logger.error(f"Database initialization error: {e}")
    traceback.print_exc()

# Start background tasks for production
try:
    # Disable background tasks in production to prevent performance issues
    # start_background_tasks()
    app_logger.info("Background tasks disabled in production for performance")
except Exception as e:
    app_logger.error(f"Failed to start background tasks: {e}")
    traceback.print_exc()

# For WSGI servers that don't support WebSocket
# We'll use the Flask app directly without SocketIO for production
application = app

# SocketIO is disabled in production due to cPanel limitations
# For servers that support WebSocket (like uWSGI with gevent)
# Uncomment the following line:
# application = socketio

app_logger.info("WSGI application ready for digivee.ir")

if __name__ == '__main__':
    # This will only run if the file is executed directly
    # In cPanel, this won't run
    app_logger.info("Starting development server...")
    socketio.run(app, host='0.0.0.0', port=5000, debug=False) 