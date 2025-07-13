#!/usr/bin/env python3
"""
Production configuration for cPanel deployment
"""

import os
import logging
from datetime import timedelta

class ProductionConfig:
    # Basic Flask settings
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'digivee-chatroom-secret-key-2024'
    DEBUG = False
    TESTING = False
    
    # Database settings - Use absolute path for production
    DATABASE_PATH = '/home/digiveei/ChatRoom/backend/db/chatroom.db'
    
    # Logging settings - Reduce logging for better performance
    LOG_LEVEL = logging.WARNING  # Changed from INFO to WARNING
    LOG_FILE = '/home/digiveei/ChatRoom/backend/logs/app.log'
    
    # Security settings
    SESSION_COOKIE_SECURE = False  # Changed to False for compatibility
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # File upload settings
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = '/home/digiveei/ChatRoom/frontend/static/uploads'
    
    # SocketIO settings - Optimized for production
    SOCKETIO_ASYNC_MODE = 'threading'  # Changed from eventlet to threading
    SOCKETIO_PING_TIMEOUT = 60
    SOCKETIO_PING_INTERVAL = 25
    SOCKETIO_CORS_ALLOWED_ORIGINS = "*"
    
    # Domain settings
    SERVER_NAME = 'digivee.ir'
    PREFERRED_URL_SCHEME = 'https'
    
    # Security settings for production
    SESSION_COOKIE_SECURE = False  # Changed to False for compatibility
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'  # Changed from 'Strict' to 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    
    # Disable debug mode
    DEBUG = False
    
    # Production logging - Reduced for performance
    LOG_LEVEL = 'ERROR'  # Changed from WARNING to ERROR
    
    # CORS settings for production
    CORS_ORIGINS = ['*']  # Adjust this based on your domain
    
    # Content Security Policy for production
    CONTENT_SECURITY_POLICY = {
        'default-src': ["'self'"],
        'script-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://cdn.socket.io"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
        'font-src': ["'self'", "https://cdn.jsdelivr.net", "https://fonts.gstatic.com"],
        'img-src': ["'self'", "data:", "https:"],
        'connect-src': ["'self'", "ws:", "wss:", "https://cdn.socket.io"],
    }
    
    # Security headers
    SECURITY_HEADERS = {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'SAMEORIGIN',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
    }
    
    # Message limits
    MAX_MESSAGE_LENGTH = 1000
    MIN_MESSAGE_LENGTH = 1
    MAX_MESSAGES_PER_MINUTE = 60
    SPAM_BAN_DURATION_MINUTES = 10
    
    # User limits
    MAX_USERNAME_LENGTH = 30
    MIN_USERNAME_LENGTH = 3
    MAX_LOGIN_ATTEMPTS = 5
    LOGIN_TIMEOUT_MINUTES = 15
    
    # File upload limits
    MAX_FILE_SIZE = 5 * 1024 * 1024  # 5MB
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    
    # Session settings
    SESSION_TIMEOUT_MINUTES = 60
    
    # Rate limiting - Disabled for better performance
    RATELIMIT_ENABLED = False  # Changed from True to False
    RATELIMIT_STORAGE_URL = "memory://"

# Create config instance
config = ProductionConfig() 