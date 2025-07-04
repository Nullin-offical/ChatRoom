"""
Security Module for ChatRoom Application
Handles rate limiting, spam protection, and security validations
"""

import time
import re
from datetime import datetime, timedelta
from collections import defaultdict, deque
from functools import wraps
from flask import request, session, g
from flask_socketio import emit, disconnect
import sqlite3

# Rate limiting storage
user_message_timestamps = defaultdict(deque)
user_spam_warnings = defaultdict(int)
user_bans = {}

# Security configurations
SECURITY_CONFIG = {
    'MAX_MESSAGES_PER_MINUTE': 60,
    'SPAM_WARNING_THRESHOLD': 3,
    'BAN_DURATION_MINUTES': 10,
    'MAX_MESSAGE_LENGTH': 1000,
    'MIN_MESSAGE_LENGTH': 1,
    'ALLOWED_HTML_TAGS': [],  # No HTML allowed
    'MAX_USERNAME_LENGTH': 30,
    'MIN_USERNAME_LENGTH': 3,
    'SESSION_TIMEOUT_MINUTES': 60,
    'MAX_LOGIN_ATTEMPTS': 5,
    'LOGIN_TIMEOUT_MINUTES': 15
}

class SecurityManager:
    """Main security manager class"""
    
    def __init__(self):
        self.message_history = defaultdict(deque)
        self.login_attempts = defaultdict(list)
        self.banned_users = {}
    
    def is_user_banned(self, user_id):
        """Check if user is currently banned"""
        if user_id in self.banned_users:
            ban_time, duration = self.banned_users[user_id]
            if time.time() - ban_time < duration * 60:  # duration in minutes
                return True
            else:
                # Ban expired, remove from banned list
                del self.banned_users[user_id]
        return False
    
    def ban_user(self, user_id, duration_minutes=10):
        """Ban a user for specified duration"""
        self.banned_users[user_id] = (time.time(), duration_minutes)
        return f"You have been banned for {duration_minutes} minutes due to spam."
    
    def check_rate_limit(self, user_id, max_messages=60, time_window=60):
        """Check if user is within rate limits"""
        now = time.time()
        user_messages = self.message_history[user_id]
        # Remove old messages outside the time window
        while user_messages and now - user_messages[0] >= time_window:
            user_messages.popleft()
        # Check if user is banned
        if self.is_user_banned(user_id):
            return False, "You are currently banned from sending messages."
        # Check rate limit
        if len(user_messages) >= max_messages:
            ban_message = self.ban_user(user_id, SECURITY_CONFIG['BAN_DURATION_MINUTES'])
            return False, ban_message
        user_messages.append(now)
        return True, "OK"
    
    def validate_message_content(self, content):
        """Validate message content for security"""
        if not content or not isinstance(content, str):
            return False, "Invalid message content"
        
        content = content.strip()
        
        # Check length
        if len(content) < SECURITY_CONFIG['MIN_MESSAGE_LENGTH']:
            return False, "Message too short"
        
        if len(content) > SECURITY_CONFIG['MAX_MESSAGE_LENGTH']:
            return False, f"Message too long (max {SECURITY_CONFIG['MAX_MESSAGE_LENGTH']} characters)"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',  # JavaScript protocol
            r'data:text/html',  # Data URLs
            r'vbscript:',  # VBScript
            r'on\w+\s*=',  # Event handlers
            r'<iframe[^>]*>',  # Iframe tags
            r'<object[^>]*>',  # Object tags
            r'<embed[^>]*>',  # Embed tags
            r'<link[^>]*>',  # Link tags
            r'<meta[^>]*>',  # Meta tags
            r'../',
            r'\.\./',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'..%2f',
            r'..%5c',
            r'\\windows\\system32',
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, "Message contains forbidden content"
        
        # Check for excessive repetition
        if len(set(content)) < len(content) * 0.3:  # More than 70% repeated characters
            return False, "Message contains too much repetition"
        
        return True, "OK"
    
    def validate_username(self, username):
        """Validate username for security"""
        if not username or not isinstance(username, str):
            return False, "Invalid username"
        
        username = username.strip()
        
        # Check length
        if len(username) < SECURITY_CONFIG['MIN_USERNAME_LENGTH']:
            return False, f"Username too short (min {SECURITY_CONFIG['MIN_USERNAME_LENGTH']} characters)"
        
        if len(username) > SECURITY_CONFIG['MAX_USERNAME_LENGTH']:
            return False, f"Username too long (max {SECURITY_CONFIG['MAX_USERNAME_LENGTH']} characters)"
        
        # Check for valid characters (alphanumeric, underscore, dash)
        if not re.match(r'^[a-zA-Z0-9_-]+$', username):
            return False, "Username contains invalid characters"
        
        # Check for reserved words
        reserved_words = ['admin', 'root', 'system', 'guest', 'anonymous', 'null', 'undefined']
        if username.lower() in reserved_words:
            return False, "Username is reserved"
        
        return True, "OK"
    
    def check_login_attempts(self, username, max_attempts=5, timeout_minutes=15):
        """Check login attempts to prevent brute force"""
        now = time.time()
        attempts = self.login_attempts[username]
        # Remove old attempts
        attempts[:] = [attempt for attempt in attempts if now - attempt < timeout_minutes * 60]
        if len(attempts) >= max_attempts:
            return False, f"Too many login attempts. Try again in {timeout_minutes} minutes."
        return True, "OK"
    
    def record_login_attempt(self, username, success=True):
        """Record a login attempt"""
        if not success:
            self.login_attempts[username].append(time.time())
        else:
            # Clear failed attempts on successful login
            self.login_attempts[username].clear()
    
    def sanitize_input(self, text):
        """Sanitize user input to prevent XSS"""
        if not text:
            return ""
        # Remove HTML tags
        text = re.sub(r'<[^>]+>', '', text)
        # Escape special characters
        text = text.replace('&', '&amp;')
        text = text.replace('<', '&lt;')
        text = text.replace('>', '&gt;')
        text = text.replace('"', '&quot;')
        text = text.replace("'", '&#x27;')
        return text
    
    def validate_room_access(self, user_id, room_slug, db_connection):
        """Validate if user can access a specific room"""
        try:
            cur = db_connection.cursor()
            cur.execute('SELECT id, has_password, is_hidden FROM rooms WHERE slug = ?', (room_slug,))
            room = cur.fetchone()
            
            if not room:
                return False, "Room not found"
            
            room_id, has_password, is_hidden = room
            
            # Check if room is hidden (admin only)
            if is_hidden:
                cur.execute('SELECT is_admin FROM users WHERE id = ?', (user_id,))
                user = cur.fetchone()
                if not user or not user[0]:
                    return False, "Access denied"
            
            return True, room_id
        except Exception as e:
            return False, f"Database error: {str(e)}"
    
    def validate_pm_access(self, sender_id, recipient_username, db_connection):
        """Validate if user can send PM to recipient"""
        try:
            cur = db_connection.cursor()
            cur.execute('SELECT id FROM users WHERE username = ?', (recipient_username,))
            recipient = cur.fetchone()
            
            if not recipient:
                return False, "Recipient not found"
            
            recipient_id = recipient[0]
            
            # User cannot send PM to themselves
            if sender_id == recipient_id:
                return False, "Cannot send message to yourself"
            
            return True, recipient_id
        except Exception as e:
            return False, f"Database error: {str(e)}"

# Global security manager instance
security_manager = SecurityManager()

def require_security_check(f):
    """Decorator to add security checks to socket events"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get user ID from current_user (assuming Flask-Login is used)
        from flask_login import current_user
        
        if not current_user.is_authenticated:
            emit('error', {'message': 'Authentication required'})
            return
        
        user_id = current_user.id
        
        # Check if user is banned
        if security_manager.is_user_banned(user_id):
            ban_time, duration = security_manager.banned_users[user_id]
            remaining_time = int((ban_time + duration * 60 - time.time()) / 60)
            emit('error', {
                'message': f'You are banned for {remaining_time} more minutes due to spam.'
            })
            return
        
        return f(*args, **kwargs)
    return decorated_function

def log_security_event(event_type, user_id, details):
    """Log security events for monitoring"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = f"[{timestamp}] {event_type} - User: {user_id} - Details: {details}"
    
    # In production, you might want to log to a file or database
    print(f"SECURITY LOG: {log_entry}")

# Export security functions
def check_message_security(user_id, content):
    """Check if message is allowed to be sent"""
    # Check rate limit
    rate_ok, rate_msg = security_manager.check_rate_limit(user_id)
    if not rate_ok:
        log_security_event("RATE_LIMIT_EXCEEDED", user_id, f"Message: {content[:50]}...")
        return False, rate_msg
    
    # Validate content
    content_ok, content_msg = security_manager.validate_message_content(content)
    if not content_ok:
        log_security_event("INVALID_CONTENT", user_id, f"Message: {content[:50]}...")
        return False, content_msg
    
    return True, "OK"

def sanitize_user_input(text):
    """Sanitize user input"""
    return security_manager.sanitize_input(text) 