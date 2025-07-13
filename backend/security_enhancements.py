"""
Additional Security Enhancements for ChatRoom Application
Implements additional security measures and validations
"""

import re
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify, current_app
from flask_login import current_user

class SecurityEnhancements:
    """Additional security enhancements"""
    
    def __init__(self):
        self.request_history = {}
        self.suspicious_ips = set()
        self.blocked_ips = set()
        
    def validate_json_request(self, required_fields=None, max_size=1024*1024):
        """Validate JSON request data"""
        if not request.is_json:
            return False, "Content-Type must be application/json"
        
        if request.content_length and request.content_length > max_size:
            return False, "Request too large"
        
        try:
            data = request.get_json()
            if data is None:
                return False, "Invalid JSON data"
            
            if required_fields:
                for field in required_fields:
                    if field not in data:
                        return False, f"Missing required field: {field}"
            
            return True, data
        except Exception:
            return False, "Invalid JSON format"
    
    def validate_file_upload(self, file, allowed_extensions, max_size):
        """Enhanced file upload validation"""
        if not file:
            return False, "No file provided"
        
        # Check file size
        if file.content_length and file.content_length > max_size:
            return False, "File too large"
        
        # Check file extension
        filename = file.filename
        if not filename:
            return False, "Invalid filename"
        
        ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
        if ext not in allowed_extensions:
            return False, f"File type not allowed. Allowed: {', '.join(allowed_extensions)}"
        
        # Check for suspicious patterns in filename
        suspicious_patterns = [
            r'\.\./', r'\.\.\\', r'%2e%2e', r'%2e%2e%2f',
            r'<script', r'javascript:', r'vbscript:', r'data:text/html'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, filename, re.IGNORECASE):
                return False, "Suspicious filename detected"
        
        return True, "OK"
    
    def generate_secure_token(self, length=32):
        """Generate cryptographically secure token"""
        return secrets.token_urlsafe(length)
    
    def hash_sensitive_data(self, data):
        """Hash sensitive data for logging"""
        if not data:
            return "***"
        return hashlib.sha256(data.encode()).hexdigest()[:8] + "***"
    
    def sanitize_log_data(self, data):
        """Sanitize data for logging"""
        if isinstance(data, dict):
            sanitized = {}
            sensitive_fields = ['password', 'token', 'secret', 'key', 'auth']
            for key, value in data.items():
                if any(sensitive in key.lower() for sensitive in sensitive_fields):
                    sanitized[key] = self.hash_sensitive_data(str(value))
                else:
                    sanitized[key] = value
            return sanitized
        return data
    
    def check_request_frequency(self, ip, endpoint, max_requests=100, window=60):
        """Check request frequency per IP per endpoint"""
        now = datetime.now()
        key = f"{ip}:{endpoint}"
        
        if key not in self.request_history:
            self.request_history[key] = []
        
        # Remove old requests
        self.request_history[key] = [
            req_time for req_time in self.request_history[key]
            if (now - req_time).total_seconds() < window
        ]
        
        # Add current request
        self.request_history[key].append(now)
        
        # Check if too many requests
        if len(self.request_history[key]) > max_requests:
            return False, f"Too many requests to {endpoint}"
        
        return True, "OK"
    
    def validate_email(self, email):
        """Enhanced email validation"""
        if not email:
            return False, "Email is required"
        
        # Basic email format check
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, email):
            return False, "Invalid email format"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'<script', r'javascript:', r'vbscript:', r'data:text/html',
            r'\.\./', r'\.\.\\', r'%2e%2e'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return False, "Suspicious email content detected"
        
        return True, "OK"
    
    def validate_password_strength(self, password):
        """Enhanced password strength validation"""
        if not password:
            return False, "Password is required"
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        
        if len(password) > 128:
            return False, "Password too long (max 128 characters)"
        
        # Check for common patterns
        common_passwords = [
            'password', '123456', 'qwerty', 'admin', 'user',
            'test', 'demo', 'guest', 'welcome', 'login'
        ]
        
        if password.lower() in common_passwords:
            return False, "Password too common"
        
        # Check for character variety
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in password)
        
        if not (has_upper and has_lower and has_digit):
            return False, "Password must contain uppercase, lowercase, and digits"
        
        return True, "OK"

# Global instance
security_enhancements = SecurityEnhancements()

def require_json(f):
    """Decorator to require JSON requests"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        valid, result = security_enhancements.validate_json_request()
        if not valid:
            return jsonify({'success': False, 'error': result}), 400
        return f(*args, **kwargs)
    return decorated_function

def rate_limit_by_ip(max_requests=100, window=60):
    """Decorator to rate limit by IP address"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            endpoint = request.endpoint
            
            valid, result = security_enhancements.check_request_frequency(
                client_ip, endpoint, max_requests, window
            )
            
            if not valid:
                return jsonify({'success': False, 'error': result}), 429
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_security_event(event_type, details, user_id=None, ip=None):
    """Log security events"""
    if not user_id and current_user.is_authenticated:
        user_id = current_user.id
    
    if not ip:
        ip = request.remote_addr
    
    log_data = {
        'timestamp': datetime.now().isoformat(),
        'event_type': event_type,
        'user_id': user_id,
        'ip_address': ip,
        'user_agent': request.headers.get('User-Agent', ''),
        'endpoint': request.endpoint,
        'method': request.method,
        'details': security_enhancements.sanitize_log_data(details)
    }
    
    # In production, log to file or database
    print(f"SECURITY EVENT: {log_data}")

def validate_csrf_token():
    """Validate CSRF token if present"""
    if request.method in ['GET', 'HEAD', 'OPTIONS']:
        return True
    
    # Check for CSRF token in headers or form data
    token = request.headers.get('X-CSRF-Token') or request.form.get('csrf_token')
    
    if not token:
        return False
    
    # In a real implementation, validate against session token
    # For now, just check if token exists
    return bool(token)

def require_csrf(f):
    """Decorator to require CSRF token"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not validate_csrf_token():
            return jsonify({'success': False, 'error': 'CSRF token required'}), 403
        return f(*args, **kwargs)
    return decorated_function 
 
 