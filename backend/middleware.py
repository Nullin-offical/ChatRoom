"""
Security Middleware for ChatRoom Application
Handles request filtering, rate limiting, and security headers
"""

import time
import re
from functools import wraps
from flask import request, g, abort, make_response
from flask_login import current_user
from collections import defaultdict, deque

class SecurityMiddleware:
    """Main security middleware class"""
    
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
        
        # Rate limiting storage
        self.request_history = defaultdict(deque)
        self.ip_blacklist = set()
        
        # Suspicious patterns
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',
            r'javascript:',
            r'data:text/html',
            r'vbscript:',
            r'on\w+\s*=',
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'../',
            r'\.\./',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'..%2f',
            r'..%5c',
        ]
    
    def init_app(self, app):
        """Initialize the middleware with Flask app"""
        self.app = app
        
        # Register before_request handler
        app.before_request(lambda: self.before_request())
        
        # Register after_request handler
        app.after_request(lambda response: self.after_request(response))
        
        # Register error handlers
        app.register_error_handler(400, self.bad_request)
        app.register_error_handler(403, self.forbidden)
        app.register_error_handler(404, self.not_found)
        app.register_error_handler(429, self.too_many_requests)
        app.register_error_handler(500, self.internal_error)
    
    def before_request(self):
        """Handle requests before they are processed"""
        # Get client IP
        client_ip = self.get_client_ip()
        g.client_ip = client_ip
        
        # Check IP blacklist
        if client_ip in self.ip_blacklist:
            abort(403, description="Access denied")
        
        # Rate limiting for API endpoints
        if request.path.startswith('/api/'):
            if not self.check_rate_limit(client_ip):
                abort(429, description="Too many requests")
        
        # Check for suspicious content
        if self.is_suspicious_request():
            abort(400, description="Suspicious request detected")
        
        # Log request
        self.log_request()
    
    def after_request(self, response):
        """Handle responses after they are processed"""
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Add HSTS header for HTTPS
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # Add Content Security Policy
        csp_policy = self.get_csp_policy()
        response.headers['Content-Security-Policy'] = csp_policy
        
        return response
    
    def get_client_ip(self):
        """Get the real client IP address"""
        # Check for forwarded headers
        x_forwarded_for = request.headers.get('X-Forwarded-For')
        if x_forwarded_for:
            return x_forwarded_for.split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        else:
            return request.remote_addr
    
    def check_rate_limit(self, client_ip, max_requests=100, time_window=60):
        """Check if client is within rate limits"""
        now = time.time()
        requests = self.request_history[client_ip]
        
        # Remove old requests
        while requests and now - requests[0] > time_window:
            requests.popleft()
        
        # Check limit
        if len(requests) >= max_requests:
            return False
        
        # Add current request
        requests.append(now)
        return True
    
    def is_suspicious_request(self):
        """Check if request contains suspicious content"""
        # Check URL
        url = request.url.lower()
        for pattern in self.suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        # Check form data
        if request.form:
            for key, value in request.form.items():
                if isinstance(value, str):
                    for pattern in self.suspicious_patterns:
                        if re.search(pattern, value, re.IGNORECASE):
                            return True
        
        # Check JSON data
        if request.is_json:
            try:
                json_data = str(request.get_json())
                for pattern in self.suspicious_patterns:
                    if re.search(pattern, json_data, re.IGNORECASE):
                        return True
            except:
                pass
        
        return False
    
    def log_request(self):
        """Log request information"""
        log_data = {
            'timestamp': time.time(),
            'method': request.method,
            'path': request.path,
            'ip': g.client_ip,
            'user_agent': request.headers.get('User-Agent', ''),
            'user_id': current_user.id if current_user.is_authenticated else None
        }
        
        # In production, you might want to log to a file or database
        print(f"REQUEST LOG: {log_data}")
    
    def get_csp_policy(self):
        """Get Content Security Policy string"""
        policy_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net",
            "font-src 'self' https://cdn.jsdelivr.net",
            "img-src 'self' data: https:",
            "connect-src 'self' ws: wss:",
            "frame-ancestors 'self'"
        ]
        return "; ".join(policy_parts)
    
    def blacklist_ip(self, ip, duration=3600):
        """Blacklist an IP address"""
        self.ip_blacklist.add(ip)
        # In production, you might want to persist this to a database
    
    def whitelist_ip(self, ip):
        """Remove IP from blacklist"""
        self.ip_blacklist.discard(ip)
    
    # Error handlers
    def bad_request(self, error):
        return make_response({'error': 'Bad Request', 'message': str(error.description)}, 400)
    
    def forbidden(self, error):
        return make_response({'error': 'Forbidden', 'message': str(error.description)}, 403)
    
    def not_found(self, error):
        return make_response({'error': 'Not Found', 'message': 'Resource not found'}, 404)
    
    def too_many_requests(self, error):
        return make_response({'error': 'Too Many Requests', 'message': str(error.description)}, 429)
    
    def internal_error(self, error):
        return make_response({'error': 'Internal Server Error', 'message': 'Something went wrong'}, 500)

# Decorator for rate limiting specific endpoints
def rate_limit(max_requests=60, time_window=60):
    """Decorator to apply rate limiting to specific endpoints"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            client_ip = request.remote_addr
            middleware = getattr(g, 'security_middleware', None)
            
            if middleware and not middleware.check_rate_limit(client_ip, max_requests, time_window):
                abort(429, description="Rate limit exceeded")
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Decorator for admin-only endpoints
def admin_required(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403, description="Admin access required")
        return f(*args, **kwargs)
    return decorated_function

# Decorator for CSRF protection
def csrf_protect(f):
    """Decorator to add CSRF protection"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.method == 'POST':
            # Check CSRF token
            token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
            if not token or not verify_csrf_token(token):
                abort(403, description="CSRF token invalid")
        return f(*args, **kwargs)
    return decorated_function

def verify_csrf_token(token):
    """Verify CSRF token"""
    # In a real implementation, you would verify against a stored token
    # For now, we'll use a simple check
    return token and len(token) > 10 