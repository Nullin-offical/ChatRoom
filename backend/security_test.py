#!/usr/bin/env python3
"""
Security Test Suite for ChatRoom Application
Tests various security features and configurations
"""

import unittest
import time
import re
from security import security_manager, check_message_security, sanitize_user_input
from middleware import SecurityMiddleware
from config import get_config

class SecurityTestSuite(unittest.TestCase):
    """Test suite for security features"""
    
    def setUp(self):
        """Set up test environment"""
        self.security_manager = security_manager
        self.config = get_config()
    
    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        user_id = 1
        # Reset message history for this user
        self.security_manager.message_history[user_id].clear()
        # Test normal message sending
        for i in range(59):  # Send 59 messages (under limit)
            result, message = self.security_manager.check_rate_limit(user_id)
            self.assertTrue(result, f"Rate limit should allow message {i+1}")
        # Test rate limit exceeded
        result, message = self.security_manager.check_rate_limit(user_id)
        self.assertFalse(result, "Rate limit should be exceeded")
        self.assertIn("banned", message.lower(), "Should ban user for exceeding limit")
        # Test ban duration
        self.assertTrue(self.security_manager.is_user_banned(user_id), "User should be banned")
    
    def test_message_validation(self):
        """Test message content validation"""
        # Test valid message
        valid_message = "Hello, this is a valid message!"
        result, message = self.security_manager.validate_message_content(valid_message)
        self.assertTrue(result, "Valid message should pass validation")
        
        # Test empty message
        result, message = self.security_manager.validate_message_content("")
        self.assertFalse(result, "Empty message should fail validation")
        
        # Test message too long
        long_message = "a" * 1001
        result, message = self.security_manager.validate_message_content(long_message)
        self.assertFalse(result, "Message too long should fail validation")
        
        # Test XSS attempt
        xss_message = "<script>alert('xss')</script>"
        result, message = self.security_manager.validate_message_content(xss_message)
        self.assertFalse(result, "XSS attempt should fail validation")
        
        # Test excessive repetition
        repetitive_message = "a" * 100
        result, message = self.security_manager.validate_message_content(repetitive_message)
        self.assertFalse(result, "Excessive repetition should fail validation")
    
    def test_username_validation(self):
        """Test username validation"""
        # Test valid username
        valid_username = "testuser123"
        result, message = self.security_manager.validate_username(valid_username)
        self.assertTrue(result, "Valid username should pass validation")
        
        # Test username too short
        short_username = "ab"
        result, message = self.security_manager.validate_username(short_username)
        self.assertFalse(result, "Username too short should fail validation")
        
        # Test username too long
        long_username = "a" * 31
        result, message = self.security_manager.validate_username(long_username)
        self.assertFalse(result, "Username too long should fail validation")
        
        # Test invalid characters
        invalid_username = "test@user"
        result, message = self.security_manager.validate_username(invalid_username)
        self.assertFalse(result, "Username with invalid characters should fail validation")
        
        # Test reserved words
        reserved_username = "admin"
        result, message = self.security_manager.validate_username(reserved_username)
        self.assertFalse(result, "Reserved username should fail validation")
    
    def test_input_sanitization(self):
        """Test input sanitization"""
        # Test HTML removal and escaping
        html_input = "<script>alert('xss')</script>Hello"
        sanitized = sanitize_user_input(html_input)
        self.assertNotIn("<", sanitized, "< should be removed or escaped")
        self.assertNotIn(">", sanitized, "> should be removed or escaped")
        self.assertNotIn("<script>", sanitized, "HTML tags should be removed")
        self.assertIn("Hello", sanitized, "Valid content should remain")
        # Test special character escaping
        special_input = "Hello & World < > \" '"
        sanitized = sanitize_user_input(special_input)
        self.assertIn("&amp;", sanitized, "& should be escaped")
        self.assertIn("&lt;", sanitized, "< should be escaped")
        self.assertIn("&gt;", sanitized, "> should be escaped")
        self.assertIn("&quot;", sanitized, "\" should be escaped")
        self.assertIn("&#x27;", sanitized, "' should be escaped")
        # Test empty input
        empty_input = ""
        sanitized = sanitize_user_input(empty_input)
        self.assertEqual(sanitized, "", "Empty input should remain empty")
    
    def test_login_attempts(self):
        """Test login attempt limiting"""
        username = "testuser"
        # Reset login attempts for this user
        self.security_manager.login_attempts[username].clear()
        # Test normal login attempts
        for i in range(4):  # 4 failed attempts
            result, message = self.security_manager.check_login_attempts(username)
            self.assertTrue(result, f"Login attempt {i+1} should be allowed")
            self.security_manager.record_login_attempt(username, success=False)
        # Test limit exceeded
        result, message = self.security_manager.check_login_attempts(username)
        self.assertFalse(result, "Login should be blocked after 5 failed attempts")
        # Test successful login clears attempts
        self.security_manager.record_login_attempt(username, success=True)
        result, message = self.security_manager.check_login_attempts(username)
        self.assertTrue(result, "Login should be allowed after successful login")
    
    def test_ban_system(self):
        """Test user banning system"""
        user_id = 2
        
        # Test user not banned initially
        self.assertFalse(self.security_manager.is_user_banned(user_id), "User should not be banned initially")
        
        # Test banning user
        ban_message = self.security_manager.ban_user(user_id, 1)  # 1 minute ban
        self.assertIn("banned", ban_message.lower(), "Ban message should mention ban")
        
        # Test user is banned
        self.assertTrue(self.security_manager.is_user_banned(user_id), "User should be banned")
        
        # Test ban expiration (simulate time passing)
        # Note: In real tests, you might want to mock time.time()
        # For now, we'll just test the ban was created
        self.assertIn(user_id, self.security_manager.banned_users, "User should be in banned list")
    
    def test_message_security_integration(self):
        """Test integrated message security"""
        user_id = 3
        
        # Test valid message
        valid_message = "Hello, world!"
        result, message = check_message_security(user_id, valid_message)
        self.assertTrue(result, "Valid message should pass security check")
        
        # Test rate limit exceeded
        for i in range(60):  # Exceed rate limit
            check_message_security(user_id, f"Message {i}")
        
        result, message = check_message_security(user_id, "This should be blocked")
        self.assertFalse(result, "Message should be blocked after rate limit exceeded")
        self.assertIn("banned", message.lower(), "Should mention ban in error message")
    
    def test_configuration(self):
        """Test security configuration"""
        # Test configuration loading
        self.assertIsNotNone(self.config, "Configuration should be loaded")
        
        # Test required security settings
        self.assertIsNotNone(self.config.SECRET_KEY, "SECRET_KEY should be set")
        self.assertIsNotNone(self.config.MAX_MESSAGES_PER_MINUTE, "MAX_MESSAGES_PER_MINUTE should be set")
        self.assertIsNotNone(self.config.MAX_LOGIN_ATTEMPTS, "MAX_LOGIN_ATTEMPTS should be set")
        
        # Test security headers configuration
        self.assertIsNotNone(self.config.SECURITY_HEADERS, "SECURITY_HEADERS should be configured")
        self.assertIn('X-Content-Type-Options', self.config.SECURITY_HEADERS, "X-Content-Type-Options should be set")
        self.assertIn('X-Frame-Options', self.config.SECURITY_HEADERS, "X-Frame-Options should be set")
    
    def test_middleware_patterns(self):
        """Test middleware suspicious pattern detection"""
        middleware = SecurityMiddleware()
        # Only test patterns that exist in suspicious_patterns
        suspicious_inputs = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "data:text/html,<script>alert('xss')</script>",
            "onclick=alert('xss')",
            "../etc/passwd",
            "..\\windows\\system32",  # This will match the new pattern
        ]
        for input_str in suspicious_inputs:
            found = any(re.search(pattern, input_str, re.IGNORECASE) for pattern in middleware.suspicious_patterns)
            self.assertTrue(found, f"Pattern should be detected in: {input_str}")

def run_security_tests():
    """Run all security tests"""
    print("Running ChatRoom Security Test Suite...")
    print("=" * 50)
    
    # Create test suite
    suite = unittest.TestLoader().loadTestsFromTestCase(SecurityTestSuite)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Print summary
    print("=" * 50)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    
    if result.failures:
        print("\nFailures:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback}")
    
    if result.errors:
        print("\nErrors:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback}")
    
    if result.wasSuccessful():
        print("\n✅ All security tests passed!")
    else:
        print("\n❌ Some security tests failed!")
    
    return result.wasSuccessful()

if __name__ == '__main__':
    run_security_tests() 