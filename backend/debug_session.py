#!/usr/bin/env python3
"""
Debug script for session issues on hosting
"""

import os
import sys

# Set production environment
os.environ['FLASK_ENV'] = 'production'

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_session_config():
    """Test session configuration"""
    print("=== Testing Session Configuration ===\n")
    
    try:
        from app import app
        
        print("Session Configuration:")
        print(f"SECRET_KEY: {'Set' if app.config.get('SECRET_KEY') else 'Not Set'}")
        print(f"SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE', 'Not Set')}")
        print(f"SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY', 'Not Set')}")
        print(f"SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE', 'Not Set')}")
        print(f"PERMANENT_SESSION_LIFETIME: {app.config.get('PERMANENT_SESSION_LIFETIME', 'Not Set')}")
        
        return True
    except Exception as e:
        print(f"Error testing session config: {e}")
        return False

def test_login_flow():
    """Test login flow"""
    print("\n=== Testing Login Flow ===\n")
    
    try:
        from app import app
        from auth import authenticate_user
        
        # Test user authentication
        test_user = authenticate_user('shayan', 'shayan.1400')
        if test_user:
            print(f"✓ User authentication successful: {test_user.username}")
        else:
            print("✗ User authentication failed")
            return False
        
        # Test session creation
        with app.test_request_context():
            from flask_login import login_user, current_user
            
            login_user(test_user)
            print(f"✓ User logged in: {current_user.username}")
            print(f"✓ User authenticated: {current_user.is_authenticated}")
            
            # Test session persistence
            from flask import session
            print(f"✓ Session ID: {session.get('_fresh', 'Not Set')}")
            
        return True
    except Exception as e:
        print(f"Error testing login flow: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_redirect_handling():
    """Test redirect handling"""
    print("\n=== Testing Redirect Handling ===\n")
    
    try:
        from app import app
        
        with app.test_request_context('/login?next=/dashboard'):
            from flask import request
            next_page = request.args.get('next')
            print(f"✓ Next parameter: {next_page}")
            
            if next_page and next_page.startswith('/'):
                print(f"✓ Valid redirect URL: {next_page}")
            else:
                print("✗ Invalid redirect URL")
        
        return True
    except Exception as e:
        print(f"Error testing redirect handling: {e}")
        return False

def main():
    """Run all debug tests"""
    print("=== ChatRoom Session Debug ===\n")
    
    tests = [
        ("Session Configuration", test_session_config),
        ("Login Flow", test_login_flow),
        ("Redirect Handling", test_redirect_handling)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"Running {test_name}...")
        if test_func():
            passed += 1
            print(f"✓ {test_name} passed\n")
        else:
            print(f"✗ {test_name} failed\n")
    
    print(f"=== Debug Results: {passed}/{total} tests passed ===")
    
    if passed == total:
        print("\n🎉 All tests passed! Session should work correctly.")
    else:
        print("\n⚠️  Some tests failed. Check the session configuration.")

if __name__ == '__main__':
    main() 