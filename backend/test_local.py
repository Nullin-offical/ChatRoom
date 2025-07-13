#!/usr/bin/env python3
"""
Test script for local development
This script helps test the application locally
"""

import os
import sys

# Set development environment
os.environ['FLASK_ENV'] = 'development'
os.environ['DATABASE_PATH'] = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_imports():
    """Test if all imports work correctly"""
    try:
        from app import app, socketio
        print("✓ Flask app imported successfully")
        
        from auth import User, get_user_by_id, get_user_by_username
        print("✓ Auth module imported successfully")
        
        from db.init_db import init_db
        print("✓ Database module imported successfully")
        
        from security import security_manager
        print("✓ Security module imported successfully")
        
        return True
    except Exception as e:
        print(f"✗ Import error: {e}")
        return False

def test_database():
    """Test database connection and initialization"""
    try:
        from db.init_db import init_db
        init_db()
        print("✓ Database initialized successfully")
        
        from auth import get_user_by_username
        admin_user = get_user_by_username('shayan')  # Changed from 'admin' to 'shayan'
        if admin_user:
            print("✓ Admin user found in database")
        else:
            print("✗ Admin user not found")
            return False
        
        return True
    except Exception as e:
        print(f"✗ Database error: {e}")
        return False

def test_flask_app():
    """Test Flask app configuration"""
    try:
        from app import app
        
        # Test basic configuration
        if app.config.get('SECRET_KEY'):
            print("✓ Secret key configured")
        else:
            print("✗ Secret key not configured")
            return False
        
        # Test static folder
        if app.static_folder:
            print(f"✓ Static folder: {app.static_folder}")
        else:
            print("✗ Static folder not configured")
            return False
        
        # Test template folder
        if app.template_folder:
            print(f"✓ Template folder: {app.template_folder}")
        else:
            print("✗ Template folder not configured")
            return False
        
        return True
    except Exception as e:
        print(f"✗ Flask app error: {e}")
        return False

def main():
    """Run all tests"""
    print("=== ChatRoom Local Development Test ===\n")
    
    tests = [
        ("Import Test", test_imports),
        ("Database Test", test_database),
        ("Flask App Test", test_flask_app)
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
    
    print(f"=== Test Results: {passed}/{total} tests passed ===")
    
    if passed == total:
        print("\n🎉 All tests passed! You can now run the application with:")
        print("   python app.py")
        print("   or")
        print("   python run.py")
    else:
        print("\n❌ Some tests failed. Please fix the issues before running the application.")

if __name__ == '__main__':
    main() 