#!/usr/bin/env python3
"""
Security test script for password-protected rooms
This script tests that users cannot access password-protected rooms without proper authentication
"""

import os
import sys
import sqlite3
from datetime import datetime

# Set development environment
os.environ['FLASK_ENV'] = 'development'

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_room_password_protection():
    """Test that password-protected rooms are properly secured"""
    print("=== Testing Room Password Protection ===\n")
    
    try:
        from app import app, check_room_access
        from auth import get_user_by_username
        
        # Create a test context
        with app.test_request_context():
            # Simulate a user session
            app.config['TESTING'] = True
            
            # Get admin user
            admin_user = get_user_by_username('shayan')
            if not admin_user:
                print("✗ Admin user not found")
                return False
            
            print(f"✓ Using test user: {admin_user.username}")
            
            # Test 1: Create a password-protected room
            print("\n1. Testing room creation with password...")
            with app.app_context():
                from app import get_db
                with get_db() as conn:
                    cur = conn.cursor()
                    
                    # Create a test room with password
                    test_room_slug = 'test-secure-room'
                    test_password = 'secret123'
                    
                    cur.execute('''
                        INSERT OR REPLACE INTO rooms (name, slug, password, created_at) 
                        VALUES (?, ?, ?, ?)
                    ''', ('Test Secure Room', test_room_slug, test_password, datetime.now().isoformat()))
                    conn.commit()
                    print(f"✓ Created test room: {test_room_slug}")
            
            # Test 2: Check access without password (should fail)
            print("\n2. Testing access without password...")
            access_ok, access_msg = check_room_access(test_room_slug, admin_user.id)
            if not access_ok:
                print(f"✓ Access correctly denied: {access_msg}")
            else:
                print(f"✗ Access incorrectly granted to password-protected room")
                return False
            
            # Test 3: Simulate password verification in session
            print("\n3. Testing access with password verification...")
            with app.test_request_context():
                # Simulate successful password verification
                from flask import session
                session[f'room_access_{test_room_slug}'] = True
                
                access_ok, access_msg = check_room_access(test_room_slug, admin_user.id)
                if access_ok:
                    print(f"✓ Access correctly granted after password verification")
                else:
                    print(f"✗ Access incorrectly denied after password verification: {access_msg}")
                    return False
            
            # Test 4: Test access to public room (should work)
            print("\n4. Testing access to public room...")
            with app.app_context():
                with get_db() as conn:
                    cur = conn.cursor()
                    
                    # Create a public room
                    public_room_slug = 'test-public-room'
                    cur.execute('''
                        INSERT OR REPLACE INTO rooms (name, slug, created_at) 
                        VALUES (?, ?, ?)
                    ''', ('Test Public Room', public_room_slug, datetime.now().isoformat()))
                    conn.commit()
                    print(f"✓ Created public room: {public_room_slug}")
            
            with app.test_request_context():
                access_ok, access_msg = check_room_access(public_room_slug, admin_user.id)
                if access_ok:
                    print(f"✓ Access correctly granted to public room")
                else:
                    print(f"✗ Access incorrectly denied to public room: {access_msg}")
                    return False
            
            # Test 5: Test non-existent room
            print("\n5. Testing access to non-existent room...")
            with app.test_request_context():
                access_ok, access_msg = check_room_access('non-existent-room', admin_user.id)
                if not access_ok:
                    print(f"✓ Access correctly denied to non-existent room: {access_msg}")
                else:
                    print(f"✗ Access incorrectly granted to non-existent room")
                    return False
            
            # Cleanup
            print("\n6. Cleaning up test data...")
            with app.app_context():
                with get_db() as conn:
                    cur = conn.cursor()
                    cur.execute('DELETE FROM rooms WHERE slug IN (?, ?)', (test_room_slug, public_room_slug))
                    conn.commit()
                    print("✓ Test data cleaned up")
            
            print("\n🎉 All security tests passed!")
            return True
            
    except Exception as e:
        print(f"✗ Security test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_session_management():
    """Test that session-based access control works correctly"""
    print("\n=== Testing Session Management ===\n")
    
    try:
        from app import app
        
        with app.test_request_context():
            from flask import session
            
            # Test session storage and retrieval
            test_room = 'test-room-session'
            session[f'room_access_{test_room}'] = True
            
            # Verify session data
            if session.get(f'room_access_{test_room}', False):
                print("✓ Session storage and retrieval working correctly")
            else:
                print("✗ Session storage and retrieval failed")
                return False
            
            # Test session clearing
            session[f'room_access_{test_room}'] = False
            if not session.get(f'room_access_{test_room}', False):
                print("✓ Session clearing working correctly")
            else:
                print("✗ Session clearing failed")
                return False
            
            print("🎉 Session management tests passed!")
            return True
            
    except Exception as e:
        print(f"✗ Session management test failed with error: {e}")
        return False

def main():
    """Run all security tests"""
    print("=== ChatRoom Security Test Suite ===\n")
    
    tests = [
        ("Room Password Protection", test_room_password_protection),
        ("Session Management", test_session_management)
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
    
    print(f"=== Security Test Results: {passed}/{total} tests passed ===")
    
    if passed == total:
        print("\n🔒 All security tests passed! Password-protected rooms are properly secured.")
    else:
        print("\n⚠️  Some security tests failed. Please review the security implementation.")

if __name__ == '__main__':
    main() 