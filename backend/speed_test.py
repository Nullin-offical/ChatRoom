#!/usr/bin/env python3
"""
Simple speed test for production optimizations
"""

import time
import os
import sys

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_home_page_speed():
    """Test home page loading speed"""
    print("Testing home page speed...")
    
    try:
        from app import app
        
        with app.test_client() as client:
            start_time = time.time()
            response = client.get('/')
            end_time = time.time()
            
            load_time = end_time - start_time
            print(f"Home page loaded in {load_time:.3f} seconds")
            
            if load_time < 2.0:
                print("✅ Speed test PASSED - Page loads quickly")
                return True
            else:
                print("❌ Speed test FAILED - Page loads too slowly")
                return False
                
    except Exception as e:
        print(f"❌ Speed test failed with error: {e}")
        return False

def test_database_speed():
    """Test database query speed"""
    print("\nTesting database speed...")
    
    try:
        from app import get_db
        
        with get_db() as conn:
            cur = conn.cursor()
            
            # Test user count query
            start_time = time.time()
            cur.execute('SELECT COUNT(*) FROM users')
            user_count = cur.fetchone()[0]
            end_time = time.time()
            
            query_time = end_time - start_time
            print(f"User count query: {query_time:.3f} seconds")
            
            if query_time < 0.1:
                print("✅ Database test PASSED - Queries are fast")
                return True
            else:
                print("❌ Database test FAILED - Queries are slow")
                return False
                
    except Exception as e:
        print(f"❌ Database test failed with error: {e}")
        return False

if __name__ == '__main__':
    print("=== ChatRoom Speed Test ===\n")
    
    home_test = test_home_page_speed()
    db_test = test_database_speed()
    
    print("\n=== Results ===")
    print(f"Home Page: {'✅ PASS' if home_test else '❌ FAIL'}")
    print(f"Database: {'✅ PASS' if db_test else '❌ FAIL'}")
    
    if home_test and db_test:
        print("\n🎉 All speed tests passed! Site should load quickly.")
    else:
        print("\n⚠️ Some tests failed. Check the optimizations.") 
 
 