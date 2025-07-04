#!/usr/bin/env python3
"""
Database migration script to add created_at column to users table
"""

import sqlite3
import os
from datetime import datetime

def migrate_database():
    db_path = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')
    
    # Check if database exists
    if not os.path.exists(db_path):
        print("Database not found. Please run the application first to create it.")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if created_at column exists
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        if 'created_at' not in columns:
            print("Adding created_at column to users table...")
            
            # Create new table with created_at column
            cursor.execute("""
                CREATE TABLE users_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    hashed_password TEXT NOT NULL,
                    is_admin INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Copy data from old table to new table
            cursor.execute("""
                INSERT INTO users_new (id, username, email, hashed_password, is_admin, created_at)
                SELECT id, username, email, hashed_password, is_admin, CURRENT_TIMESTAMP
                FROM users
            """)
            
            # Drop old table
            cursor.execute("DROP TABLE users")
            
            # Rename new table to users
            cursor.execute("ALTER TABLE users_new RENAME TO users")
            
            conn.commit()
            print("Migration completed successfully!")
        else:
            print("created_at column already exists.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_database() 