#!/usr/bin/env python3
"""
Migration script to add last_seen field to users table
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')

def migrate_last_seen():
    """Add last_seen field to users table"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    try:
        # Check if last_seen column already exists
        cur.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cur.fetchall()]
        
        if 'last_seen' not in columns:
            print("Adding last_seen column to users table...")
            cur.execute("ALTER TABLE users ADD COLUMN last_seen TIMESTAMP")
            # Update existing records with current timestamp
            cur.execute("UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE last_seen IS NULL")
            conn.commit()
            print("✓ last_seen column added successfully")
        else:
            print("✓ last_seen column already exists")
            
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    print("Starting last_seen migration...")
    migrate_last_seen()
    print("Migration completed!") 