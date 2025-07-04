#!/usr/bin/env python3
"""
Migration script to add hidden field to rooms table
"""

import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')

def migrate_rooms_hidden():
    """Add hidden field to rooms table"""
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    try:
        # Check if hidden column already exists
        cur.execute("PRAGMA table_info(rooms)")
        columns = [column[1] for column in cur.fetchall()]
        
        if 'hidden' not in columns:
            print("Adding hidden column to rooms table...")
            cur.execute("ALTER TABLE rooms ADD COLUMN hidden BOOLEAN DEFAULT 0")
            conn.commit()
            print("✓ Hidden column added successfully")
        else:
            print("✓ Hidden column already exists")
            
    except Exception as e:
        print(f"Error during migration: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    print("Starting rooms hidden migration...")
    migrate_rooms_hidden()
    print("Migration completed!") 