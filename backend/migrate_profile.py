#!/usr/bin/env python3
"""
Database migration script to add profile fields to users table
"""

import sqlite3
import os
from datetime import datetime

def migrate_profile_fields():
    db_path = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')
    
    # Check if database exists
    if not os.path.exists(db_path):
        print("Database not found. Please run the application first to create it.")
        return
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    try:
        # Check if profile fields exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        
        new_fields = ['display_name', 'bio', 'birth_date', 'profile_image']
        fields_to_add = []
        
        for field in new_fields:
            if field not in columns:
                fields_to_add.append(field)
        
        if fields_to_add:
            print(f"Adding profile fields: {', '.join(fields_to_add)}")
            
            # Add each field
            for field in fields_to_add:
                if field == 'display_name':
                    cursor.execute("ALTER TABLE users ADD COLUMN display_name TEXT")
                elif field == 'bio':
                    cursor.execute("ALTER TABLE users ADD COLUMN bio TEXT")
                elif field == 'birth_date':
                    cursor.execute("ALTER TABLE users ADD COLUMN birth_date DATE")
                elif field == 'profile_image':
                    cursor.execute("ALTER TABLE users ADD COLUMN profile_image TEXT")
            
            conn.commit()
            print("Profile fields migration completed successfully!")
        else:
            print("All profile fields already exist.")
            
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_profile_fields() 