#!/usr/bin/env python3
"""
Database Optimization Script
Adds indexes to improve query performance without changing functionality
"""

import sqlite3
import os

def optimize_database():
    """Add performance indexes to the database"""
    db_path = 'db/chatroom.db'
    
    if not os.path.exists(db_path):
        print(f"Database file {db_path} not found!")
        return
    
    print("Starting database optimization...")
    
    with sqlite3.connect(db_path) as conn:
        cur = conn.cursor()
        
        # Get current indexes
        cur.execute("SELECT name FROM sqlite_master WHERE type='index'")
        existing_indexes = {row[0] for row in cur.fetchall()}
        print(f"Existing indexes: {existing_indexes}")
        
        # Define indexes for better performance
        indexes = [
            # Messages table indexes
            ("idx_messages_room_timestamp", "messages", "room_id, timestamp DESC"),
            ("idx_messages_sender_timestamp", "messages", "sender_id, timestamp DESC"),
            ("idx_messages_timestamp", "messages", "timestamp DESC"),
            
            # Private messages indexes
            ("idx_private_messages_sender_receiver", "private_messages", "sender_id, receiver_id"),
            ("idx_private_messages_receiver_sender", "private_messages", "receiver_id, sender_id"),
            ("idx_private_messages_timestamp", "private_messages", "timestamp DESC"),
            
            # Users table indexes
            ("idx_users_username", "users", "username"),
            ("idx_users_last_seen", "users", "last_seen DESC"),
            
            # Rooms table indexes
            ("idx_rooms_slug", "rooms", "slug"),
            ("idx_rooms_created", "rooms", "created_at DESC"),
            
            # User blocks indexes
            ("idx_user_blocks_blocker", "user_blocks", "blocker_id"),
            ("idx_user_blocks_blocked", "user_blocks", "blocked_id"),
            
            # Deleted chats indexes
            ("idx_deleted_chats_user", "deleted_chats", "user_id"),
            ("idx_deleted_chats_other", "deleted_chats", "other_user_id"),
        ]
        
        # Create indexes
        created_count = 0
        for index_name, table_name, columns in indexes:
            if index_name not in existing_indexes:
                try:
                    cur.execute(f"CREATE INDEX {index_name} ON {table_name} ({columns})")
                    print(f"✓ Created index: {index_name}")
                    created_count += 1
                except sqlite3.Error as e:
                    print(f"✗ Failed to create index {index_name}: {e}")
            else:
                print(f"- Index already exists: {index_name}")
        
        # Analyze tables for better query planning
        print("\nAnalyzing tables for better query planning...")
        cur.execute("ANALYZE")
        
        # Get table statistics
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cur.fetchall()
        
        for table in tables:
            table_name = table[0]
            cur.execute(f"SELECT COUNT(*) FROM {table_name}")
            count = cur.fetchone()[0]
            print(f"Table {table_name}: {count} rows")
        
        print(f"\nDatabase optimization complete!")
        print(f"Created {created_count} new indexes")
        print("Query performance should be significantly improved.")

if __name__ == "__main__":
    optimize_database() 