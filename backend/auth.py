import sqlite3
import os
from flask_login import UserMixin
import bcrypt

# Import the centralized database functions
from database import get_db, DatabaseContext, with_db_retry

class User(UserMixin):
    def __init__(self, id, username, email, hashed_password, is_admin, created_at=None, 
                 display_name=None, bio=None, birth_date=None, profile_image=None, last_seen=None):
        self.id = id
        self.username = username
        self.email = email
        self.hashed_password = hashed_password
        self.is_admin = is_admin
        self.created_at = created_at or "2024-01-01"  # Default fallback
        self.display_name = display_name or username
        self.bio = bio or ""
        self.birth_date = birth_date
        self.profile_image = profile_image
        self.last_seen = last_seen

    @staticmethod
    def get(user_id):
        return get_user_by_id(user_id)

def get_user_by_id(user_id):
    """Get user by ID using centralized database connection"""
    try:
        with DatabaseContext() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, username, email, hashed_password, is_admin, created_at, 
                           display_name, bio, birth_date, profile_image, last_seen FROM users WHERE id = ?''', (user_id,))
            row = cur.fetchone()
            if row:
                return User(*row)
            return None
    except Exception as e:
        print(f"Error getting user by ID {user_id}: {e}")
        return None

def get_user_by_username(username):
    """Get user by username using centralized database connection"""
    try:
        with DatabaseContext() as conn:
            cur = conn.cursor()
            cur.execute('''SELECT id, username, email, hashed_password, is_admin, created_at, 
                           display_name, bio, birth_date, profile_image, last_seen FROM users WHERE username = ?''', (username,))
            row = cur.fetchone()
            if row:
                return User(*row)
            return None
    except Exception as e:
        print(f"Error getting user by username {username}: {e}")
        return None

def register_user(username, email, password):
    """
    Register a new user with robust error handling and retry logic.
    Returns (user, error_message) tuple.
    """
    print(f"DEBUG: Starting registration for username: {username}, email: {email}")
    
    # Check if username already exists
    existing_user = get_user_by_username(username)
    if existing_user:
        print(f"DEBUG: Username {username} already exists")
        return None, 'Username already exists.'
    
    # Hash the password
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    print(f"DEBUG: Password hashed successfully")
    
    def do_register():
        print(f"DEBUG: Inside do_register function")
        with DatabaseContext() as conn:
            cur = conn.cursor()
            # Check if email already exists
            cur.execute('SELECT id FROM users WHERE email = ?', (email,))
            if cur.fetchone():
                print(f"DEBUG: Email {email} already exists")
                return None, 'Email already exists.'
            print(f"DEBUG: Inserting new user")
            cur.execute('INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)',
                        (username, email, hashed))
            user_id = cur.lastrowid
            print(f"DEBUG: User inserted with ID: {user_id}")
            # Fetch the user from the same connection before commit
            cur.execute('''SELECT id, username, email, hashed_password, is_admin, created_at, 
                           display_name, bio, birth_date, profile_image, last_seen FROM users WHERE id = ?''', (user_id,))
            row = cur.fetchone()
            if row:
                print(f"DEBUG: Retrieved user from same connection: {row}")
                return User(*row), None
            print(f"DEBUG: Could not retrieve user after insert")
            return None, 'Registration failed. Please try again.'
    try:
        print(f"DEBUG: Calling with_db_retry")
        result = with_db_retry(do_register)
        print(f"DEBUG: with_db_retry returned: {result}")
        return result
    except sqlite3.IntegrityError as e:
        print(f"DEBUG: IntegrityError caught: {e}")
        if "UNIQUE constraint failed" in str(e):
            if "username" in str(e):
                return None, 'Username already exists.'
            elif "email" in str(e):
                return None, 'Email already exists.'
        return None, 'Registration failed. Please try again.'
    except Exception as e:
        print(f"DEBUG: Exception caught: {e}")
        return None, 'Registration failed. Please try again.'

def authenticate_user(username, password):
    """Authenticate user with proper error handling"""
    try:
        user = get_user_by_username(username)
        if user:
            hashed = user.hashed_password
            if isinstance(hashed, str):
                hashed = hashed.encode('utf-8')
            if bcrypt.checkpw(password.encode('utf-8'), hashed):
                return user
        return None
    except Exception as e:
        print(f"Error during authentication: {e}")
        return None 