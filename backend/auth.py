import sqlite3
import os
from flask_login import UserMixin
import bcrypt

DB_PATH = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')

class User(UserMixin):
    def __init__(self, id, username, email, hashed_password, is_admin, created_at=None, 
                 display_name=None, bio=None, birth_date=None, profile_image=None):
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

    @staticmethod
    def get(user_id):
        return get_user_by_id(user_id)

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT id, username, email, hashed_password, is_admin, created_at, 
                   display_name, bio, birth_date, profile_image FROM users WHERE id = ?''', (user_id,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

def get_user_by_username(username):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute('''SELECT id, username, email, hashed_password, is_admin, created_at, 
                   display_name, bio, birth_date, profile_image FROM users WHERE username = ?''', (username,))
    row = cur.fetchone()
    conn.close()
    if row:
        return User(*row)
    return None

def register_user(username, email, password):
    if get_user_by_username(username):
        return None, 'Username already exists.'
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('INSERT INTO users (username, email, hashed_password) VALUES (?, ?, ?)',
                    (username, email, hashed))
        conn.commit()
        user_id = cur.lastrowid
        conn.close()
        return get_user_by_id(user_id), None
    except sqlite3.IntegrityError as e:
        return None, 'Email already exists.'

def authenticate_user(username, password):
    user = get_user_by_username(username)
    if user:
        hashed = user.hashed_password
        if isinstance(hashed, str):
            hashed = hashed.encode('utf-8')
        if bcrypt.checkpw(password.encode('utf-8'), hashed):
            return user
    return None 