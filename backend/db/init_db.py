import sqlite3
import os
import bcrypt
import re
from utils import slugify

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'chatroom.db')
SCHEMA_PATH = os.path.join(os.path.dirname(BASE_DIR), 'models', 'schema.sql')

DEFAULT_ADMIN = {
    'username': 'admin',
    'email': 'shayan@gmail.com',
    'password': 'shayan.1400'
}

def init_db():
    if not os.path.exists(DB_PATH):
        conn = sqlite3.connect(DB_PATH)
        with open(SCHEMA_PATH, 'r', encoding='utf-8') as f:
            conn.executescript(f.read())
        # Create default admin if not exists
        cur = conn.cursor()
        cur.execute('SELECT id FROM users WHERE username=? OR email=?', (DEFAULT_ADMIN['username'], DEFAULT_ADMIN['email']))
        if not cur.fetchone():
            hashed = bcrypt.hashpw(DEFAULT_ADMIN['password'].encode('utf-8'), bcrypt.gensalt())
            conn.execute('INSERT INTO users (username, email, hashed_password, is_admin) VALUES (?, ?, ?, 1)',
                         (DEFAULT_ADMIN['username'], DEFAULT_ADMIN['email'], hashed))
            conn.commit()
            print('Database initialized. Default admin created.')
        else:
            print('Database initialized. Admin user already exists.')
        conn.close()
    else:
        # Check if admin exists, if not, create
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute('SELECT id FROM users WHERE is_admin=1')
        if not cur.fetchone():
            cur.execute('SELECT id FROM users WHERE username=? OR email=?', (DEFAULT_ADMIN['username'], DEFAULT_ADMIN['email']))
            if not cur.fetchone():
                hashed = bcrypt.hashpw(DEFAULT_ADMIN['password'].encode('utf-8'), bcrypt.gensalt())
                conn.execute('INSERT INTO users (username, email, hashed_password, is_admin) VALUES (?, ?, ?, 1)',
                             (DEFAULT_ADMIN['username'], DEFAULT_ADMIN['email'], hashed))
                conn.commit()
                print('Default admin created.')
            else:
                print('Admin username/email already exists, not creating new admin.')
        else:
            print('Database already exists and admin user present.')
        # MIGRATION: fill slug for existing rooms if missing
        cur.execute('PRAGMA table_info(rooms)')
        columns = [col[1] for col in cur.fetchall()]
        if 'slug' in columns:
            cur.execute('SELECT id, name FROM rooms WHERE slug IS NULL OR slug=""')
            for room_id, name in cur.fetchall():
                slug = slugify(name)
                cur.execute('UPDATE rooms SET slug=? WHERE id=?', (slug, room_id))
            conn.commit()
            print('Room slugs migrated.')
        conn.close()

if __name__ == '__main__':
    init_db() 