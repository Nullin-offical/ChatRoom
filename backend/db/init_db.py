import sqlite3
import os
import bcrypt
import re

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'chatroom.db')
SCHEMA_PATH = os.path.join(os.path.dirname(BASE_DIR), 'models', 'schema.sql')

DEFAULT_ADMIN = {
    'username': 'shayan',
    'email': 'shayanqasmy@gmail.com',
    'password': 'shayan.1400'
}

def slugify(value):
    value = str(value)
    value = value.strip().lower()
    value = re.sub(r'[^a-z0-9\u0600-\u06FF]+', '-', value)
    value = re.sub(r'-+', '-', value)
    return value.strip('-')

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
        # Ensure private_messages table exists (migration for PM feature)
        cur.execute('''CREATE TABLE IF NOT EXISTS private_messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (receiver_id) REFERENCES users(id) ON DELETE CASCADE
        )''')
        conn.commit()
        print('Private messages table ensured.')
        
        # Ensure deleted_chats table exists (for one-sided chat deletion)
        cur.execute('''CREATE TABLE IF NOT EXISTS deleted_chats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            other_user_id INTEGER NOT NULL,
            deleted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (other_user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, other_user_id)
        )''')
        conn.commit()
        print('Deleted chats table ensured.')
        
        # Ensure user_blocks table exists (for block/unblock functionality)
        cur.execute('''CREATE TABLE IF NOT EXISTS user_blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (blocker_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (blocked_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(blocker_id, blocked_id)
        )''')
        conn.commit()
        print('User blocks table ensured.')
        

        
        # MIGRATION: Add password column to rooms table if not exists
        cur.execute('PRAGMA table_info(rooms)')
        columns = [col[1] for col in cur.fetchall()]
        if 'password' not in columns:
            cur.execute('ALTER TABLE rooms ADD COLUMN password TEXT')
            conn.commit()
            print('Password column added to rooms table.')
        conn.close()

if __name__ == '__main__':
    init_db() 