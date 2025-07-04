import sqlite3
import os

def migrate():
    db_path = os.path.join(os.path.dirname(__file__), 'chatroom.db')
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Create settings table if not exists
    cur.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    # Insert default site_name if not exists
    cur.execute('''
        INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)
    ''', ('site_name', 'ChatRoom'))
    conn.commit()
    print('Migration complete: settings table created and default site_name set.')
    conn.close()

if __name__ == '__main__':
    migrate() 