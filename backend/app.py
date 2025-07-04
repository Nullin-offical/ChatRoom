from flask import Flask, jsonify, render_template, request, redirect, url_for, flash, abort, session
from flask_cors import CORS
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
import os
from auth import User, register_user, authenticate_user, get_user_by_id
from auth import get_user_by_username
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
from datetime import datetime
from functools import wraps
import re
from utils import slugify

# --- App Config ---
app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
CORS(app)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')
socketio = SocketIO(app, cors_allowed_origins="*")

# --- Login Manager ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return get_user_by_id(user_id)

# --- Error Handlers ---
@app.errorhandler(404)
def not_found(e):
    return render_template('base.html', content='<div class="text-center py-5"><h2>404 - Not Found</h2><p>The page you are looking for does not exist.</p></div>'), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('base.html', content='<div class="text-center py-5"><h2>403 - Forbidden</h2><p>You do not have permission to access this page.</p></div>'), 403

@app.errorhandler(500)
def server_error(e):
    return render_template('base.html', content='<div class="text-center py-5"><h2>500 - Server Error</h2><p>Something went wrong. Please try again later.</p></div>'), 500

# --- Database Helper ---
def get_db():
    db_path = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')
    return sqlite3.connect(db_path)

# --- Main Routes ---
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/api/ping')
def ping():
    return jsonify({'status': 'ok'})

# --- Auth Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm_password']
        if password != confirm:
            error = 'Passwords do not match.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            user, reg_error = register_user(username, email, password)
            if reg_error:
                error = reg_error
            else:
                login_user(user)
                return redirect(url_for('dashboard'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = authenticate_user(username, password)
        if user:
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            error = 'Invalid username or password.'
    return render_template('login.html', error=error)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

# --- Dashboard ---
@app.route('/dashboard')
@login_required
def dashboard():
    rooms = fetch_rooms()
    return render_template('dashboard.html', rooms=rooms)

# --- Chatroom ---
@app.route('/chat')
@login_required
def chat():
    rooms = fetch_rooms()
    return render_template('chat.html', rooms=rooms, current_user_username=current_user.username)

# --- Admin ---
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not getattr(current_user, 'is_admin', False):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin', methods=['GET'])
@login_required
@admin_required
def admin_panel():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, username, email, is_admin FROM users')
        users = [dict(id=row[0], username=row[1], email=row[2], is_admin=row[3]) for row in cur.fetchall()]
        cur.execute('''SELECT messages.id, users.username, messages.content, messages.timestamp FROM messages JOIN users ON messages.sender_id = users.id ORDER BY messages.timestamp DESC LIMIT 100''')
        messages = [dict(id=row[0], username=row[1], content=row[2], timestamp=row[3]) for row in cur.fetchall()]
    rooms = fetch_rooms()
    return render_template('admin.html', users=users, messages=messages, rooms=rooms)

@app.route('/admin/delete_user', methods=['POST'])
@login_required
@admin_required
def admin_delete_user():
    user_id = request.form.get('user_id')
    if not user_id or int(user_id) == current_user.id:
        flash('Cannot delete yourself.', 'danger')
        return redirect(url_for('admin_panel'))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete_message', methods=['POST'])
@login_required
@admin_required
def admin_delete_message():
    message_id = request.form.get('message_id')
    if not message_id:
        flash('Invalid message.', 'danger')
        return redirect(url_for('admin_panel'))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('DELETE FROM messages WHERE id = ?', (message_id,))
        conn.commit()
    flash('Message deleted.', 'success')
    return redirect(url_for('admin_panel'))

# --- Profile Management ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    error = None
    success = None
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        with get_db() as conn:
            cur = conn.cursor()
            # Check for username/email conflicts
            cur.execute('SELECT id FROM users WHERE username=? AND id!=?', (username, current_user.id))
            if cur.fetchone():
                error = 'Username already taken.'
            else:
                cur.execute('SELECT id FROM users WHERE email=? AND id!=?', (email, current_user.id))
                if cur.fetchone():
                    error = 'Email already taken.'
        if not error:
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute('UPDATE users SET username=?, email=? WHERE id=?', (username, email, current_user.id))
                if password:
                    import bcrypt
                    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    cur.execute('UPDATE users SET hashed_password=? WHERE id=?', (hashed, current_user.id))
                conn.commit()
            success = 'Profile updated.'
    # Fetch latest user info
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT username, email FROM users WHERE id=?', (current_user.id,))
        user = cur.fetchone()
    return render_template('profile.html', user=user, error=error, success=success)

# --- Room Management ---
@app.route('/admin/create_room', methods=['POST'])
@login_required
@admin_required
def admin_create_room():
    room_name = request.form.get('room_name', '').strip()
    if not room_name:
        flash('Room name required.', 'danger')
        return redirect(url_for('admin_panel') + '#rooms')
    slug = slugify(room_name)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM rooms WHERE slug=?', (slug,))
        if cur.fetchone():
            flash('Room with this name already exists.', 'danger')
            return redirect(url_for('admin_panel') + '#rooms')
        cur.execute('INSERT INTO rooms (name, slug) VALUES (?, ?)', (room_name, slug))
        conn.commit()
    flash('Room created.', 'success')
    # Notify all clients via SocketIO
    socketio.emit('room_list', fetch_rooms())
    return redirect(url_for('admin_panel') + '#rooms')

# --- Real-time Room List ---
def fetch_rooms():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, slug, created_at FROM rooms ORDER BY created_at ASC')
        return [dict(id=row[0], name=row[1], slug=row[2], created_at=row[3]) for row in cur.fetchall()]

@socketio.on('get_rooms')
def handle_get_rooms():
    emit('room_list', fetch_rooms())

# --- Room Join Page ---
@app.route('/chat/room/<room_slug>')
@login_required
def chat_room(room_slug):
    # Validate room exists
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name FROM rooms WHERE slug=?', (room_slug,))
        room = cur.fetchone()
    if not room:
        flash('Room not found.', 'danger')
        return redirect(url_for('chat'))
    return render_template('chat.html', room={'id': room[0], 'name': room[1], 'slug': room_slug}, current_user_username=current_user.username)

# --- SocketIO Handlers ---
@socketio.on('connect')
@login_required
def handle_connect():
    print(f'Client connected: {current_user.username}')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_room')
@login_required
def handle_join_room(data):
    room_slug = data.get('room_slug')
    if not room_slug:
        return
    join_room(room_slug)
    print(f'{current_user.username} joined room {room_slug}')
    # Optionally, announce user joining to the room
    # socketio.emit('status', {'msg': f'{current_user.username} has entered the room.'}, room=room_slug)

@socketio.on('leave_room')
@login_required
def handle_leave_room(data):
    room_slug = data.get('room_slug')
    if not room_slug:
        return
    leave_room(room_slug)
    print(f'{current_user.username} left room {room_slug}')
    # Optionally, announce user leaving to the room
    # socketio.emit('status', {'msg': f'{current_user.username} has left the room.'}, room=room_slug)

@socketio.on('send_message')
@login_required
def handle_send_message(data):
    content = data.get('content', '').strip()
    room_slug = data.get('room_slug')

    if not content or not room_slug:
        return

    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM rooms WHERE slug=?', (room_slug,))
        room_row = cur.fetchone()
        if not room_row:
            return 
        room_id = room_row[0]

        cur.execute(
            'INSERT INTO messages (sender_id, room_id, content) VALUES (?, ?, ?)',
            (current_user.id, room_id, content)
        )
        message_id = cur.lastrowid
        conn.commit()

        # Fetch the full message to broadcast
        cur.execute('''
            SELECT m.content, m.timestamp, u.username, r.slug as room_slug
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            JOIN rooms r ON m.room_id = r.id
            WHERE m.id = ?
        ''', (message_id,))
        msg_row = cur.fetchone()
        msg = {
            'username': msg_row[2],
            'content': msg_row[0],
            'timestamp': msg_row[1],
            'room_slug': msg_row[3]
        }
    
    socketio.emit('new_message', msg, room=room_slug)

@socketio.on('get_chat_history')
@login_required
def handle_get_chat_history(data):
    room_slug = data.get('room_slug')
    if not room_slug:
        return
        
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM rooms WHERE slug=?', (room_slug,))
        room = cur.fetchone()
        if not room:
            emit('chat_history', [])
            return
        
        room_id = room[0]
        cur.execute('''
            SELECT m.content, m.timestamp, u.username, r.slug as room_slug
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            JOIN rooms r ON m.room_id = r.id
            WHERE m.room_id=? ORDER BY m.timestamp ASC
        ''', (room_id,))
        messages = [
            {'content': row[0], 'timestamp': row[1], 'username': row[2], 'room_slug': row[3]} 
            for row in cur.fetchall()
        ]
        
    emit('chat_history', messages)

# --- Helper for PM room name ---

def _pm_room_name(user1_id, user2_id):
    """Return deterministic Socket.IO room name for private chat between two user IDs."""
    uid1, uid2 = sorted([user1_id, user2_id])
    return f'pm_{uid1}_{uid2}'

# --- User Public Profile ---
@app.route('/user/<username>')
@login_required
def public_profile(username):
    target_user = get_user_by_username(username)
    if not target_user:
        abort(404)
    is_self = target_user.id == current_user.id
    return render_template('user_profile.html', target_user=target_user, is_self=is_self)

# --- Private Messaging (PM) ---
@app.route('/pm')
@login_required
def pm_index():
    """PM landing page with search box."""
    return render_template('pm.html', target_username=None)

@app.route('/pm/<username>')
@login_required
def pm_chat(username):
    if username == current_user.username:
        flash('Cannot send private messages to yourself.', 'warning')
        return redirect(url_for('pm_index'))
    target_user = get_user_by_username(username)
    if not target_user:
        flash('User not found.', 'danger')
        return redirect(url_for('pm_index'))
    return render_template('pm.html', target_username=target_user.username)

# --- API: Search Users ---
@app.route('/api/search_users')
@login_required
def api_search_users():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT username FROM users WHERE username LIKE ? AND username != ? LIMIT 20', (f'%{q}%', current_user.username))
        results = [row[0] for row in cur.fetchall()]
    return jsonify(results)

# --- SocketIO events for Private Messaging ---
@socketio.on('join_pm')
@login_required
def handle_join_pm(data):
    username = data.get('username')
    target_user = get_user_by_username(username)
    if not target_user:
        return
    room_name = _pm_room_name(current_user.id, target_user.id)
    join_room(room_name)
    print(f'{current_user.username} joined private room {room_name}')

@socketio.on('leave_pm')
@login_required
def handle_leave_pm(data):
    username = data.get('username')
    target_user = get_user_by_username(username)
    if not target_user:
        return
    room_name = _pm_room_name(current_user.id, target_user.id)
    leave_room(room_name)

@socketio.on('send_pm')
@login_required
def handle_send_pm(data):
    content = data.get('content', '').strip()
    receiver_username = data.get('receiver_username')
    if not content or not receiver_username:
        return
    receiver = get_user_by_username(receiver_username)
    if not receiver or receiver.id == current_user.id:
        return
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO private_messages (sender_id, receiver_id, content) VALUES (?, ?, ?)',
            (current_user.id, receiver.id, content)
        )
        msg_id = cur.lastrowid
        conn.commit()
        cur.execute('''SELECT content, timestamp FROM private_messages WHERE id=?''', (msg_id,))
        row = cur.fetchone()
        message = {
            'username': current_user.username,
            'content': row[0],
            'timestamp': row[1]
        }
    room_name = _pm_room_name(current_user.id, receiver.id)
    socketio.emit('new_pm', message, room=room_name)

@socketio.on('get_pm_history')
@login_required
def handle_get_pm_history(data):
    username = data.get('username')
    target_user = get_user_by_username(username)
    if not target_user:
        emit('pm_history', [])
        return
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT sender_id, content, timestamp FROM private_messages 
                       WHERE (sender_id=? AND receiver_id=?) OR (sender_id=? AND receiver_id=?)
                       ORDER BY timestamp ASC''',
                    (current_user.id, target_user.id, target_user.id, current_user.id))
        messages = []
        for sender_id, content, timestamp in cur.fetchall():
            sender_name = current_user.username if sender_id == current_user.id else target_user.username
            messages.append({'username': sender_name, 'content': content, 'timestamp': timestamp})
    emit('pm_history', messages)

# --- Main Entrypoint ---
if __name__ == '__main__':
    from db.init_db import init_db
    init_db()
    socketio.run(app, debug=True)