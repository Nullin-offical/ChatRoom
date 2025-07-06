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
import glob
from security import security_manager, check_message_security, sanitize_user_input, log_security_event

def slugify(value):
    value = str(value)
    value = value.strip().lower()
    value = re.sub(r'[^a-z0-9\u0600-\u06FF]+', '-', value)
    value = re.sub(r'-+', '-', value)
    return value.strip('-')

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

# --- Helper Functions ---
def format_join_date(date_str):
    """Format join date in a user-friendly way"""
    if not date_str:
        return 'Unknown'
    
    try:
        if isinstance(date_str, str):
            # Parse the date string
            date_obj = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        else:
            date_obj = date_str
        
        # Format as "Month Day, Year"
        return date_obj.strftime('%B %d, %Y')
    except:
        return str(date_str) if date_str else 'Unknown'

# --- Database Helper ---
def get_db():
    db_path = os.path.join(os.path.dirname(__file__), 'db', 'chatroom.db')
    return sqlite3.connect(db_path)

# --- Main Routes ---
@app.route('/')
def home():
    with get_db() as conn:
        cur = conn.cursor()
        # Get stats for home page
        cur.execute('SELECT COUNT(*) FROM users')
        user_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM messages')
        message_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM rooms')
        room_count = cur.fetchone()[0]
        
        # Get recent rooms
        cur.execute('SELECT name, slug, created_at FROM rooms ORDER BY created_at DESC LIMIT 6')
        recent_rooms = [dict(name=row[0], slug=row[1], created_at=row[2]) for row in cur.fetchall()]
        
        # Get recent users
        cur.execute('SELECT username, display_name, created_at FROM users ORDER BY created_at DESC LIMIT 6')
        recent_users = [dict(username=row[0], display_name=row[1] or row[0], created_at=row[2]) for row in cur.fetchall()]
    
    return render_template('home.html', 
                         user_count=user_count,
                         message_count=message_count,
                         room_count=room_count,
                         recent_rooms=recent_rooms,
                         recent_users=recent_users)

@app.route('/api/ping')
def ping():
    return jsonify({'status': 'ok'})

# --- Auth Routes ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip()
        password = request.form['password']
        confirm = request.form['confirm_password']
        
        # Validate username
        username_ok, username_msg = security_manager.validate_username(username)
        if not username_ok:
            error = username_msg
        elif password != confirm:
            error = 'Passwords do not match.'
        elif len(password) < 6:
            error = 'Password must be at least 6 characters.'
        else:
            # Sanitize inputs
            username = sanitize_user_input(username)
            email = sanitize_user_input(email)
            
            user, reg_error = register_user(username, email, password)
            if reg_error:
                error = reg_error
            else:
                login_user(user)
                log_security_event("USER_REGISTERED", user.id, f"Username: {username}")
                return redirect(url_for('dashboard'))
    return render_template('register.html', error=error)

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        # Check login attempts
        login_ok, login_msg = security_manager.check_login_attempts(username)
        if not login_ok:
            error = login_msg
        else:
            user = authenticate_user(username, password)
            if user:
                security_manager.record_login_attempt(username, success=True)
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                security_manager.record_login_attempt(username, success=False)
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
    with get_db() as conn:
        cur = conn.cursor()
        
        # Get all users
        cur.execute('SELECT id, username, email, is_admin, created_at FROM users')
        users = [dict(id=row[0], username=row[1], email=row[2], is_admin=row[3], created_at=row[4]) for row in cur.fetchall()]
        
        # Get all messages
        cur.execute('SELECT id, sender_id, content, timestamp FROM messages')
        messages = [dict(id=row[0], sender_id=row[1], content=row[2], timestamp=row[3]) for row in cur.fetchall()]
        
        # Get recent messages with user info
        cur.execute('''
            SELECT messages.id, users.username, messages.content, messages.timestamp, rooms.name as room_name 
            FROM messages 
            JOIN users ON messages.sender_id = users.id 
            LEFT JOIN rooms ON messages.room_id = rooms.id 
            ORDER BY messages.timestamp DESC 
            LIMIT 10
        ''')
        recent_messages = [dict(id=row[0], username=row[1], content=row[2], timestamp=row[3], room_name=row[4] or 'General') for row in cur.fetchall()]
        
        # Get user stats
        cur.execute('SELECT COUNT(*) FROM messages WHERE sender_id = ?', (current_user.id,))
        user_message_count = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(DISTINCT room_id) FROM messages WHERE sender_id = ?', (current_user.id,))
        user_rooms_joined = cur.fetchone()[0]
        
        cur.execute('SELECT COUNT(*) FROM private_messages WHERE sender_id = ? OR receiver_id = ?', (current_user.id, current_user.id))
        user_pm_count = cur.fetchone()[0]
    
    rooms = fetch_rooms()
    return render_template('dashboard.html', 
                         rooms=rooms, 
                         users=users, 
                         messages=messages, 
                         recent_messages=recent_messages,
                         user_message_count=user_message_count,
                         user_rooms_joined=user_rooms_joined,
                         user_pm_count=user_pm_count)

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
    rooms = fetch_all_rooms()
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

@app.route('/admin/delete_room', methods=['POST'])
@login_required
@admin_required
def admin_delete_room():
    room_id = request.form.get('room_id')
    if not room_id:
        flash('Invalid room.', 'danger')
        return redirect(url_for('admin_panel'))
    with get_db() as conn:
        cur = conn.cursor()
        # Delete all messages in the room first
        cur.execute('DELETE FROM messages WHERE room_id = ?', (room_id,))
        # Delete the room
        cur.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
        conn.commit()
    flash('Room deleted.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle_room_visibility', methods=['POST'])
@login_required
@admin_required
def admin_toggle_room_visibility():
    room_id = request.form.get('room_id')
    if not room_id:
        flash('Room ID required.', 'danger')
        return redirect(url_for('admin_panel'))
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT name, hidden FROM rooms WHERE id=?', (room_id,))
        room = cur.fetchone()
        if not room:
            flash('Room not found.', 'danger')
            return redirect(url_for('admin_panel'))
        
        # Toggle hidden status
        new_hidden = not room[1]
        cur.execute('UPDATE rooms SET hidden = ? WHERE id = ?', (new_hidden, room_id))
        conn.commit()
        
        status = 'hidden' if new_hidden else 'shown'
        flash(f'Room "{room[0]}" {status}.', 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/site_name', methods=['POST'])
@login_required
def admin_edit_site_name():
    if not getattr(current_user, 'is_admin', False):
        abort(403)
    new_name = request.form.get('site_name', '').strip()
    if not new_name or len(new_name) > 64:
        flash('Site name is required and must be at most 64 characters.', 'danger')
        return redirect(url_for('admin_panel'))
    set_setting('site_name', new_name)
    flash('Site name updated successfully.', 'success')
    return redirect(url_for('admin_panel'))

# --- Profile Management ---
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    error = None
    success = None
    # --- Avatar discovery ---
    avatar_dir = os.path.join(os.path.dirname(__file__), '../frontend/static/avatars')
    avatar_files = sorted([os.path.basename(f) for f in glob.glob(os.path.join(avatar_dir, 'avatar*.png'))])
    avatar_urls = [f'/static/avatars/{fname}' for fname in avatar_files]

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        display_name = request.form.get('display_name', '').strip()
        bio = request.form.get('bio', '').strip()
        birth_date = request.form.get('birth_date', '').strip()
        selected_avatar = request.form.get('profile_avatar', '').strip()
        if selected_avatar not in avatar_urls and selected_avatar != '':
            error = 'Invalid avatar selection.'
        # Only check password length if password is not empty
        if password and len(password) < 6:
            error = 'Password must be at least 6 characters.'
        if not error:
            with get_db() as conn:
                cur = conn.cursor()
                update_fields = ['username=?, email=?, display_name=?, bio=?, birth_date=?']
                update_values = [username, email, display_name, bio, birth_date]
                update_fields.append('profile_image=?')
                update_values.append(selected_avatar if selected_avatar else None)
                if password:
                    import bcrypt
                    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
                    update_fields.append('hashed_password=?')
                    update_values.append(hashed.decode('utf-8'))
                update_values.append(current_user.id)
                query = f'UPDATE users SET {", ".join(update_fields)} WHERE id=?'
                cur.execute(query, update_values)
                conn.commit()
                current_user.username = username
                current_user.email = email
            success = 'Profile updated successfully.'
    
    # Fetch latest user info
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT username, email, display_name, bio, birth_date, profile_image, created_at 
                      FROM users WHERE id=?''', (current_user.id,))
        user = cur.fetchone()
    
    user_data = {
        'username': user[0],
        'email': user[1],
        'display_name': user[2] or user[0],
        'bio': user[3] or '',
        'birth_date': user[4] or '',
        'profile_image': user[5],
        'created_at': format_join_date(user[6]) if user[6] else 'Unknown'
    }
    
    return render_template('profile.html', user=user_data, error=error, success=success, avatars=avatar_urls)

# --- Room Management ---
@app.route('/admin/create_room', methods=['POST'])
@login_required
@admin_required
def admin_create_room():
    room_name = request.form.get('room_name', '').strip()
    room_password = request.form.get('room_password', '').strip()
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
        cur.execute('INSERT INTO rooms (name, slug, password) VALUES (?, ?, ?)', (room_name, slug, room_password if room_password else None))
        conn.commit()
    flash('Room created.', 'success')
    # Notify all clients via SocketIO
    socketio.emit('room_list', fetch_rooms())
    return redirect(url_for('admin_panel') + '#rooms')

# --- Real-time Room List ---
def fetch_rooms():
    print('fetch_rooms() called')
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, slug, password, created_at, hidden FROM rooms WHERE hidden = 0 ORDER BY created_at ASC')
        rooms = [dict(id=row[0], name=row[1], slug=row[2], has_password=bool(row[3]), created_at=row[4], hidden=bool(row[5])) for row in cur.fetchall()]
        print(f'fetch_rooms() returning {len(rooms)} rooms: {rooms}')
        return rooms

def fetch_all_rooms():
    """Fetch all rooms including hidden ones for admin panel"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, slug, password, created_at, hidden FROM rooms ORDER BY created_at DESC')
        return [dict(id=row[0], name=row[1], slug=row[2], has_password=bool(row[3]), created_at=row[4], hidden=bool(row[5])) for row in cur.fetchall()]

@socketio.on('get_rooms')
def handle_get_rooms():
    print(f'get_rooms event received from {current_user.username}')
    rooms = fetch_rooms()
    print(f'Fetched rooms: {rooms}')
    emit('room_list', rooms)

# --- Room Join Page ---
@app.route('/chat/room/<room_slug>')
@login_required
def chat_room(room_slug):
    # Validate room exists
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, password FROM rooms WHERE slug=?', (room_slug,))
        room = cur.fetchone()
    if not room:
        flash('Room not found.', 'danger')
        return redirect(url_for('chat'))
    
    room_data = {
        'id': room[0], 
        'name': room[1], 
        'slug': room_slug, 
        'has_password': bool(room[2]),
        'password_verified': session.get(f'room_access_{room_slug}', False)
    }
    
    return render_template('chat.html', room=room_data, current_user_username=current_user.username)

@app.route('/chat/room/<room_slug>/join', methods=['POST'])
@login_required
def join_room_with_password(room_slug):
    password = request.form.get('password', '').strip()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, name, password FROM rooms WHERE slug=?', (room_slug,))
        room = cur.fetchone()
    if not room:
        return jsonify({'success': False, 'error': 'Room not found.'}), 404
    
    if room[2] and room[2] != password:
        return jsonify({'success': False, 'error': 'Incorrect password.'}), 401
    
    # Store successful password verification in session
    session[f'room_access_{room_slug}'] = True
    return jsonify({'success': True, 'redirect': url_for('chat_room', room_slug=room_slug)})

# --- SocketIO Handlers ---
@socketio.on('connect')
@login_required
def handle_connect(auth=None):
    print(f'Client connected: {current_user.username}')
    # Join user's personal room for notifications
    join_room(f'user_{current_user.id}')
    
    # Update user's online status
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (current_user.id,))
        conn.commit()
    
    # Broadcast online status to all users
    socketio.emit('user_status_change', {
        'user_id': current_user.id,
        'username': current_user.username,
        'status': 'online'
    })

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')
    # Update user's offline status if they were logged in
    if hasattr(current_user, 'id'):
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (current_user.id,))
            conn.commit()
        # Broadcast offline status to all users
        socketio.emit('user_status_change', {
            'user_id': current_user.id,
            'username': current_user.username,
            'status': 'offline'
        })

@socketio.on('join_room')
@login_required
def handle_join_room(data):
    room_slug = data.get('room')
    if not room_slug:
        return
    join_room(room_slug)
    print(f'{current_user.username} joined room {room_slug}')
    # Announce user joining to the room
    socketio.emit('user_joined', {'username': current_user.username}, room=room_slug)

@socketio.on('leave_room')
@login_required
def handle_leave_room(data):
    room_slug = data.get('room')
    if not room_slug:
        return
    leave_room(room_slug)
    print(f'{current_user.username} left room {room_slug}')
    # Announce user leaving to the room
    socketio.emit('user_left', {'username': current_user.username}, room=room_slug)

@socketio.on('send_message')
@login_required
def handle_send_message(data):
    print(f"send_message event received from {current_user.username}: {data}")
    content = data.get('content', '').strip()
    room_slug = data.get('room')
    
    if not content:
        print("No content provided")
        emit('error', {'message': 'Message content is required'})
        return
    
    if not room_slug:
        print("No room provided")
        emit('error', {'message': 'Room is required'})
        return
    
    # Security checks
    security_ok, security_msg = check_message_security(current_user.id, content)
    if not security_ok:
        print(f"Security check failed: {security_msg}")
        emit('error', {'message': security_msg})
        return
    
    # Sanitize content
    content = sanitize_user_input(content)
    
    # Simpler: Just get room id by slug
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id FROM rooms WHERE slug=? LIMIT 1', (room_slug,))
        room_data = cur.fetchone()
        
        if not room_data:
            print(f"Room not found: {room_slug}")
            emit('error', {'message': 'Room not found'})
            return 
        
        room_id = room_data[0]
        print(f"Found room ID: {room_id}")

        # Insert message and get ID in one operation
        cur.execute(
            'INSERT INTO messages (sender_id, room_id, content, timestamp) VALUES (?, ?, ?, ?)',
            (current_user.id, room_id, content, datetime.now().isoformat())
        )
        message_id = cur.lastrowid
        conn.commit()
        print(f"Message saved with ID: {message_id}")

        # Optimized: Single query to get all message data with user info
        cur.execute('''
            SELECT m.content, m.timestamp, u.username, u.display_name, u.profile_image, r.slug as room_slug
            FROM messages m
            INNER JOIN users u ON m.sender_id = u.id
            INNER JOIN rooms r ON m.room_id = r.id
            WHERE m.id = ?
        ''', (message_id,))
        msg_row = cur.fetchone()
        
        if not msg_row:
            print("Error: Could not retrieve saved message")
            emit('error', {'message': 'Failed to save message'})
            return
            
        msg = {
            'username': msg_row[2],
            'display_name': msg_row[3] or msg_row[2],
            'content': msg_row[0],
            'timestamp': msg_row[1],
            'profile_image': msg_row[4] or 'default.png',
            'room_slug': msg_row[5]
        }
        print(f"Broadcasting message: {msg}")
    
    socketio.emit('new_message', msg, room=room_slug)

@socketio.on('get_chat_history')
@login_required
def handle_get_chat_history(data):
    print(f"get_chat_history event received from {current_user.username}: {data}")
    room_slug = data.get('room')
    if not room_slug:
        print("No room provided")
        return
        
    with get_db() as conn:
        cur = conn.cursor()
        # Optimized: Use indexed lookup for room
        cur.execute('SELECT id FROM rooms WHERE slug=? LIMIT 1', (room_slug,))
        room = cur.fetchone()
        if not room:
            print(f"Room not found: {room_slug}")
            emit('chat_history', [])
            return
        
        room_id = room[0]
        print(f"Loading chat history for room ID: {room_id}")
        
        # Optimized query: Limit to last 100 messages, use proper indexing
        cur.execute('''
            SELECT m.content, m.timestamp, u.username, u.display_name, u.profile_image, r.slug as room_slug
            FROM messages m
            INNER JOIN users u ON m.sender_id = u.id
            INNER JOIN rooms r ON m.room_id = r.id
            WHERE m.room_id = ?
            ORDER BY m.timestamp DESC
            LIMIT 100
        ''', (room_id,))
        
        # Reverse the results to get chronological order
        rows = cur.fetchall()
        messages = [
            {'content': row[0], 'timestamp': row[1], 'username': row[2], 'display_name': row[3], 'profile_image': row[4], 'room_slug': row[5]} 
            for row in reversed(rows)
        ]
        print(f"Found {len(messages)} messages for room {room_slug}")
        
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
    target_user_obj = get_user_by_username(username)
    if not target_user_obj:
        abort(404)
    
    # Check if user is online (active in last 5 minutes)
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT last_seen FROM users WHERE id = ?''', (target_user_obj.id,))
        last_seen = cur.fetchone()[0]
        import datetime
        if last_seen:
            try:
                last_seen_dt = datetime.datetime.fromisoformat(last_seen.replace('Z', '+00:00'))
                now = datetime.datetime.now(datetime.timezone.utc)
                time_diff = now - last_seen_dt
                is_online = time_diff.total_seconds() < 300  # 5 minutes
            except:
                is_online = False
        else:
            is_online = False
    # Prepare user dict for template
    target_user = {
        'id': target_user_obj.id,
        'username': target_user_obj.username,
        'display_name': target_user_obj.display_name,
        'bio': target_user_obj.bio,
        'birth_date': target_user_obj.birth_date,
        'profile_image': target_user_obj.profile_image,
        'created_at': format_join_date(target_user_obj.created_at),
        'is_online': is_online
    }
    is_self = target_user_obj.id == current_user.id
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
    
    return render_template('pm.html', target_username=target_user.username, current_user_id=current_user.id)

# --- API: Search Users ---
@app.route('/api/search_users')
@login_required
def api_search_users():
    q = request.args.get('q', '').strip()
    if not q:
        return jsonify([])
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT id, username, display_name FROM users WHERE username LIKE ? AND username != ? LIMIT 20', (f'%{q}%', current_user.username))
        results = []
        for row in cur.fetchall():
            results.append({
                'id': row[0],
                'username': row[1],
                'display_name': row[2] or row[1]
            })
        return jsonify(results)

@app.route('/api/pm_chats')
@login_required
def api_pm_chats():
    """Get list of users with whom current user has exchanged PMs - Optimized version"""
    with get_db() as conn:
        cur = conn.cursor()
        
        # Optimized query: Use CTE for better performance and readability
        cur.execute('''
            WITH user_messages AS (
                SELECT 
                    CASE 
                        WHEN sender_id = ? THEN receiver_id 
                        ELSE sender_id 
                    END as other_user_id,
                    MAX(timestamp) as last_message_time,
                    COUNT(*) as message_count
                FROM private_messages 
                WHERE sender_id = ? OR receiver_id = ?
                GROUP BY other_user_id
            ),
            latest_messages AS (
                SELECT 
                    pm.sender_id,
                    pm.receiver_id,
                    pm.content,
                    pm.timestamp,
                    ROW_NUMBER() OVER (
                        PARTITION BY 
                            CASE 
                                WHEN pm.sender_id = ? THEN pm.receiver_id 
                                ELSE pm.sender_id 
                            END
                        ORDER BY pm.timestamp DESC
                    ) as rn
                FROM private_messages pm
                WHERE pm.sender_id = ? OR pm.receiver_id = ?
            )
            SELECT 
                u.username, 
                u.id,
                um.message_count,
                um.last_message_time,
                lm.content as last_message
            FROM user_messages um
            INNER JOIN users u ON u.id = um.other_user_id
            LEFT JOIN latest_messages lm ON (
                (lm.sender_id = ? AND lm.receiver_id = um.other_user_id) OR
                (lm.sender_id = um.other_user_id AND lm.receiver_id = ?)
            ) AND lm.rn = 1
            WHERE u.id NOT IN (
                SELECT blocked_id FROM user_blocks WHERE blocker_id = ?
            )
            AND u.id NOT IN (
                SELECT blocker_id FROM user_blocks WHERE blocked_id = ?
            )
            ORDER BY um.last_message_time DESC
        ''', (current_user.id, current_user.id, current_user.id, 
              current_user.id, current_user.id, current_user.id,
              current_user.id, current_user.id, current_user.id, current_user.id))
        
        chats = []
        for row in cur.fetchall():
            chats.append({
                'username': row[0],
                'user_id': row[1],
                'message_count': row[2],
                'last_message_time': row[3] or '2024-01-01 00:00:00',
                'last_message': row[4] or 'No messages yet'
            })
        return jsonify(chats)

@app.route('/api/delete_chat/<int:other_user_id>', methods=['POST'])
@login_required
def api_delete_chat(other_user_id):
    """Delete a chat conversation for the current user (one-sided deletion)"""
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check if the other user exists
            cur.execute('SELECT id FROM users WHERE id = ?', (other_user_id,))
            if not cur.fetchone():
                return jsonify({'error': 'User not found'}), 404
            
            # Check if there's already a deletion record
            cur.execute('SELECT id FROM deleted_chats WHERE user_id = ? AND other_user_id = ?', 
                       (current_user.id, other_user_id))
            
            if cur.fetchone():
                return jsonify({'error': 'Chat already deleted'}), 400
            
            # Add deletion record
            cur.execute('INSERT INTO deleted_chats (user_id, other_user_id) VALUES (?, ?)', 
                       (current_user.id, other_user_id))
            conn.commit()
            
            return jsonify({'success': True, 'message': 'Chat deleted successfully'})
            
    except Exception as e:
        return jsonify({'error': f'Failed to delete chat: {str(e)}'}), 500

@app.route('/api/block_user/<int:user_id>', methods=['POST'])
@login_required
def api_block_user(user_id):
    """Block a user"""
    try:
        if user_id == current_user.id:
            return jsonify({'error': 'Cannot block yourself'}), 400
            
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check if the user exists
            cur.execute('SELECT id FROM users WHERE id = ?', (user_id,))
            if not cur.fetchone():
                return jsonify({'error': 'User not found'}), 404
            
            # Check if already blocked
            cur.execute('SELECT id FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?', 
                       (current_user.id, user_id))
            
            if cur.fetchone():
                return jsonify({'error': 'User already blocked'}), 400
            
            # Add block record
            cur.execute('INSERT INTO user_blocks (blocker_id, blocked_id) VALUES (?, ?)', 
                       (current_user.id, user_id))
            conn.commit()
            
            return jsonify({'success': True, 'message': 'User blocked successfully'})
            
    except Exception as e:
        return jsonify({'error': f'Failed to block user: {str(e)}'}), 500

@app.route('/api/unblock_user/<int:user_id>', methods=['POST'])
@login_required
def api_unblock_user(user_id):
    """Unblock a user"""
    print(f"Unblock request: {current_user.username} trying to unblock user ID {user_id}")
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Check if the user is blocked
            cur.execute('SELECT id FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?', 
                       (current_user.id, user_id))
            
            block_record = cur.fetchone()
            if not block_record:
                print(f"User {user_id} is not blocked by {current_user.username}")
                return jsonify({'error': 'User not blocked'}), 400
            
            print(f"Found block record: {block_record[0]}")
            
            # Remove block record
            cur.execute('DELETE FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?', 
                       (current_user.id, user_id))
            deleted_rows = cur.rowcount
            conn.commit()
            
            print(f"Deleted {deleted_rows} block record(s)")
            
            # Verify the block was removed
            cur.execute('SELECT id FROM user_blocks WHERE blocker_id = ? AND blocked_id = ?', 
                       (current_user.id, user_id))
            remaining_block = cur.fetchone()
            if remaining_block:
                print(f"ERROR: Block record still exists after deletion!")
                return jsonify({'error': 'Failed to remove block record'}), 500
            
            print(f"Successfully unblocked user {user_id}")
            return jsonify({'success': True, 'message': 'User unblocked successfully'})
            
    except Exception as e:
        print(f"Error in unblock_user: {e}")
        return jsonify({'error': f'Failed to unblock user: {str(e)}'}), 500

@app.route('/api/blocked_users')
@login_required
def api_blocked_users():
    """Get list of users blocked by current user"""
    with get_db() as conn:
        cur = conn.cursor()
        
        cur.execute('''
            SELECT u.id, u.username, u.display_name, ub.blocked_at
            FROM user_blocks ub
            JOIN users u ON ub.blocked_id = u.id
            WHERE ub.blocker_id = ?
            ORDER BY ub.blocked_at DESC
        ''', (current_user.id,))
        
        blocked_users = []
        for row in cur.fetchall():
            user_id, username, display_name, blocked_at = row
            blocked_users.append({
                'id': user_id,
                'username': username,
                'display_name': display_name or username,
                'blocked_at': blocked_at
            })
    
    return jsonify(blocked_users)



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
    
    # Also join the target user's personal room for notifications
    join_room(f'user_{target_user.id}')

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
    print(f"Received PM data: {data}")
    
    content = data.get('content', '').strip()
    recipient = data.get('recipient')
    
    print(f"Content: '{content}', Recipient: '{recipient}'")
    
    if not content:
        print("Error: No content provided")
        emit('error', {'message': 'Message content is required'})
        return
    
    if not recipient:
        print("Error: No recipient provided")
        emit('error', {'message': 'Recipient is required'})
        return
    
    # Security checks
    security_ok, security_msg = check_message_security(current_user.id, content)
    if not security_ok:
        print(f"Security check failed: {security_msg}")
        emit('error', {'message': security_msg})
        return
    
    # Sanitize content
    content = sanitize_user_input(content)
    
    # Validate recipient exists and is not the current user
    target_user = get_user_by_username(recipient)
    if not target_user:
        print(f"Error: User '{recipient}' not found")
        emit('error', {'message': f'User "{recipient}" not found'})
        return
    
    if target_user.id == current_user.id:
        print("Error: Cannot send message to yourself")
        emit('error', {'message': 'Cannot send message to yourself'})
        return
    
    # Check if either user has blocked the other
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT 1 FROM user_blocks 
            WHERE (blocker_id = ? AND blocked_id = ?) 
               OR (blocker_id = ? AND blocked_id = ?)
        ''', (current_user.id, target_user.id, target_user.id, current_user.id))
        
        if cur.fetchone():
            print("Error: Cannot send message - user is blocked")
            emit('error', {'message': 'Cannot send message to this user'})
            return
    
    print(f"Sending PM from {current_user.username} to {target_user.username}")
    
    try:
        with get_db() as conn:
            cur = conn.cursor()
            
            # Insert the message
            cur.execute(
                'INSERT INTO private_messages (sender_id, receiver_id, content, timestamp) VALUES (?, ?, ?, ?)',
                (current_user.id, target_user.id, content, datetime.now().isoformat())
            )
            msg_id = cur.lastrowid
            conn.commit()
            
            print(f"Message saved with ID: {msg_id}")
            
            # Verify the message was saved correctly
            cur.execute('SELECT sender_id, receiver_id, content, timestamp FROM private_messages WHERE id = ?', (msg_id,))
            saved_msg = cur.fetchone()
            if saved_msg:
                print(f"Saved message: sender_id={saved_msg[0]}, receiver_id={saved_msg[1]}, content='{saved_msg[2]}'")
            else:
                print("Error: Message not found after saving")
                emit('error', {'message': 'Failed to save message'})
                return
            
            # Get the inserted message with user details
            cur.execute('''SELECT pm.content, pm.timestamp, u.profile_image, u.display_name
                           FROM private_messages pm 
                           JOIN users u ON pm.sender_id = u.id 
                           WHERE pm.id=?''', (msg_id,))
            row = cur.fetchone()
            
            if not row:
                print("Error: Could not retrieve saved message")
                emit('error', {'message': 'Failed to save message'})
                return
            
            message = {
                'username': current_user.username,
                'display_name': row[3] or current_user.username,
                'content': row[0],
                'timestamp': row[1],
                'profile_image': row[2] or 'default.png',
                'sender': current_user.username,
                'recipient': recipient
            }
            
            print(f"Prepared message: {message}")
        
        # Send to PM room
        room_name = _pm_room_name(current_user.id, target_user.id)
        print(f"Emitting to room: {room_name}")
        socketio.emit('new_pm', message, room=room_name)
        
        # Send notification to receiver
        notification = {
            'type': 'pm',
            'from': current_user.username,
            'message': content[:50] + '...' if len(content) > 50 else content,
            'timestamp': row[1]
        }
        socketio.emit('notification', notification, room=f'user_{target_user.id}')
        
        print("PM sent successfully")
        
    except Exception as e:
        print(f"Error sending PM: {e}")
        import traceback
        traceback.print_exc()
        emit('error', {'message': 'Failed to send message'})

@socketio.on('get_pm_history')
@login_required
def handle_get_pm_history(data):
    target_user = data.get('target_user')  # Changed from target_username to target_user
    target_user_obj = get_user_by_username(target_user)
    if not target_user_obj:
        emit('pm_history', [])
        return
    
    # Join PM room
    room_name = _pm_room_name(current_user.id, target_user_obj.id)
    join_room(room_name)
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''SELECT pm.sender_id, pm.content, pm.timestamp, u.profile_image 
                       FROM private_messages pm
                       JOIN users u ON pm.sender_id = u.id
                       WHERE (pm.sender_id=? AND pm.receiver_id=?) OR (pm.sender_id=? AND pm.receiver_id=?)
                       ORDER BY pm.timestamp ASC''',
                    (current_user.id, target_user_obj.id, target_user_obj.id, current_user.id))
        messages = []
        for sender_id, content, timestamp, profile_image in cur.fetchall():
            sender_name = current_user.username if sender_id == current_user.id else target_user_obj.username
            messages.append({'username': sender_name, 'content': content, 'timestamp': timestamp, 'profile_image': profile_image})
    emit('pm_history', messages)

@socketio.on('ping')
@login_required
def handle_ping():
    """Handle ping from client to update online status"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (current_user.id,))
        conn.commit()

@socketio.on('user_active')
@login_required
def handle_user_active(data):
    """Handle user becoming active"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (current_user.id,))
        conn.commit()
    
    # Broadcast online status
    socketio.emit('user_status_change', {
        'user_id': current_user.id,
        'username': current_user.username,
        'status': 'online'
    })

@socketio.on('user_inactive')
@login_required
def handle_user_inactive(data):
    """Handle user becoming inactive"""
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('UPDATE users SET last_seen = CURRENT_TIMESTAMP WHERE id = ?', (current_user.id,))
        conn.commit()

@socketio.on('typing')
@login_required
def handle_typing(data):
    """Handle typing indicator for chat rooms"""
    room_slug = data.get('room')
    if not room_slug:
        return
    socketio.emit('typing', {
        'username': current_user.username
    }, room=room_slug)

@socketio.on('stop_typing')
@login_required
def handle_stop_typing(data):
    """Handle stop typing indicator for chat rooms"""
    room_slug = data.get('room')
    if not room_slug:
        return
    socketio.emit('stop_typing', {
        'username': current_user.username
    }, room=room_slug)

@socketio.on('pm_typing')
@login_required
def handle_pm_typing(data):
    """Handle PM typing indicator"""
    recipient = data.get('recipient')
    if not recipient:
        return
    target_user = get_user_by_username(recipient)
    if not target_user:
        return
    room_name = _pm_room_name(current_user.id, target_user.id)
    socketio.emit('pm_typing', {
        'sender': current_user.username
    }, room=room_name)

@socketio.on('pm_stop_typing')
@login_required
def handle_pm_stop_typing(data):
    """Handle PM stop typing indicator"""
    recipient = data.get('recipient')
    if not recipient:
        return
    target_user = get_user_by_username(recipient)
    if not target_user:
        return
    room_name = _pm_room_name(current_user.id, target_user.id)
    socketio.emit('pm_stop_typing', {
        'sender': current_user.username
    }, room=room_name)

@socketio.on('search_users')
@login_required
def handle_search_users(data):
    """Handle user search for PM (excluding blocked users)"""
    query = data.get('query', '').strip()
    if not query or len(query) < 2:
        emit('search_results', [])
        return
    
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('''
            SELECT u.username, u.display_name 
            FROM users u
            WHERE u.username LIKE ? 
            AND u.username != ? 
            AND NOT EXISTS (
                SELECT 1 FROM user_blocks 
                WHERE (blocker_id = ? AND blocked_id = u.id) 
                   OR (blocker_id = u.id AND blocked_id = ?)
            )
            ORDER BY u.username 
            LIMIT 10
        ''', (f'%{query}%', current_user.username, current_user.id, current_user.id))
        users = []
        for row in cur.fetchall():
            users.append({
                'username': row[0],
                'display_name': row[1] or row[0]
            })
        emit('search_results', users)

@socketio.on('get_pm_chats')
@login_required
def handle_get_pm_chats():
    """Get list of PM chats for current user (excluding deleted chats and blocked users)"""
    print(f"Getting PM chats for user: {current_user.username} (ID: {current_user.id})")
    
    with get_db() as conn:
        cur = conn.cursor()
        
        # Get users with whom current user has exchanged messages (excluding deleted chats and blocked users)
        cur.execute('''
            SELECT DISTINCT u.username, u.id,
                   (SELECT COUNT(*) FROM private_messages 
                    WHERE (sender_id = ? AND receiver_id = u.id) 
                       OR (sender_id = u.id AND receiver_id = ?)) as message_count,
                   (SELECT MAX(timestamp) FROM private_messages 
                    WHERE (sender_id = ? AND receiver_id = u.id) 
                       OR (sender_id = u.id AND receiver_id = ?)) as last_message_time,
                   (SELECT content FROM private_messages 
                    WHERE (sender_id = ? AND receiver_id = u.id) 
                       OR (sender_id = u.id AND receiver_id = ?)
                    ORDER BY timestamp DESC LIMIT 1) as last_message
            FROM users u
            WHERE u.id IN (
                SELECT DISTINCT 
                    CASE 
                        WHEN sender_id = ? THEN receiver_id 
                        ELSE sender_id 
                    END
                FROM private_messages 
                WHERE sender_id = ? OR receiver_id = ?
            )
            AND NOT EXISTS (
                SELECT 1 FROM deleted_chats 
                WHERE user_id = ? AND other_user_id = u.id
            )
            AND NOT EXISTS (
                SELECT 1 FROM user_blocks 
                WHERE (blocker_id = ? AND blocked_id = u.id) 
                   OR (blocker_id = u.id AND blocked_id = ?)
            )
            ORDER BY last_message_time DESC
        ''', (current_user.id, current_user.id, current_user.id, current_user.id, 
              current_user.id, current_user.id, current_user.id, current_user.id, current_user.id,
              current_user.id, current_user.id, current_user.id))
        
        chats = []
        for row in cur.fetchall():
            chat_data = {
                'username': row[0],
                'user_id': row[1],
                'message_count': row[2],
                'last_message_time': row[3] or '2024-01-01 00:00:00',
                'last_message': row[4] or 'No messages yet'
            }
            chats.append(chat_data)
            print(f"Chat with {row[0]}: {row[2]} messages, last: {row[3]}")
        
        print(f"Returning {len(chats)} chats")
        emit('pm_chats', chats)

# --- Settings Utility ---
def get_setting(key, default=None):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cur.fetchone()
        return row[0] if row else default

def set_setting(key, value):
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()

# --- Context Processor ---
@app.context_processor
def inject_site_name():
    site_name = get_setting('site_name', 'ChatRoom')
    return dict(site_name=site_name)

@app.route('/api/rooms')
@login_required
def api_get_rooms():
    """API endpoint to get rooms (fallback for socket issues)"""
    rooms = fetch_rooms()
    return jsonify(rooms)

# --- Main Entrypoint ---
if __name__ == '__main__':
    from db.init_db import init_db
    init_db()
    socketio.run(app, debug=True)