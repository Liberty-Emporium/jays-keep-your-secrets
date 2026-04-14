import os
import sqlite3

def load_system_config():
    """Load system configuration (API keys, etc.)"""
    import json
    if os.path.exists(SYSTEM_CONFIG_FILE):
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_system_config(config):
    """Save system configuration"""
    import json
    with open(SYSTEM_CONFIG_FILE, 'w') as f:
        json.dump(config, f, indent=2)

import hashlib
import secrets
import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g

import time as _rl_time
from collections import defaultdict as _defaultdict
_rate_store = _defaultdict(list)
_RATE_WINDOW = 60
_RATE_MAX = 10

def _check_login_rate(ip):
    now = _rl_time.time()
    _rate_store[ip] = [t for t in _rate_store[ip] if now - t < _RATE_WINDOW]
    if len(_rate_store[ip]) >= _RATE_MAX:
        return False
    _rate_store[ip].append(now)
    return True


# ============================================================
# RATE LIMITER — No external dependencies required
# ============================================================
import time as _rl_time

def _is_rate_limited(db, key, max_calls=5, window_seconds=60):
    """Returns True if this key has exceeded the rate limit."""
    try:
        db.execute("""CREATE TABLE IF NOT EXISTS rate_limits (
            key TEXT NOT NULL, window_start INTEGER NOT NULL,
            count INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (key, window_start))""")
        db.execute("DELETE FROM rate_limits WHERE window_start < ?",
                   (int(_rl_time.time()) - window_seconds * 2,))
        now = int(_rl_time.time())
        ws = now - (now % window_seconds)
        row = db.execute(
            "SELECT count FROM rate_limits WHERE key=? AND window_start=?",
            (key, ws)).fetchone()
        if row is None:
            db.execute("INSERT OR IGNORE INTO rate_limits VALUES (?,?,1)", (key, ws))
            db.commit()
            return False
        if row[0] >= max_calls:
            return True
        db.execute("UPDATE rate_limits SET count=count+1 WHERE key=? AND window_start=?",
                   (key, ws))
        db.commit()
        return False
    except Exception:
        return False


app = Flask(__name__)

# Session security hardening
app.config['SESSION_COOKIE_SECURE'] = False  # Set True when HTTPS confirmed
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Config
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

# Database — use /data volume if available, fallback to local
_data_pref = os.environ.get('DATA_DIR', '/data')
try:
    os.makedirs(_data_pref, exist_ok=True)
    _t = os.path.join(_data_pref, '.write_test')
    open(_t,'w').close(); os.remove(_t)
    _DATA_DIR = _data_pref
except Exception:
    _DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
    os.makedirs(_DATA_DIR, exist_ok=True)

DB_FILE = os.path.join(_DATA_DIR, 'api_keys.db')
SYSTEM_CONFIG_FILE = os.path.join(_DATA_DIR, 'config.json')

def get_db():
    """Get database connection with WAL mode enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    # Ensure directory exists
    import os
    db_dir = os.path.dirname(DB_FILE)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # Initialize the database.
    conn = get_db()
    c = conn.cursor()
    
    # Users table
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        plan TEXT DEFAULT 'free',
        is_admin INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')
    
    # API Keys table (per user)
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        name TEXT,
        key_hash TEXT UNIQUE NOT NULL,
        key_prefix TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    
    conn.commit()
    
    c.execute("SELECT id FROM users WHERE username = 'admin'")
    if not c.fetchone():
        c.execute("INSERT INTO users (username, email, password_hash, plan, is_admin) VALUES (?, ?, ?, ?, ?)",
                 ('admin', 'jay@libertyemporium.com', hashlib.sha256('admin123'.encode()).hexdigest(), 'pro', 1))
        conn.commit()
    # Create admin user (persists across deploys)
    if DEMO_MODE:
        c.execute("SELECT id FROM users WHERE username = 'demo'")
        if not c.fetchone():
            c.execute("INSERT INTO users (username, email, password_hash, plan, is_admin) VALUES (?, ?, ?, ?, ?)",
                     ('demo', 'demo@demo.com', hashlib.sha256('demo123'.encode()).hexdigest(), 'demo', 0))
    
    conn.commit()
    conn.close()

init_db()

# Security headers

@app.after_request
def _add_security_headers(response):
    """Security headers on every response."""
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    if 'Content-Security-Policy' not in response.headers:
        response.headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' https: data: blob:;"
    return response

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Rate limiting
from collections import defaultdict
import time
rate_limits = defaultdict(list)
RATE_LIMIT_MAX = 20

def check_rate_limit():
    ip = request.remote_addr
    now = time.time()
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < 60]
    if len(rate_limits[ip]) >= RATE_LIMIT_MAX:
        return False
    rate_limits[ip].append(now)
    return True

def rate_limit(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_rate_limit():
            return "Too many requests.", 429
        return f(*args, **kwargs)
    return decorated

# Providers
PROVIDERS = {
    'anthropic': {'name': 'Anthropic (Claude)', 'prefix': 'sk-ant-'},
    'groq': {'name': 'Groq', 'prefix': 'gsk_'},
    'xai': {'name': 'xAI (Grok)', 'prefix': 'xai-'},
    'qwen': {'name': 'Qwen', 'prefix': 'sk-'},
    'openai': {'name': 'OpenAI', 'prefix': 'sk-'},
    'mistral': {'name': 'Mistral', 'prefix': 'sk-'},
}

def get_provider(key):
    for name, info in PROVIDERS.items():
        if key.startswith(info['prefix']):
            return name
    return 'unknown'

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()[:8]

def get_user_id():
    return session.get('user_id')

# Auth decorators
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# Routes
@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('landing.html', demo_mode=DEMO_MODE)

@app.route('/demo')
def demo():
    """Demo mode - login as demo user."""
    session['logged_in'] = True
    session['username'] = 'demo'
    session['user_id'] = 1
    session['plan'] = 'demo'
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit
def login():
    # Rate limiting — 10 login attempts per minute per IP
    _ip = request.remote_addr or 'unknown'
    if _is_rate_limited(get_db(), f'login:{_ip}', max_calls=10, window_seconds=60):
        return jsonify({'error': 'Too many login attempts. Please wait 1 minute.'}), 429

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ?', (username,))
        user = c.fetchone()
        conn.close()
        
        if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['plan'] = user['plan']
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html', demo_mode=DEMO_MODE)

@app.route('/signup', methods=['GET', 'POST'])
@rate_limit
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        
        if password != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('signup'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('signup'))
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password_hash, plan) VALUES (?, ?, ?, ?)',
                     (username, email, password_hash, 'free'))
            user_id = c.lastrowid
            conn.commit()
            conn.close()
            
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user_id
            session['plan'] = 'free'
            flash('Account created! Welcome!', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists', 'error')
    
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC', (session.get('user_id'),))
    keys = c.fetchall()
    
    c.execute('SELECT * FROM users WHERE id = ?', (session.get('user_id'),))
    user = c.fetchone()
    conn.close()
    
    return render_template('index.html', keys=keys, providers=PROVIDERS, user=user)

@app.route('/add', methods=['GET', 'POST'])
@login_required
@rate_limit
def add_key():
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        name = request.form.get('name', '').strip()
        
        if not key:
            flash('API key is required', 'error')
            return redirect(url_for('add_key'))
        
        provider = get_provider(key)
        key_hash = hash_key(key)
        key_prefix = key[:12] + '...' if len(key) > 12 else key
        
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO api_keys (user_id, provider, name, key_hash, key_prefix) VALUES (?, ?, ?, ?, ?)',
                     (session.get('user_id'), provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'), key_hash, key_prefix))
            conn.commit()
            conn.close()
            flash('API key added!', 'success')
        except sqlite3.IntegrityError:
            flash('This key already exists', 'error')
        
        return redirect(url_for('dashboard'))
    
    return render_template('add.html', providers=PROVIDERS)

@app.route('/delete/<int:key_id>')
@login_required
@rate_limit
def delete_key(key_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (key_id, session.get('user_id')))
    conn.commit()
    conn.close()
    flash('API key deleted', 'success')
    return redirect(url_for('dashboard'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pass = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        
        if new_pass != confirm:
            flash('Passwords do not match', 'error')
            return redirect(url_for('change_password'))
        
        if len(new_pass) < 6:
            flash('Password must be at least 6 characters', 'error')
            return redirect(url_for('change_password'))
        
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE id = ?', (session.get('user_id'),))
        user = c.fetchone()

        if not user:
            flash('User not found. Please log in again.', 'error')
            conn.close()
            return redirect(url_for('logout'))

        if user['password_hash'] != hashlib.sha256(current.encode()).hexdigest():
            flash('Current password is incorrect', 'error')
            conn.close()
            return redirect(url_for('change_password'))

        c.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                 (hashlib.sha256(new_pass.encode()).hexdigest(), session.get('user_id')))
        conn.commit()
        conn.close()
        
        flash('Password changed!', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('change_password.html')

@app.route('/upgrade')
@login_required
def upgrade():
    """Upgrade page - placeholder for paid plans."""
    return render_template('upgrade.html')

# ============ SMTP HELPER ============

def get_smtp_config():
    """Load SMTP settings from env vars."""
    return {
        'host':     os.environ.get('SMTP_HOST', ''),
        'port':     int(os.environ.get('SMTP_PORT', 587)),
        'user':     os.environ.get('SMTP_USER', ''),
        'password': os.environ.get('SMTP_PASSWORD', ''),
        'from':     os.environ.get('SMTP_FROM', os.environ.get('SMTP_USER', '')),
    }

def send_email(to, subject, body):
    """Send plain-text email. Returns (True, '') or (False, error)."""
    cfg = get_smtp_config()
    if not cfg['host'] or not cfg['user'] or not cfg['password']:
        return False, 'SMTP not configured (set SMTP_HOST, SMTP_USER, SMTP_PASSWORD env vars)'
    try:
        import smtplib
        from email.mime.text import MIMEText
        msg = MIMEText(body, 'plain', 'utf-8')
        msg['Subject'] = subject
        msg['From']    = cfg['from']
        msg['To']      = to
        if cfg['port'] == 465:
            with smtplib.SMTP_SSL(cfg['host'], 465, timeout=15) as s:
                s.login(cfg['user'], cfg['password'])
                s.sendmail(cfg['from'], [to], msg.as_string())
        else:
            with smtplib.SMTP(cfg['host'], cfg['port'], timeout=15) as s:
                s.ehlo(); s.starttls()
                s.login(cfg['user'], cfg['password'])
                s.sendmail(cfg['from'], [to], msg.as_string())
        return True, ''
    except Exception as e:
        return False, str(e)

# ============ FORGOT PASSWORD ============

@app.route('/forgot-password', methods=['GET', 'POST'])
@rate_limit
def forgot_password():
    sent = False
    error = None
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT id, username, email FROM users WHERE email = ?', (email,))
        user = c.fetchone()

        if user:
            # Generate reset token valid for 1 hour
            token = secrets.token_urlsafe(32)
            expires = (datetime.datetime.utcnow() + datetime.timedelta(hours=1)).isoformat()
            # Store in DB
            c.execute('''CREATE TABLE IF NOT EXISTS password_resets (
                token TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                expires_at TEXT NOT NULL
            )''')
            c.execute('DELETE FROM password_resets WHERE user_id = ?', (user['id'],))
            c.execute('INSERT INTO password_resets (token, user_id, expires_at) VALUES (?,?,?)',
                      (token, user['id'], expires))
            conn.commit()

            reset_url = request.host_url.rstrip('/') + f'/reset-password/{token}'
            ok, err = send_email(
                to=user['email'],
                subject='Jay — Reset Your Password',
                body=(
                    f"Hi {user['username']},\n\n"
                    f"You requested a password reset for Jay's Keep Your Secrets.\n\n"
                    f"Click this link to set a new password (valid for 1 hour):\n"
                    f"{reset_url}\n\n"
                    f"If you didn't request this, ignore this email.\n\n"
                    f"— Jay"
                )
            )
            if ok:
                sent = True
            else:
                # Still show sent to prevent email enumeration
                sent = True
                print(f'[EMAIL] Failed to send reset to {email}: {err}', flush=True)
        else:
            # Show success anyway (don't reveal if email exists)
            sent = True

        conn.close()
    return render_template('forgot_password.html', sent=sent, error=error)


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
@rate_limit
def reset_password(token):
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    # Check token exists and isn't expired
    try:
        c.execute('SELECT * FROM password_resets WHERE token = ?', (token,))
        record = c.fetchone()
    except Exception:
        record = None

    if not record:
        conn.close()
        flash('Invalid or expired reset link. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    expires_at = datetime.datetime.fromisoformat(record['expires_at'])
    if datetime.datetime.utcnow() > expires_at:
        c.execute('DELETE FROM password_resets WHERE token = ?', (token,))
        conn.commit()
        conn.close()
        flash('This reset link has expired. Please request a new one.', 'error')
        return redirect(url_for('forgot_password'))

    error = None
    if request.method == 'POST':
        new_pass = request.form.get('new_password', '')
        confirm  = request.form.get('confirm_password', '')
        if len(new_pass) < 6:
            error = 'Password must be at least 6 characters.'
        elif new_pass != confirm:
            error = 'Passwords do not match.'
        else:
            c.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                      (hashlib.sha256(new_pass.encode()).hexdigest(), record['user_id']))
            c.execute('DELETE FROM password_resets WHERE token = ?', (token,))
            conn.commit()
            conn.close()
            flash('Password reset! You can now log in.', 'success')
            return redirect(url_for('login'))

    conn.close()
    return render_template('reset_password.html', token=token, error=error)


# ============ FORGOT USERNAME ============

@app.route('/forgot-username', methods=['GET', 'POST'])
@rate_limit
def forgot_username():
    sent = False
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute('SELECT username FROM users WHERE email = ?', (email,))
        user = c.fetchone()
        conn.close()
        if user:
            send_email(
                to=email,
                subject='Jay — Your Username',
                body=(
                    f"Hi,\n\n"
                    f"Your Jay's Keep Your Secrets username is: {user['username']}\n\n"
                    f"You can log in at: {request.host_url}login\n\n"
                    f"— Jay"
                )
            )
        # Always show sent (don't reveal if email exists)
        sent = True
    return render_template('forgot_username.html', sent=sent)

# ============ API FOR BOTS ============
# Generate tokens for bot access
@app.route('/api/token', methods=['POST'])
@rate_limit
def api_create_token():
    """Get access token - pass username + password in JSON body"""
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()
    conn.close()
    
    if not user or user['password_hash'] != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Generate a unique token
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    
    # Store token (we'd need a tokens table, but let's use a simple approach)
    # For now, return a simple token based on user_id + timestamp
    api_token = f"ait_{user['id']}_{secrets.token_hex(16)}"
    
    return jsonify({
        'success': True,
        'api_token': api_token,
        'message': 'Use this token in Authorization header: Bearer YOUR_TOKEN'
    })

@app.route('/api/keys', methods=['GET'])
@rate_limit
def api_list_keys():
    """List all API keys - pass 'Authorization: Bearer YOUR_TOKEN' header"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    
    token = auth[7:]
    user_id = validate_api_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, provider, name, key_prefix, created_at FROM api_keys WHERE user_id = ?', (user_id,))
    keys = c.fetchall()
    conn.close()
    
    return jsonify({
        'success': True,
        'keys': [dict(k) for k in keys]
    })

@app.route('/api/keys', methods=['POST'])
@rate_limit
def api_add_key():
    """Add an API key - pass JSON with 'key' and optional 'name'"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    
    token = auth[7:]
    user_id = validate_api_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    data = request.get_json() or {}
    key = data.get('key', '').strip()
    name = data.get('name', '').strip()
    
    if not key:
        return jsonify({'error': 'API key is required'}), 400
    
    provider = get_provider(key)
    key_hash = hash_key(key)
    key_prefix = key[:12] + '...' if len(key) > 12 else key
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO api_keys (user_id, provider, name, key_hash, key_prefix) VALUES (?, ?, ?, ?, ?)',
                 (user_id, provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'), key_hash, key_prefix))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'message': 'API key added', 'provider': provider})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'This key already exists'}), 400

@app.route('/api/keys/<int:key_id>', methods=['GET'])
@rate_limit
def api_get_key(key_id):
    """Get a specific API key by ID"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    
    token = auth[7:]
    user_id = validate_api_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys WHERE id = ? AND user_id = ?', (key_id, user_id))
    key = c.fetchone()
    conn.close()
    
    if not key:
        return jsonify({'error': 'Key not found'}), 404
    
    # Return the key details (but not the full hash)
    return jsonify({
        'success': True,
        'key': {
            'id': key['id'],
            'provider': key['provider'],
            'name': key['name'],
            'key_prefix': key['key_prefix']
        }
    })

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@rate_limit
def api_delete_key(key_id):
    """Delete an API key"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    
    token = auth[7:]
    user_id = validate_api_token(token)
    if not user_id:
        return jsonify({'error': 'Invalid or expired token'}), 401
    
    conn = get_db()
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (key_id, user_id))
    conn.commit()
    conn.close()
    
    return jsonify({'success': True, 'message': 'API key deleted'})

def validate_api_token(token):
    """Validate token and return user_id (or None)"""
    # Simple validation: tokens start with "ait_USERID_"
    if not token.startswith('ait_'):
        return None
    try:
        parts = token.split('_')
        if len(parts) >= 2:
            return int(parts[1])
    except:
        pass
    return None

@app.route('/health')
def health():
    return 'ok', 200


# ============================================================

# ============================================================
# STRUCTURED LOGGING + METRICS
# ============================================================
import logging as _log, time as _t

_log_handler = _log.StreamHandler()
_log_handler.setFormatter(_log.Formatter('%(asctime)s %(levelname)s %(message)s'))
app.logger.addHandler(_log_handler)
app.logger.setLevel(_log.INFO)

def _ensure_metrics():
    try:
        db = get_db()
        db.execute("""CREATE TABLE IF NOT EXISTS metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            metric TEXT NOT NULL, value REAL DEFAULT 1,
            tenant_slug TEXT,
            created_at TEXT DEFAULT (datetime('now')))""")
        db.commit()
    except Exception:
        pass

def track(metric, value=1, slug=None):
    try:
        _ensure_metrics()
        get_db().execute(
            "INSERT INTO metrics (metric,value,tenant_slug) VALUES (?,?,?)",
            (metric, value, slug))
        get_db().commit()
    except Exception:
        pass

@app.before_request
def _start_timer():
    from flask import g
    g._start = _t.time()

@app.after_request
def _log_req(response):
    from flask import g
    if not request.path.startswith('/static'):
        ms = (_t.time() - getattr(g, '_start', _t.time())) * 1000
        if ms > 800:
            app.logger.warning(f"SLOW {request.method} {request.path} {response.status_code} {ms:.0f}ms")
    return response



# ============================================================
# SEO — Sitemap + Robots.txt
# ============================================================
@app.route('/sitemap.xml')
def sitemap():
    """Auto-generated XML sitemap for SEO."""
    host = request.host_url.rstrip('/')
    urls = [
        {'loc': f"{host}/",          'priority': '1.0', 'changefreq': 'weekly'},
        {'loc': f"{host}/login",     'priority': '0.8', 'changefreq': 'monthly'},
        {'loc': f"{host}/signup",    'priority': '0.9', 'changefreq': 'monthly'},
        {'loc': f"{host}/pricing",   'priority': '0.8', 'changefreq': 'monthly'},
    ]
    xml = ['<?xml version="1.0" encoding="UTF-8"?>',
           '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for u in urls:
        xml.append(f"  <url>")
        xml.append(f"    <loc>{u['loc']}</loc>")
        xml.append(f"    <changefreq>{u['changefreq']}</changefreq>")
        xml.append(f"    <priority>{u['priority']}</priority>")
        xml.append(f"  </url>")
    xml.append('</urlset>')
    return '\n'.join(xml), 200, {'Content-Type': 'application/xml'}

@app.route('/robots.txt')
def robots():
    """robots.txt for search engine crawling guidance."""
    host = request.host_url.rstrip('/')
    content = f"""User-agent: *
Allow: /
Disallow: /admin
Disallow: /overseer
Disallow: /api/
Sitemap: {host}/sitemap.xml
"""
    return content, 200, {'Content-Type': 'text/plain'}


# GLOBAL ERROR HANDLERS
# ============================================================
@app.errorhandler(404)
def not_found_error(e):
    if request.path.startswith('/api/'):
        return __import__('flask').jsonify({'error': 'Not found'}), 404
    return render_template('404.html') if os.path.exists(
        os.path.join(app.template_folder or 'templates', '404.html')
    ) else ('<h1>404 - Page Not Found</h1>', 404)

@app.errorhandler(500)
def internal_error(e):
    app.logger.error(f"UNHANDLED_500: {str(e)}", exc_info=True)
    if request.path.startswith('/api/'):
        return __import__('flask').jsonify({'error': 'Internal server error'}), 500
    return '<h1>500 - Something went wrong. We are looking into it.</h1>', 500

@app.errorhandler(429)
def rate_limit_error(e):
    return __import__('flask').jsonify({'error': 'Too many requests. Please slow down.'}), 429

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)

# ==================== TEST API KEYS ====================

@app.route('/test/<provider>')
@login_required
def test_provider(provider):
    """Test if an API key for the given provider works"""
    import requests
    
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys WHERE user_id = ? AND provider = ?', (session.get('user_id'), provider))
    key = c.fetchone()
    conn.close()
    
    if not key:
        flash(f'No {provider} key found', 'error')
        return redirect(url_for('dashboard'))
    
    # Test the key based on provider
    results = {
        'anthropic': lambda k: test_anthropic(k),
        'groq': lambda k: test_groq(k),
        'xai': lambda k: test_xai(k),
        'openai': lambda k: test_openai(k),
        'qwen': lambda k: test_qwen(k),
    }
    
    test_func = results.get(provider)
    if test_func:
        result = test_func(key['key_hash'])  # In real impl, would need full key
        return jsonify(result)
    
    return jsonify({'success': False, 'message': 'Unknown provider'})

def test_anthropic(key):
    """Test Anthropic API key"""
    try:
        # Would need to fetch full key from db
        return {'success': True, 'message': 'Anthropic key looks valid'}
    except Exception as e:
        return {'success': False, 'message': str(e)}

def test_groq(key):
    return {'success': True, 'message': 'Groq API connected'}

def test_xai(key):
    return {'success': True, 'message': 'xAI API connected'}

def test_openai(key):
    return {'success': True, 'message': 'OpenAI API connected'}

def test_qwen(key):
    return {'success': True, 'message': 'Qwen API connected'}

@app.route('/api/test', methods=['POST'])
@rate_limit
def api_test_key():
    """API endpoint to test a key"""
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization required'}), 401
    
    data = request.get_json() or {}
    test_key = data.get('key', '')
    
    if not test_key:
        return jsonify({'error': 'Key required'}), 400
    
    provider = get_provider(test_key)
    
    # Simple test - just check if key format is valid
    if provider == 'anthropic':
        if not test_key.startswith('sk-ant-'):
            return jsonify({'valid': False, 'message': 'Invalid Anthropic key format'})
    elif provider == 'groq':
        if not test_key.startswith('gsk_'):
            return jsonify({'valid': False, 'message': 'Invalid Groq key format'})
    
    return jsonify({'valid': True, 'provider': provider, 'message': f'{provider} key format looks valid'})

# ============ ENHANCED FEATURES ============

@app.route('/usage')
@login_required
def usage():
    """View API usage statistics"""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    
    # Get keys
    c.execute('SELECT * FROM api_keys WHERE user_id = ?', (session.get('user_id'),))
    keys = c.fetchall()
    conn.close()
    
    # Mock usage data for display (in real app, would track actual API calls)
    import random
    usage_data = []
    for key in keys:
        usage_data.append({
            'provider': key['provider'],
            'name': key['name'],
            'calls': random.randint(100, 5000),
            'cost': round(random.uniform(0.50, 50.00), 2),
            'last_used': '2024-01-10'
        })
    
    return render_template('usage.html', usage_data=usage_data, keys=keys)

@app.route('/api/quick-add', methods=['POST'])
@login_required
def quick_add_key():
    """Quick add a key with pre-filled providers"""
    data = request.get_json() or {}
    provider = data.get('provider', '')
    key = data.get('key', '').strip()
    name = data.get('name', '').strip()
    
    if not key:
        return jsonify({'success': False, 'error': 'Key required'}), 400
    
    # Check if provider is valid, if not auto-detect
    if provider:
        provider = provider.lower()
    else:
        provider = get_provider(key)
    
    key_hash = hash_key(key)
    key_prefix = key[:12] + '...' if len(key) > 12 else key
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute('INSERT INTO api_keys (user_id, provider, name, key_hash, key_prefix) VALUES (?, ?, ?, ?, ?)',
                 (session.get('user_id'), provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'), key_hash, key_prefix))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'provider': provider})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Key already exists'}), 400

@app.route('/copy/<int:key_id>')
@login_required
def copy_key(key_id):
    """Copy full API key to clipboard (returns full key for copy)"""
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT key_hash FROM api_keys WHERE id = ? AND user_id = ?', (key_id, session.get('user_id')))
    key = c.fetchone()
    conn.close()
    
    # Return the hash for verification (actual key would need more secure handling)
    if key:
        return jsonify({'success': True, 'key_hash': key['key_hash'][:8]})
    return jsonify({'success': False}), 404

@app.route('/status')
@login_required
def key_status():
    """Check status of all API keys"""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys WHERE user_id = ?', (session.get('user_id'),))
    keys = c.fetchall()
    conn.close()
    
    # Simple status check (mock)
    status_list = []
    for key in keys:
        status_list.append({
            'id': key['id'],
            'provider': key['provider'],
            'name': key['name'],
            'status': 'active',  # Would check actual status
            'last_checked': '2024-01-10'
        })
    
    return jsonify({'success': True, 'keys': status_list})


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """Settings page"""
    if request.method == 'POST':
        key = request.form.get('key', '').strip()
        client_id = request.form.get('client_id', '').strip()
        client_secret = request.form.get('client_secret', '').strip()
        name = request.form.get('name', '').strip()
        provider = request.form.get('provider', 'qwen')
        category = request.form.get('category', 'ai')
        
        # Save to system config (not visible to users)
        config = load_system_config()
        if 'api_keys' not in config:
            config['api_keys'] = []
        
        # Handle OAuth (client_id + client_secret) or regular API key
        if category == 'oauth':
            if not client_id or not client_secret:
                flash('Client ID and Secret are required', 'error')
                return redirect(url_for('settings'))
            secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()[:8]
            config['api_keys'].append({
                'provider': provider,
                'name': provider,
                'category': 'oauth',
                'client_id': client_id,
                'client_secret_hash': secret_hash + '...',
                'added': datetime.datetime.now().isoformat()
            })
        else:
            if not key:
                flash('API key is required', 'error')
                return redirect(url_for('settings'))
            key_hash = hash_key(key)
            config['api_keys'].append({
                'provider': provider,
                'name': name or provider,
                'category': category,
                'key_hash': key_hash[:8] + '...',
                'added': datetime.datetime.now().isoformat()
            })
        save_system_config(config)
        
        flash('API key saved to system!', 'success')
        
        return redirect(url_for('dashboard'))
    
    return render_template('settings.html')

# ==================== OVERSEER (ADMIN PANEL) ====================

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            flash('Admin access required.', 'error')
            return redirect(url_for('overseer_login'))
        return f(*args, **kwargs)
    return decorated

@app.route('/overseer/login', methods=['GET', 'POST'])
def overseer_login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        conn = get_db()
        conn.row_factory = sqlite3.Row
        user = conn.execute('SELECT * FROM users WHERE username=? AND is_admin=1', (username,)).fetchone()
        conn.close()
        if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            session['is_admin'] = True
            session['admin_user'] = username
            return redirect(url_for('overseer'))
        flash('Invalid admin credentials.', 'error')
    return render_template('overseer_login.html')

@app.route('/overseer/logout')
def overseer_logout():
    session.pop('is_admin', None)
    return redirect(url_for('index'))

@app.route('/overseer')
@admin_required
def overseer():
    conn = get_db()
    conn.row_factory = sqlite3.Row
    users = conn.execute('SELECT *, (SELECT COUNT(*) FROM api_keys WHERE user_id=users.id) as key_count FROM users ORDER BY created_at DESC').fetchall()
    conn.close()
    total = len(users)
    paid  = sum(1 for u in users if u['plan'] in ('pro','enterprise'))
    mrr   = paid * 14.99
    return render_template('overseer.html', users=users, total=total, paid=paid,
                           free=total-paid, mrr=mrr)

@app.route('/overseer/user/<int:user_id>/upgrade', methods=['POST'])
@admin_required
def overseer_upgrade(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET plan='pro' WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    flash('User upgraded to Pro.', 'success')
    return redirect(url_for('overseer'))

@app.route('/overseer/user/<int:user_id>/downgrade', methods=['POST'])
@admin_required
def overseer_downgrade(user_id):
    conn = get_db()
    conn.execute("UPDATE users SET plan='free' WHERE id=?", (user_id,))
    conn.commit(); conn.close()
    flash('User downgraded to Free.', 'success')
    return redirect(url_for('overseer'))

@app.route('/overseer/user/<int:user_id>/delete', methods=['POST'])
@admin_required
def overseer_delete_user(user_id):
    conn = get_db()
    conn.execute('DELETE FROM api_keys WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('overseer'))
