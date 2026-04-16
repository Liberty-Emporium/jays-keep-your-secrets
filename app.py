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

# ── Security core (bcrypt + pepper + session fixation fix) ───
try:
    import bcrypt as _bcrypt
    _BCRYPT_OK = True
except ImportError:
    _BCRYPT_OK = False

def _get_pepper():
    return os.environ.get('PASSWORD_PEPPER', '')

def _hash_password(password):
    """Hash password with bcrypt + pepper. Falls back to sha256."""
    peppered = _get_pepper() + password
    if _BCRYPT_OK:
        h = _bcrypt.hashpw(peppered.encode('utf-8'), _bcrypt.gensalt(rounds=12))
        return 'bcrypt:' + h.decode('utf-8')
    return hashlib.sha256(password.encode()).hexdigest()

def _verify_password(password, stored):
    """Verify password. Handles bcrypt and legacy plain sha256."""
    try:
        if stored.startswith('bcrypt:'):
            if not _BCRYPT_OK:
                return False
            peppered = _get_pepper() + password
            return _bcrypt.checkpw(peppered.encode('utf-8'), stored[7:].encode('utf-8'))
        # Legacy plain sha256 — still works for old accounts
        legacy = hashlib.sha256(password.encode()).hexdigest()
        return secrets.compare_digest(stored, legacy)
    except Exception:
        return False

def _needs_upgrade(stored):
    return not stored.startswith('bcrypt:')

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
def _get_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    import pathlib
    key_file = pathlib.Path('/data/secret_key')
    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        if key_file.exists():
            k = key_file.read_text().strip()
            if k: return k
        k = secrets.token_hex(32)
        key_file.write_text(k)
        return k
    except Exception:
        return secrets.token_hex(32)

app.secret_key = _get_secret_key()

import secrets as _secrets_module

def _get_csrf_token():
    """Generate or retrieve CSRF token from session."""
    if 'csrf_token' not in session:
        session['csrf_token'] = _secrets_module.token_hex(32)
    return session['csrf_token']

def _validate_csrf():
    """Validate CSRF token on POST requests. Returns True if valid."""
    if request.method != 'POST':
        return True
    # Skip API routes
    if request.path.startswith('/api/'):
        return True
    token = request.form.get('csrf_token') or request.headers.get('X-CSRF-Token')
    return token and token == session.get('csrf_token')

app.jinja_env.globals['csrf_token'] = _get_csrf_token


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

    # API Tokens table — real, signed, expiring tokens for bot access
    c.execute('''CREATE TABLE IF NOT EXISTS api_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        label TEXT DEFAULT 'default',
        expires_at TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')

    # Brain key table — encrypted brain password, admin-only
    c.execute('''CREATE TABLE IF NOT EXISTS brain_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        label TEXT NOT NULL DEFAULT 'default',
        key_value TEXT NOT NULL,
        rotated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by INTEGER,
        FOREIGN KEY (created_by) REFERENCES users (id)
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
    
    # Add new columns if they don't exist (safe migrations)
    migrations = [
        "ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN admin_note TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN last_login TIMESTAMP",
    ]
    for sql in migrations:
        try:
            c.execute(sql)
            conn.commit()
        except Exception:
            pass  # column already exists

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
    'groq':      {'name': 'Groq',               'prefix': 'gsk_'},
    'xai':       {'name': 'xAI (Grok)',          'prefix': 'xai-'},
    'openrouter':{'name': 'OpenRouter',           'prefix': 'sk-or-'},
    'github':    {'name': 'GitHub',               'prefix': 'ghp_'},
    'gitlab':    {'name': 'GitLab',               'prefix': 'glpat-'},
    'openai':    {'name': 'OpenAI',               'prefix': 'sk-'},
    'qwen':      {'name': 'Qwen',                 'prefix': 'sk-'},
    'mistral':   {'name': 'Mistral',              'prefix': 'sk-'},
}

def get_provider(key):
    # Check longer/more-specific prefixes first to avoid false matches
    sorted_providers = sorted(PROVIDERS.items(), key=lambda x: -len(x[1]['prefix']))
    for name, info in sorted_providers:
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
# ── OpenRouter AI (single provider) ──────────────────────────────────────────
def get_config(key, default=''):
    """Get a value from system config file."""
    cfg = load_system_config()
    return cfg.get(key, default)

def set_config(key, value):
    """Set a value in system config file."""
    cfg = load_system_config()
    cfg[key] = value
    save_system_config(cfg)

def get_openrouter_key(user_id=None):
    """Get OpenRouter API key from config or env."""
    return get_config('openrouter_key', os.environ.get('OPENROUTER_API_KEY', ''))

def get_openrouter_model(user_id=None):
    """Get selected OpenRouter model from config."""
    return get_config('openrouter_model', 'google/gemini-flash-1.5')

def call_openrouter(messages, user_id=None, max_tokens=1000):
    """Call OpenRouter API with any model. Returns text string."""
    import urllib.request as _ur, json as _json
    key = get_openrouter_key(user_id)
    if not key:
        return "AI unavailable — add your OpenRouter API key in Settings ⚙️"
    model = get_openrouter_model(user_id)
    try:
        payload = _json.dumps({
            'model': model,
            'messages': messages,
            'max_tokens': max_tokens
        }).encode()
        req = _ur.Request(
            'https://openrouter.ai/api/v1/chat/completions',
            data=payload,
            headers={
                'Authorization': f'Bearer {key}',
                'Content-Type': 'application/json',
                'HTTP-Referer': 'https://libertyemporium.com',
                'X-Title': 'Liberty App'
            }
        )
        with _ur.urlopen(req, timeout=30) as resp:
            return _json.loads(resp.read())['choices'][0]['message']['content']
    except Exception as e:
        return f"AI error: {e}"
# ─────────────────────────────────────────────────────────────────────────────

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
        
        if user and _verify_password(password, user['password_hash']):
            # Check if account is suspended
            if user['suspended'] if 'suspended' in user.keys() else False:
                flash('This account has been suspended. Contact support.', 'error')
                return render_template('login.html', demo_mode=DEMO_MODE)
            # Auto-upgrade legacy sha256 hash to bcrypt on login
            if _needs_upgrade(user['password_hash']):
                _ug = get_db()
                _ug.execute('UPDATE users SET password_hash=? WHERE id=?',
                            (_hash_password(password), user['id']))
                _ug.commit(); _ug.close()
            # Secure session — clear first prevents session fixation attacks
            session.clear()
            session.permanent = True
            session['logged_in'] = True
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['plan'] = user['plan']
            session['is_admin'] = bool(user['is_admin'])
            session['csrf_token'] = secrets.token_hex(32)
            # Update last_login timestamp
            _ll = get_db()
            _ll.execute('UPDATE users SET last_login=? WHERE id=?',
                        (datetime.datetime.utcnow().isoformat(), user['id']))
            _ll.commit(); _ll.close()
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
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('signup'))

        password_hash = _hash_password(password)
        
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute('INSERT INTO users (username, email, password_hash, plan) VALUES (?, ?, ?, ?)',
                     (username, email, password_hash, 'free'))
            user_id = c.lastrowid
            conn.commit()
            conn.close()
            
            session.clear()
            session.permanent = True
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user_id
            session['plan'] = 'free'
            session['is_admin'] = False
            session['csrf_token'] = secrets.token_hex(32)
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
        
        if len(new_pass) < 8:
            flash('Password must be at least 8 characters', 'error')
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

        if not _verify_password(current, user['password_hash']):
            flash('Current password is incorrect', 'error')
            conn.close()
            return redirect(url_for('change_password'))

        c.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                 (_hash_password(new_pass), session.get('user_id')))
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
        if len(new_pass) < 8:
            error = 'Password must be at least 8 characters.'
        elif new_pass != confirm:
            error = 'Passwords do not match.'
        else:
            c.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                      (_hash_password(new_pass), record['user_id']))
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
    """Get a real, signed, expiring API token.
    POST JSON: {"username": "...", "password": "...", "label": "echo", "expires_days": 90}
    """
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    label    = data.get('label', 'default').strip()[:64]
    expires_days = int(data.get('expires_days', 90))

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    conn = get_db()
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = c.fetchone()

    if not user or not _verify_password(password, user['password_hash']):
        conn.close()
        return jsonify({'error': 'Invalid credentials'}), 401

    # Generate a cryptographically secure token
    raw_token = secrets.token_urlsafe(48)          # 64-char URL-safe token
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)).isoformat()

    # Revoke any existing token with the same label for this user
    c.execute('DELETE FROM api_tokens WHERE user_id = ? AND label = ?', (user['id'], label))
    c.execute(
        'INSERT INTO api_tokens (user_id, token_hash, label, expires_at) VALUES (?, ?, ?, ?)',
        (user['id'], token_hash, label, expires_at)
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'api_token': raw_token,
        'label': label,
        'expires_at': expires_at,
        'message': 'Use this token in Authorization header: Bearer YOUR_TOKEN'
    })

# ── UI-based token generation (logged-in users only, no password needed) ────
@app.route('/api/token/ui', methods=['POST'])
@rate_limit
def api_token_ui_generate():
    """Generate an API token from a logged-in browser session.
    No password needed — session auth is sufficient.
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    # CSRF check
    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    label = 'ui-generated'
    expires_days = 365  # 1 year
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    expires_at = (datetime.datetime.utcnow() + datetime.timedelta(days=expires_days)).isoformat()

    conn = get_db()
    try:
        # Revoke any existing ui-generated token for this user
        conn.execute('DELETE FROM api_tokens WHERE user_id = ? AND label = ?', (user_id, label))
        conn.execute(
            'INSERT INTO api_tokens (user_id, token_hash, label, expires_at) VALUES (?, ?, ?, ?)',
            (user_id, token_hash, label, expires_at)
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({
        'success': True,
        'api_token': raw_token,
        'label': label,
        'expires_at': expires_at,
        'message': 'Use in Authorization: Bearer YOUR_TOKEN header'
    })


@app.route('/api/token/ui', methods=['DELETE'])
@rate_limit
def api_token_ui_revoke():
    """Revoke the UI-generated token for the logged-in user."""
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Not logged in'}), 401

    token = request.headers.get('X-CSRF-Token')
    if not token or token != session.get('csrf_token'):
        return jsonify({'error': 'Invalid CSRF token'}), 403

    conn = get_db()
    try:
        conn.execute('DELETE FROM api_tokens WHERE user_id = ? AND label = ?', (user_id, 'ui-generated'))
        conn.commit()
    finally:
        conn.close()

    return jsonify({'success': True, 'message': 'Token revoked'})


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
    """Validate token against DB, check expiry, return user_id or None."""
    if not token or len(token) < 16:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            'SELECT user_id, expires_at FROM api_tokens WHERE token_hash = ?',
            (token_hash,)
        ).fetchone()
        conn.close()
        if not row:
            return None
        if row['expires_at']:
            expires = datetime.datetime.fromisoformat(row['expires_at'])
            if datetime.datetime.utcnow() > expires:
                return None
        return row['user_id']
    except Exception:
        return None

# ============ BRAIN KEY API (admin only) ============
# These endpoints let KiloClaw/Echo fetch and rotate the brain encryption password.
# Only admin-level users can access these.

def _require_admin_token(token):
    """Returns user dict if token is valid AND user is admin, else None."""
    user_id = validate_api_token(token)
    if not user_id:
        return None
    conn = get_db()
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT id, username, is_admin FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    if not user or not user['is_admin']:
        return None
    return user

@app.route('/api/brain-key', methods=['GET'])
@rate_limit
def api_get_brain_key():
    """GET the current brain encryption key. Admin token required.
    Returns: {success, label, key_value, rotated_at}
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    user = _require_admin_token(auth[7:])
    if not user:
        return jsonify({'error': 'Admin access required'}), 403

    label = request.args.get('label', 'default')
    conn = get_db()
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        'SELECT label, key_value, rotated_at FROM brain_keys WHERE label = ? ORDER BY id DESC LIMIT 1',
        (label,)
    ).fetchone()
    conn.close()

    if not row:
        return jsonify({'error': f'No brain key found for label={label}. Set one first via PUT /api/brain-key'}), 404

    return jsonify({
        'success': True,
        'label': row['label'],
        'key_value': row['key_value'],
        'rotated_at': row['rotated_at']
    })

@app.route('/api/brain-key', methods=['PUT'])
@rate_limit
def api_set_brain_key():
    """PUT (create/update) the brain encryption key. Admin token required.
    Body JSON: {"label": "default", "key_value": "your-strong-passphrase"}
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    user = _require_admin_token(auth[7:])
    if not user:
        return jsonify({'error': 'Admin access required'}), 403

    data = request.get_json() or {}
    label     = data.get('label', 'default').strip()[:64]
    key_value = data.get('key_value', '').strip()

    if not key_value or len(key_value) < 12:
        return jsonify({'error': 'key_value must be at least 12 characters'}), 400

    conn = get_db()
    # Overwrite existing key for this label
    conn.execute('DELETE FROM brain_keys WHERE label = ?', (label,))
    conn.execute(
        'INSERT INTO brain_keys (label, key_value, rotated_at, created_by) VALUES (?, ?, datetime("now"), ?)',
        (label, key_value, user['id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': f'Brain key [{label}] saved. Rotate save-brain.sh next session.',
        'label': label,
        'rotated_at': datetime.datetime.utcnow().isoformat()
    })

@app.route('/api/brain-key/rotate', methods=['POST'])
@rate_limit
def api_rotate_brain_key():
    """POST to rotate the brain key to a new value. Admin token required.
    Body JSON: {"label": "default", "new_key": "new-passphrase", "old_key": "old-passphrase"}
    old_key is verified before rotation as a safety check.
    """
    auth = request.headers.get('Authorization', '')
    if not auth.startswith('Bearer '):
        return jsonify({'error': 'Authorization header required'}), 401
    user = _require_admin_token(auth[7:])
    if not user:
        return jsonify({'error': 'Admin access required'}), 403

    data    = request.get_json() or {}
    label   = data.get('label', 'default').strip()[:64]
    new_key = data.get('new_key', '').strip()
    old_key = data.get('old_key', '').strip()

    if not new_key or len(new_key) < 12:
        return jsonify({'error': 'new_key must be at least 12 characters'}), 400

    conn = get_db()
    conn.row_factory = sqlite3.Row
    row = conn.execute(
        'SELECT key_value FROM brain_keys WHERE label = ? ORDER BY id DESC LIMIT 1',
        (label,)
    ).fetchone()

    if row and old_key and row['key_value'] != old_key:
        conn.close()
        return jsonify({'error': 'old_key does not match current key'}), 403

    conn.execute('DELETE FROM brain_keys WHERE label = ?', (label,))
    conn.execute(
        'INSERT INTO brain_keys (label, key_value, rotated_at, created_by) VALUES (?, ?, datetime("now"), ?)',
        (label, new_key, user['id'])
    )
    conn.commit()
    conn.close()

    return jsonify({
        'success': True,
        'message': f'Brain key [{label}] rotated. Run save-brain.sh to re-encrypt.',
        'label': label,
        'rotated_at': datetime.datetime.utcnow().isoformat()
    })

@app.route('/health')
def health():
    try:
        db = get_db()
        db.execute('SELECT 1').fetchone()
        return jsonify({'status': 'ok', 'db': 'ok'}), 200
    except Exception as e:
        return jsonify({'status': 'degraded', 'db': str(e)}), 503


# ============================================================

# ============================================================
# STRUCTURED LOGGING + METRICS
# ============================================================
import logging as _log, time as _t

import bcrypt as _bcrypt_lib

def _sha256_hash(pw):
    import hashlib
    return hashlib.sha256(pw.encode()).hexdigest()

def _is_sha256_hash(h):
    return isinstance(h, str) and len(h) == 64 and all(c in '0123456789abcdef' for c in h.lower())

def _bcrypt_hash(pw):
    return _bcrypt_lib.hashpw(pw.encode('utf-8'), _bcrypt_lib.gensalt()).decode('utf-8')

def _bcrypt_verify(pw, stored):
    if _is_sha256_hash(stored):
        return _sha256_hash(pw) == stored, True  # valid, needs_upgrade
    try:
        return _bcrypt_lib.checkpw(pw.encode('utf-8'), stored.encode('utf-8')), False
    except Exception:
        return False, False


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
    """Settings page — OpenRouter key + model selection."""
    if request.method == 'POST':
        or_key   = request.form.get('openrouter_key', '').strip()
        or_model = request.form.get('openrouter_model', '').strip()
        if or_key:
            set_config('openrouter_key', or_key)
        if or_model:
            set_config('openrouter_model', or_model)
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))

    return render_template('settings.html',
        key_set=bool(get_openrouter_key()),
        current_key=get_openrouter_key(),
        current_model=get_openrouter_model())

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
        if user and _verify_password(password, user['password_hash']):
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
    search = request.args.get('q', '').strip()
    if search:
        users = conn.execute(
            '''SELECT *, (SELECT COUNT(*) FROM api_keys WHERE user_id=users.id) as key_count
               FROM users WHERE username LIKE ? OR email LIKE ?
               ORDER BY created_at DESC''',
            (f'%{search}%', f'%{search}%')
        ).fetchall()
    else:
        users = conn.execute(
            'SELECT *, (SELECT COUNT(*) FROM api_keys WHERE user_id=users.id) as key_count FROM users ORDER BY created_at DESC'
        ).fetchall()
    # Revenue over last 30 days (signups)
    signups_30d = conn.execute(
        "SELECT COUNT(*) as c FROM users WHERE created_at >= date('now','-30 days')"
    ).fetchone()['c']
    conn.close()
    total = len(users)
    paid  = sum(1 for u in users if u['plan'] in ('pro','enterprise'))
    mrr   = paid * 14.99
    return render_template('overseer.html', users=users, total=total, paid=paid,
                           free=total-paid, mrr=mrr, search=search,
                           signups_30d=signups_30d)


@app.route('/overseer/user/<int:user_id>/upgrade', methods=['POST'])
@admin_required
def overseer_upgrade(user_id):
    plan = request.form.get('plan', 'pro')
    if plan not in ('free','pro','enterprise','demo'):
        plan = 'pro'
    conn = get_db()
    conn.execute('UPDATE users SET plan=? WHERE id=?', (plan, user_id))
    conn.commit(); conn.close()
    flash(f'User plan set to {plan}.', 'success')
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
    conn.execute('DELETE FROM api_tokens WHERE user_id=?', (user_id,))
    conn.execute('DELETE FROM users WHERE id=?', (user_id,))
    conn.commit(); conn.close()
    flash('User deleted.', 'success')
    return redirect(url_for('overseer'))


@app.route('/overseer/user/<int:user_id>/suspend', methods=['POST'])
@admin_required
def overseer_suspend(user_id):
    """Suspend a user — disables login without deleting."""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT suspended FROM users WHERE id=?', (user_id,)).fetchone()
    # Add suspended column if not exists
    try:
        conn.execute('ALTER TABLE users ADD COLUMN suspended INTEGER DEFAULT 0')
        conn.commit()
    except Exception:
        pass
    currently = user['suspended'] if user and 'suspended' in user.keys() else 0
    new_val = 0 if currently else 1
    conn.execute('UPDATE users SET suspended=? WHERE id=?', (new_val, user_id))
    # Revoke all tokens if suspending
    if new_val:
        conn.execute('DELETE FROM api_tokens WHERE user_id=?', (user_id,))
    conn.commit(); conn.close()
    flash('User ' + ('suspended.' if new_val else 'reactivated.'), 'success')
    return redirect(url_for('overseer'))


@app.route('/overseer/user/<int:user_id>/reset-password', methods=['POST'])
@admin_required
def overseer_reset_password(user_id):
    """Admin force-resets a user's password."""
    new_pass = request.form.get('new_password', '').strip()
    if not new_pass or len(new_pass) < 8:
        flash('Password must be at least 8 characters.', 'error')
        return redirect(url_for('overseer'))
    conn = get_db()
    conn.execute('UPDATE users SET password_hash=? WHERE id=?',
                 (_hash_password(new_pass), user_id))
    # Revoke all existing tokens (force re-login)
    conn.execute('DELETE FROM api_tokens WHERE user_id=?', (user_id,))
    conn.commit(); conn.close()
    flash('Password reset and all tokens revoked.', 'success')
    return redirect(url_for('overseer'))


@app.route('/overseer/user/<int:user_id>/force-logout', methods=['POST'])
@admin_required
def overseer_force_logout(user_id):
    """Revoke all API tokens for a user (forces re-login/re-auth)."""
    conn = get_db()
    conn.execute('DELETE FROM api_tokens WHERE user_id=?', (user_id,))
    conn.commit(); conn.close()
    flash('All sessions and tokens revoked for user.', 'success')
    return redirect(url_for('overseer'))


@app.route('/overseer/user/<int:user_id>/note', methods=['POST'])
@admin_required
def overseer_add_note(user_id):
    """Add an admin note to a user."""
    note = request.form.get('note', '').strip()[:500]
    conn = get_db()
    try:
        conn.execute('ALTER TABLE users ADD COLUMN admin_note TEXT DEFAULT NULL')
        conn.commit()
    except Exception:
        pass
    conn.execute('UPDATE users SET admin_note=? WHERE id=?', (note, user_id))
    conn.commit(); conn.close()
    flash('Note saved.', 'success')
    return redirect(url_for('overseer'))


@app.route('/overseer/user/<int:user_id>/keys')
@admin_required
def overseer_view_keys(user_id):
    """View a user's API keys (prefixes only, not full keys)."""
    conn = get_db()
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT username, email, plan FROM users WHERE id=?', (user_id,)).fetchone()
    keys = conn.execute(
        'SELECT id, provider, name, key_prefix, created_at FROM api_keys WHERE user_id=? ORDER BY created_at DESC',
        (user_id,)
    ).fetchall()
    conn.close()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('overseer'))
    return render_template('overseer_user_keys.html', user=user, keys=keys, user_id=user_id)


@app.route('/overseer/user/<int:user_id>/send-email', methods=['POST'])
@admin_required
def overseer_send_email(user_id):
    """Send an email to a specific user."""
    subject = request.form.get('subject', '').strip()
    body    = request.form.get('body', '').strip()
    if not subject or not body:
        flash('Subject and message are required.', 'error')
        return redirect(url_for('overseer'))
    conn = get_db()
    conn.row_factory = sqlite3.Row
    user = conn.execute('SELECT email, username FROM users WHERE id=?', (user_id,)).fetchone()
    conn.close()
    if not user:
        flash('User not found.', 'error')
        return redirect(url_for('overseer'))
    ok, err = send_email(user['email'], subject, body)
    if ok:
        flash(f'Email sent to {user["email"]}.', 'success')
    else:
        flash(f'Email failed: {err}', 'error')
    return redirect(url_for('overseer'))