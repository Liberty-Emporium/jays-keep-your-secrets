import os
import sqlite3
import hashlib
import secrets
import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Config
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

# Database
DB_FILE = os.path.join(os.path.dirname(__file__), 'api_keys.db')

def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(DB_FILE)
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
    
    # Create demo user if demo mode
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
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        conn = sqlite3.connect(DB_FILE)
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
            conn = sqlite3.connect(DB_FILE)
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
    conn = sqlite3.connect(DB_FILE)
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
            conn = sqlite3.connect(DB_FILE)
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
    conn = sqlite3.connect(DB_FILE)
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
        
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE id = ?', (session.get('user_id'),))
        user = c.fetchone()
        
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

@app.route('/health')
def health():
    return 'ok', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
