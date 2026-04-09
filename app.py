import os
import sqlite3
import hashlib
import secrets
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, make_response
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Security config
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'MySecret123')  # CHANGE THIS!
ADMIN_USER = os.environ.get('ADMIN_USER', 'admin')

# Database
DB_FILE = os.path.join(os.path.dirname(__file__), 'api_keys.db')

def init_db():
    """Initialize the database with security tables."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    
    # API Keys table
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL,
        name TEXT,
        key_hash TEXT UNIQUE NOT NULL,
        key_prefix TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    
    # Sessions table for security tracking
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_token TEXT UNIQUE NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        expires_at TIMESTAMP
    )''')
    
    conn.commit()
    conn.close()

init_db()

# Security headers
@app.after_request
def add_security_headers(response):
    """Add comprehensive security headers."""
    # Content Security Policy
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Simple session management
def login_required(f):
    """Decorator to require authentication."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Rate limiting (simple in-memory)
from collections import defaultdict
import time
rate_limits = defaultdict(list)
RATE_LIMIT_MAX = 20  # requests per minute
RATE_LIMIT_WINDOW = 60

def check_rate_limit():
    """Check if request exceeds rate limit."""
    ip = request.remote_addr
    now = time.time()
    rate_limits[ip] = [t for t in rate_limits[ip] if now - t < RATE_LIMIT_WINDOW]
    if len(rate_limits[ip]) >= RATE_LIMIT_MAX:
        return False
    rate_limits[ip].append(now)
    return True

def rate_limit(f):
    """Decorator for rate limiting."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not check_rate_limit():
            return "Too many requests. Please wait.", 429
        return f(*args, **kwargs)
    return decorated

# Provider info
PROVIDERS = {
    'anthropic': {'name': 'Anthropic (Claude)', 'prefix': 'sk-ant-'},
    'groq': {'name': 'Groq', 'prefix': 'gsk_'},
    'xai': {'name': 'xAI (Grok)', 'prefix': 'xai-'},
    'qwen': {'name': 'Qwen', 'prefix': 'sk-'},
    'openai': {'name': 'OpenAI', 'prefix': 'sk-'},
    'mistral': {'name': 'Mistral', 'prefix': 'sk-'},
    'cohere': {'name': 'Cohere', 'prefix': 'ck_'},
    'google': {'name': 'Google AI', 'prefix': 'AIza'},
}

def get_provider(key):
    """Detect provider from key prefix."""
    for name, info in PROVIDERS.items():
        if key.startswith(info['prefix']):
            return name
    return 'unknown'

def hash_key(key):
    """Hash the key for display (show only last 4 chars)."""
    return hashlib.sha256(key.encode()).hexdigest()[:8]

@app.route('/login', methods=['GET', 'POST'])
@rate_limit
def login():
    """Login page with rate limiting."""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Check credentials
        if username == ADMIN_USER and password == ADMIN_PASSWORD:
            session['logged_in'] = True
            session['username'] = username
            session.permanent = True
            flash('Logged in successfully!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout and clear session."""
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

@app.route('/')
@login_required
@rate_limit
def index():
    """Dashboard - requires login."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys ORDER BY created_at DESC')
    keys = c.fetchall()
    conn.close()
    return render_template('index.html', keys=keys, providers=PROVIDERS)

@app.route('/add', methods=['GET', 'POST'])
@login_required
@rate_limit
def add_key():
    """Add new API key - requires login."""
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
            c.execute('INSERT INTO api_keys (provider, name, key_hash, key_prefix) VALUES (?, ?, ?, ?)',
                     (provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'), key_hash, key_prefix))
            conn.commit()
            conn.close()
            flash('API key added successfully!', 'success')
        except sqlite3.IntegrityError:
            flash('This key already exists', 'error')
        
        return redirect(url_for('index'))
    
    return render_template('add.html', providers=PROVIDERS)

@app.route('/delete/<int:key_id>')
@login_required
@rate_limit
def delete_key(key_id):
    """Delete API key - requires login."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('API key deleted', 'success')
    return redirect(url_for('index'))

@app.route('/api/keys')
@login_required
@rate_limit
def api_keys():
    """Return keys as JSON - requires login."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, provider, name, key_prefix, created_at FROM api_keys ORDER BY created_at DESC')
    keys = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in keys])

@app.route('/health')
def health():
    """Health check endpoint."""
    return 'ok', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
