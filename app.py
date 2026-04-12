import os
import sqlite3
import hashlib
import secrets
import datetime
from functools import wraps
from collections import defaultdict
import time

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# Config
DEMO_MODE = os.environ.get('DEMO_MODE', 'true').lower() == 'true'

# Database — persisted to /data volume
DATA_DIR = os.environ.get('DATA_DIR', '/data')
os.makedirs(DATA_DIR, exist_ok=True)
DB_FILE = os.path.join(DATA_DIR, 'api_keys.db')

PLAN_LIMITS = {
    'free':       {'keys': 5},
    'pro':        {'keys': 999},
    'enterprise': {'keys': 9999},
}

PROVIDERS = {
    'anthropic': {'name': 'Anthropic (Claude)', 'prefix': 'sk-ant-'},
    'groq':      {'name': 'Groq',               'prefix': 'gsk_'},
    'xai':       {'name': 'xAI (Grok)',          'prefix': 'xai-'},
    'qwen':      {'name': 'Qwen',                'prefix': 'sk-'},
    'openai':    {'name': 'OpenAI',              'prefix': 'sk-'},
    'mistral':   {'name': 'Mistral',             'prefix': 'sk-'},
}

# ==================== DATABASE ====================

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_FILE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_FILE)
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            plan TEXT NOT NULL DEFAULT 'free',
            is_admin INTEGER DEFAULT 0,
            stripe_customer_id TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            provider TEXT NOT NULL,
            name TEXT,
            category TEXT DEFAULT 'ai',
            key_hash TEXT UNIQUE NOT NULL,
            key_prefix TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS api_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            token_hash TEXT UNIQUE NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expires_at TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
    ''')
    # Default admin — admin / admin1
    existing = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
    if not existing:
        db.execute(
            "INSERT INTO users (username, email, password_hash, plan, is_admin) VALUES (?,?,?,?,?)",
            ('admin', 'admin@localhost', hashlib.sha256('admin1'.encode()).hexdigest(), 'enterprise', 1)
        )
    if DEMO_MODE:
        demo = db.execute("SELECT id FROM users WHERE username = 'demo'").fetchone()
        if not demo:
            db.execute(
                "INSERT INTO users (username, email, password_hash, plan) VALUES (?,?,?,?)",
                ('demo', 'demo@demo.com', hashlib.sha256('demo123'.encode()).hexdigest(), 'free')
            )
    db.commit()
    db.close()

init_db()

# ==================== SECURITY HEADERS ====================

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# ==================== RATE LIMITING ====================

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
            return jsonify({'error': 'Too many requests.'}), 429
        return f(*args, **kwargs)
    return decorated

# ==================== HELPERS ====================

def get_provider(key):
    for name, info in PROVIDERS.items():
        if key.startswith(info['prefix']):
            return name
    return 'unknown'

def hash_key(key):
    return hashlib.sha256(key.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            flash('Please log in to continue.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def plan_required(min_plan):
    order = ['free', 'pro', 'enterprise']
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not session.get('logged_in'):
                return redirect(url_for('login'))
            plan = session.get('plan', 'free')
            if order.index(plan) < order.index(min_plan):
                flash(f'This feature requires the {min_plan.title()} plan.', 'error')
                return redirect(url_for('upgrade'))
            return f(*args, **kwargs)
        return decorated
    return decorator

def get_current_user():
    if not session.get('user_id'):
        return None
    return get_db().execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

def user_key_count(user_id):
    return get_db().execute('SELECT COUNT(*) FROM api_keys WHERE user_id = ?', (user_id,)).fetchone()[0]

# ==================== AUTH ====================

@app.route('/')
def index():
    if session.get('logged_in'):
        return redirect(url_for('dashboard'))
    return render_template('landing.html', demo_mode=DEMO_MODE)

@app.route('/demo')
def demo():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = 'demo'").fetchone()
    if user:
        session['logged_in'] = True
        session['username'] = user['username']
        session['user_id'] = user['id']
        session['plan'] = user['plan']
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
@rate_limit
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and user['password_hash'] == hashlib.sha256(password.encode()).hexdigest():
            session['logged_in'] = True
            session['username'] = user['username']
            session['user_id'] = user['id']
            session['plan'] = user['plan']
            db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
            db.commit()
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'error')
    return render_template('login.html', demo_mode=DEMO_MODE)

@app.route('/signup', methods=['GET', 'POST'])
@rate_limit
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')

        if password != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('signup'))
        if len(password) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('signup'))

        try:
            db = get_db()
            db.execute('INSERT INTO users (username, email, password_hash, plan) VALUES (?,?,?,?)',
                       (username, email, hashlib.sha256(password.encode()).hexdigest(), 'free'))
            db.commit()
            user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            session['logged_in'] = True
            session['username'] = username
            session['user_id'] = user['id']
            session['plan'] = 'free'
            flash('Account created! Welcome!', 'success')
            return redirect(url_for('dashboard'))
        except sqlite3.IntegrityError:
            flash('Username or email already exists.', 'error')
    return render_template('signup.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'success')
    return redirect(url_for('index'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current = request.form.get('current_password', '')
        new_pass = request.form.get('new_password', '')
        confirm = request.form.get('confirm_password', '')
        if new_pass != confirm:
            flash('Passwords do not match.', 'error')
            return redirect(url_for('change_password'))
        if len(new_pass) < 6:
            flash('Password must be at least 6 characters.', 'error')
            return redirect(url_for('change_password'))
        db = get_db()
        user = db.execute('SELECT password_hash FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        if user['password_hash'] != hashlib.sha256(current.encode()).hexdigest():
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('change_password'))
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                   (hashlib.sha256(new_pass.encode()).hexdigest(), session['user_id']))
        db.commit()
        flash('Password changed!', 'success')
        return redirect(url_for('dashboard'))
    return render_template('change_password.html')

# ==================== DASHBOARD ====================

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    keys = db.execute('SELECT * FROM api_keys WHERE user_id = ? ORDER BY created_at DESC',
                      (session['user_id'],)).fetchall()
    user = get_current_user()
    limit = PLAN_LIMITS.get(user['plan'], PLAN_LIMITS['free'])['keys']
    return render_template('index.html', keys=keys, providers=PROVIDERS, user=user,
                           key_limit=limit, key_count=len(keys))

# ==================== KEY MANAGEMENT ====================

@app.route('/add', methods=['GET', 'POST'])
@login_required
@rate_limit
def add_key():
    if request.method == 'POST':
        user_id = session['user_id']
        plan = session.get('plan', 'free')
        limit = PLAN_LIMITS.get(plan, PLAN_LIMITS['free'])['keys']

        if user_key_count(user_id) >= limit:
            flash(f'Key limit reached ({limit} on {plan} plan). Upgrade for more!', 'error')
            return redirect(url_for('upgrade'))

        key = request.form.get('key', '').strip()
        name = request.form.get('name', '').strip()
        category = request.form.get('category', 'ai')

        if not key:
            flash('API key is required.', 'error')
            return redirect(url_for('add_key'))

        provider = get_provider(key)
        key_hash = hash_key(key)
        key_prefix = key[:12] + '...' if len(key) > 12 else key

        try:
            db = get_db()
            db.execute('INSERT INTO api_keys (user_id, provider, name, category, key_hash, key_prefix) VALUES (?,?,?,?,?,?)',
                       (user_id, provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'),
                        category, key_hash, key_prefix))
            db.commit()
            flash('API key added!', 'success')
        except sqlite3.IntegrityError:
            flash('This key already exists.', 'error')

        return redirect(url_for('dashboard'))
    return render_template('add.html', providers=PROVIDERS)

@app.route('/delete/<int:key_id>')
@login_required
def delete_key(key_id):
    db = get_db()
    db.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (key_id, session['user_id']))
    db.commit()
    flash('API key deleted.', 'success')
    return redirect(url_for('dashboard'))

@app.route('/usage')
@login_required
def usage():
    db = get_db()
    keys = db.execute('SELECT * FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchall()
    return render_template('usage.html', keys=keys)

@app.route('/status')
@login_required
def key_status():
    db = get_db()
    keys = db.execute('SELECT * FROM api_keys WHERE user_id = ?', (session['user_id'],)).fetchall()
    status_list = [{'id': k['id'], 'provider': k['provider'], 'name': k['name'], 'status': 'active'} for k in keys]
    return jsonify({'success': True, 'keys': status_list})

# ==================== UPGRADE / BILLING ====================

@app.route('/upgrade')
@login_required
def upgrade():
    user = get_current_user()
    return render_template('upgrade.html', current_plan=user['plan'])

STRIPE_SECRET_KEY = os.environ.get('STRIPE_SECRET_KEY', '')
STRIPE_PRICE_ID = os.environ.get('STRIPE_PRICE_ID', '')
STRIPE_WEBHOOK_SECRET = os.environ.get('STRIPE_WEBHOOK_SECRET', '')
stripe_enabled = bool(STRIPE_SECRET_KEY and STRIPE_SECRET_KEY.startswith('sk_'))

if stripe_enabled:
    import stripe
    stripe.api_key = STRIPE_SECRET_KEY

@app.route('/create-checkout-session', methods=['POST'])
@login_required
def create_checkout_session():
    if not stripe_enabled:
        return jsonify({'error': 'Stripe not configured'}), 400
    user = get_current_user()
    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=user['email'],
            payment_method_types=['card'],
            line_items=[{'price': STRIPE_PRICE_ID, 'quantity': 1}],
            mode='subscription',
            success_url=request.host_url + 'dashboard?upgraded=1',
            cancel_url=request.host_url + 'upgrade',
            metadata={'user_id': user['id']}
        )
        return jsonify({'url': checkout_session.url})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/webhook', methods=['POST'])
def stripe_webhook():
    if not stripe_enabled:
        return jsonify({'error': 'Stripe not configured'}), 400
    payload = request.data
    sig_header = request.headers.get('stripe-signature')
    try:
        event = stripe.Webhook.construct_event(payload, sig_header, STRIPE_WEBHOOK_SECRET)
        if event['type'] == 'checkout.session.completed':
            obj = event['data']['object']
            user_id = obj.get('metadata', {}).get('user_id')
            customer_id = obj.get('customer')
            if user_id:
                db = get_db()
                db.execute("UPDATE users SET plan='pro', stripe_customer_id=? WHERE id=?", (customer_id, user_id))
                db.commit()
        elif event['type'] == 'customer.subscription.deleted':
            customer_id = event['data']['object'].get('customer')
            if customer_id:
                db = get_db()
                db.execute("UPDATE users SET plan='free' WHERE stripe_customer_id=?", (customer_id,))
                db.commit()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

# ==================== SETTINGS ====================

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        # Forward to add_key for convenience
        return redirect(url_for('add_key'))
    return render_template('settings.html')

# ==================== REST API ====================

def validate_api_token(token):
    """Validate Bearer token, return user_id or None."""
    if not token:
        return None
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db = get_db()
    row = db.execute(
        'SELECT user_id FROM api_tokens WHERE token_hash = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)',
        (token_hash,)
    ).fetchone()
    return row['user_id'] if row else None

def require_api_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return jsonify({'error': 'Authorization header required'}), 401
        user_id = validate_api_token(auth[7:])
        if not user_id:
            return jsonify({'error': 'Invalid or expired token'}), 401
        g.api_user_id = user_id
        return f(*args, **kwargs)
    return decorated

@app.route('/api/token', methods=['POST'])
@rate_limit
def api_create_token():
    data = request.get_json() or {}
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    if not user or user['password_hash'] != hashlib.sha256(password.encode()).hexdigest():
        return jsonify({'error': 'Invalid credentials'}), 401
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    db.execute('INSERT INTO api_tokens (user_id, token_hash) VALUES (?,?)', (user['id'], token_hash))
    db.commit()
    return jsonify({'success': True, 'api_token': token,
                    'message': 'Use in Authorization header: Bearer YOUR_TOKEN'})

@app.route('/api/keys', methods=['GET'])
@rate_limit
@require_api_token
def api_list_keys():
    keys = get_db().execute(
        'SELECT id, provider, name, category, key_prefix, created_at FROM api_keys WHERE user_id = ?',
        (g.api_user_id,)
    ).fetchall()
    return jsonify({'success': True, 'keys': [dict(k) for k in keys]})

@app.route('/api/keys', methods=['POST'])
@rate_limit
@require_api_token
def api_add_key():
    plan = get_db().execute('SELECT plan FROM users WHERE id = ?', (g.api_user_id,)).fetchone()['plan']
    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS['free'])['keys']
    if user_key_count(g.api_user_id) >= limit:
        return jsonify({'error': f'Key limit reached ({limit} on {plan} plan)'}), 403

    data = request.get_json() or {}
    key = data.get('key', '').strip()
    name = data.get('name', '').strip()
    category = data.get('category', 'ai')
    if not key:
        return jsonify({'error': 'API key is required'}), 400

    provider = get_provider(key)
    key_hash = hash_key(key)
    key_prefix = key[:12] + '...' if len(key) > 12 else key
    try:
        db = get_db()
        db.execute('INSERT INTO api_keys (user_id, provider, name, category, key_hash, key_prefix) VALUES (?,?,?,?,?,?)',
                   (g.api_user_id, provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'),
                    category, key_hash, key_prefix))
        db.commit()
        return jsonify({'success': True, 'provider': provider})
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Key already exists'}), 400

@app.route('/api/keys/<int:key_id>', methods=['DELETE'])
@rate_limit
@require_api_token
def api_delete_key(key_id):
    db = get_db()
    db.execute('DELETE FROM api_keys WHERE id = ? AND user_id = ?', (key_id, g.api_user_id))
    db.commit()
    return jsonify({'success': True})

@app.route('/api/quick-add', methods=['POST'])
@login_required
def quick_add_key():
    user_id = session['user_id']
    plan = session.get('plan', 'free')
    limit = PLAN_LIMITS.get(plan, PLAN_LIMITS['free'])['keys']
    if user_key_count(user_id) >= limit:
        return jsonify({'success': False, 'error': f'Key limit reached on {plan} plan'}), 403

    data = request.get_json() or {}
    key = data.get('key', '').strip()
    name = data.get('name', '').strip()
    category = data.get('category', 'ai')
    provider = data.get('provider') or get_provider(key)

    if not key:
        return jsonify({'success': False, 'error': 'Key required'}), 400

    key_hash = hash_key(key)
    key_prefix = key[:12] + '...' if len(key) > 12 else key
    try:
        db = get_db()
        db.execute('INSERT INTO api_keys (user_id, provider, name, category, key_hash, key_prefix) VALUES (?,?,?,?,?,?)',
                   (user_id, provider, name or PROVIDERS.get(provider, {}).get('name', 'Unknown'),
                    category, key_hash, key_prefix))
        db.commit()
        return jsonify({'success': True, 'provider': provider})
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'error': 'Key already exists'}), 400

@app.route('/health')
def health():
    return 'ok', 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
