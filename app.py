import os
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import hashlib

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'ai-api-tracker-secret-2026')

DB_FILE = os.path.join(os.path.dirname(__file__), 'api_keys.db')

def init_db():
    """Initialize the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        provider TEXT NOT NULL,
        name TEXT,
        key_hash TEXT UNIQUE NOT NULL,
        key_prefix TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )''')
    conn.commit()
    conn.close()

init_db()

# Provider info
PROVIDERS = {
    'anthropic': {'name': 'Anthropic (Claude)', 'prefix': 'sk-ant-', 'test_url': 'https://api.anthropic.com/v1/messages'},
    'groq': {'name': 'Groq', 'prefix': 'gsk_', 'test_url': 'https://api.groq.com/openai/v1/models'},
    'xai': {'name': 'xAI (Grok)', 'prefix': 'xai-', 'test_url': 'https://api.xai.com/v1/models'},
    'qwen': {'name': 'Qwen', 'prefix': 'sk-', 'test_url': 'https://dashscope.aliyuncs.com/api/v1/services/aigc/multimodal-generation/generation'},
    'openai': {'name': 'OpenAI', 'prefix': 'sk-', 'test_url': 'https://api.openai.com/v1/models'},
    'mistral': {'name': 'Mistral', 'prefix': 'sk-', 'test_url': 'https://api.mistral.ai/v1/models'},
    'cohere': {'name': 'Cohere', 'prefix': 'ck_', 'test_url': 'https://api.cohere.ai/v1/models'},
    'google': {'name': 'Google AI', 'prefix': 'AIza', 'test_url': 'https://aistudio.googleapis.com/v1/models'},
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

@app.route('/')
def index():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT * FROM api_keys ORDER BY created_at DESC')
    keys = c.fetchall()
    conn.close()
    return render_template('index.html', keys=keys, providers=PROVIDERS)

@app.route('/add', methods=['GET', 'POST'])
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
def delete_key(key_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
    conn.commit()
    conn.close()
    flash('API key deleted', 'success')
    return redirect(url_for('index'))

@app.route('/api/keys')
def api_keys():
    """Return keys as JSON (without exposing actual keys)."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute('SELECT id, provider, name, key_prefix, created_at FROM api_keys ORDER BY created_at DESC')
    keys = c.fetchall()
    conn.close()
    return jsonify([dict(row) for row in keys])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
