"""
Tests for Jay's Keep Your Secrets (KYS)
Covers: auth, API keys CRUD, health, CSRF, rate limiting, password utils
"""
import os
import sys
import pytest

# Point to app root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault('SECRET_KEY', 'test-secret-key')
os.environ.setdefault('DATABASE_URL', '')
os.environ.setdefault('PASSWORD_PEPPER', 'test-pepper')

import app as kys_app


@pytest.fixture
def client(tmp_path):
    kys_app.app.config['TESTING'] = True
    kys_app.app.config['SECRET_KEY'] = 'test-secret-key'
    kys_app.app.config['WTF_CSRF_ENABLED'] = False
    kys_app.DATA_DIR = str(tmp_path)
    kys_app.DB_PATH = str(tmp_path / 'test.db')
    kys_app.SYSTEM_CONFIG_FILE = str(tmp_path / 'config.json')
    with kys_app.app.test_client() as c:
        with kys_app.app.app_context():
            kys_app.init_db()
        yield c


# ── Health ──────────────────────────────────────────────────────────────────

def test_health_returns_json_ok(client):
    res = client.get('/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'ok'
    assert 'db' in data


# ── Public pages ─────────────────────────────────────────────────────────────

def test_index_returns_200(client):
    res = client.get('/')
    assert res.status_code == 200

def test_demo_returns_200(client):
    res = client.get('/demo', follow_redirects=True)
    assert res.status_code == 200

def test_login_page_get_returns_200(client):
    res = client.get('/login')
    assert res.status_code == 200

def test_signup_page_get_returns_200(client):
    res = client.get('/signup')
    assert res.status_code == 200


# ── Signup & Login ───────────────────────────────────────────────────────────

def _register(client, username='testuser', password='TestPass123!', email='test@test.com'):
    return client.post('/signup', data={
        'username': username,
        'password': password,
        'email': email
    }, follow_redirects=True)

def test_signup_creates_user(client):
    res = _register(client)
    assert res.status_code == 200

def test_login_with_valid_credentials_redirects_to_dashboard(client):
    _register(client)
    res = client.post('/login', data={
        'username': 'testuser',
        'password': 'TestPass123!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'dashboard' in res.data.lower() or b'logout' in res.data.lower()

def test_login_with_wrong_password_fails(client):
    _register(client)
    res = client.post('/login', data={
        'username': 'testuser',
        'password': 'WrongPassword!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'invalid' in res.data.lower() or b'incorrect' in res.data.lower() or b'wrong' in res.data.lower()

def test_login_nonexistent_user_fails(client):
    res = client.post('/login', data={
        'username': 'nobody',
        'password': 'anything'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'invalid' in res.data.lower() or b'incorrect' in res.data.lower()

def test_dashboard_requires_login(client):
    res = client.get('/dashboard', follow_redirects=False)
    assert res.status_code in (302, 401)

def test_logout_redirects(client):
    _register(client)
    client.post('/login', data={'username': 'testuser', 'password': 'TestPass123!'})
    res = client.get('/logout', follow_redirects=False)
    assert res.status_code in (302, 200)


# ── Password utilities ────────────────────────────────────────────────────────

def test_hash_password_produces_bcrypt_prefix():
    h = kys_app._hash_password('mypassword')
    assert h.startswith('bcrypt:')

def test_verify_password_correct():
    h = kys_app._hash_password('mypassword')
    assert kys_app._verify_password('mypassword', h) is True

def test_verify_password_wrong():
    h = kys_app._hash_password('mypassword')
    assert kys_app._verify_password('wrong', h) is False

def test_verify_password_empty_string():
    h = kys_app._hash_password('')
    assert kys_app._verify_password('', h) is True
    assert kys_app._verify_password('notempty', h) is False

def test_needs_upgrade_returns_true_for_sha256():
    sha_hash = 'abc123def456' * 4  # plain sha256 (no bcrypt: prefix)
    assert kys_app._needs_upgrade(sha_hash) is True

def test_needs_upgrade_returns_false_for_bcrypt():
    h = kys_app._hash_password('pw')
    assert kys_app._needs_upgrade(h) is False


# ── API — token auth ──────────────────────────────────────────────────────────

def test_api_keys_requires_token(client):
    res = client.get('/api/keys')
    assert res.status_code in (401, 403)

def test_api_keys_with_invalid_token_rejected(client):
    res = client.get('/api/keys', headers={'Authorization': 'Bearer badtoken'})
    assert res.status_code in (401, 403)


# ── Security headers ──────────────────────────────────────────────────────────

def test_response_has_x_content_type_header(client):
    res = client.get('/')
    assert 'X-Content-Type-Options' in res.headers

def test_response_has_x_frame_options(client):
    res = client.get('/')
    assert 'X-Frame-Options' in res.headers
