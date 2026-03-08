import re
import click
from functools import wraps
from flask import (
    Flask, request, session, jsonify, redirect, url_for, render_template,
)
from config import Config
from database import (
    get_db, close_db, init_db, get_setting, set_setting,
    get_user_by_id, get_user_by_username, log_event,
    get_pending_tickets, acknowledge_ticket,
)
from auth import (
    create_user, verify_password_a, verify_password_b,
    verify_token_c, reset_user, change_first_login_password,
    hash_password,
)
from notifications import send_security_alert

app = Flask(__name__)
app.config.from_object(Config)
app.teardown_appcontext(close_db)


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------

@app.cli.command('init-db')
def init_db_command():
    init_db()
    click.echo('Database initialized.')


@app.cli.command('seed-admin')
@click.option('--username', default='admin', help='Admin username')
@click.option('--email', default='admin@tripleauth.local', help='Admin email')
@click.option('--password-a', default='admin123', help='Admin Password A')
@click.option('--password-b', default='verify456', help='Admin Password B')
def seed_admin_command(username, email, password_a, password_b):
    init_db()
    try:
        result = create_user(username, email, password_b, is_admin=True)
        # Override dummy password with specified password, clear first-login flag
        db = get_db()
        a_hash = hash_password(password_a).decode('utf-8')
        user = get_user_by_username(username)
        db.execute(
            "UPDATE users SET password_a_hash = ?, is_first_login = 0 WHERE id = ?",
            (a_hash, user['id']),
        )
        db.commit()
        click.echo(f'Admin user created successfully!')
        click.echo(f'  Username:   {username}')
        click.echo(f'  Password A: {password_a}')
        click.echo(f'  Password B: {password_b}')
        click.echo(f'  Token C:    {result["token_c"]}')
    except Exception as e:
        click.echo(f'Error: {e}')


# ---------------------------------------------------------------------------
# Decorators
# ---------------------------------------------------------------------------

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('is_admin'):
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{1,50}$')


def validate_username(username):
    return bool(USERNAME_RE.match(username))


# ---------------------------------------------------------------------------
# Public routes
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    return redirect(url_for('login'))


@app.route('/login')
def login():
    return render_template('login.html')


@app.route('/locked')
def locked():
    return render_template('locked.html')


@app.route('/api/auth/verify-a', methods=['POST'])
def api_verify_a():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password_a = data.get('password_a', '')

    if not username or not password_a:
        return jsonify({'success': False, 'error': 'Username and password are required'}), 400

    ip = request.remote_addr
    result = verify_password_a(username, password_a, ip)

    if result.get('success'):
        session['pending_user_id'] = result['user_id']
        session['is_first_login'] = result.get('is_first_login', False)
        session.permanent = True
        return jsonify({
            'success': True,
            'requires_b': True,
            'is_first_login': result.get('is_first_login', False),
        })

    if result.get('notify'):
        send_security_alert(result['user_id'], result['event_type'])

    status = 423 if result.get('locked') else 401
    return jsonify({
        'success': False,
        'error': result['error'],
        'locked': result.get('locked', False),
    }), status


@app.route('/api/auth/verify-b', methods=['POST'])
def api_verify_b():
    pending = session.get('pending_user_id')
    if not pending:
        return jsonify({'success': False, 'error': 'Session expired. Please start over.'}), 401

    data = request.get_json(silent=True) or {}
    password_b = data.get('password_b', '')

    if not password_b:
        return jsonify({'success': False, 'error': 'Verification password is required'}), 400

    ip = request.remote_addr
    result = verify_password_b(pending, password_b, ip)

    if result.get('success'):
        session.pop('pending_user_id', None)
        session['user_id'] = result['user_id']
        session['is_admin'] = result.get('is_admin', False)

        # Check if first login - redirect to password change
        if result.get('is_first_login'):
            session['must_change_password'] = True
            return jsonify({'success': True, 'redirect': '/change-password'})

        return jsonify({'success': True, 'redirect': '/home'})

    # B failed - kill session
    session.pop('pending_user_id', None)
    if result.get('notify'):
        send_security_alert(result['user_id'], result['event_type'])

    return jsonify({'success': False, 'error': result['error']}), 401


@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    session.clear()
    return jsonify({'success': True, 'redirect': '/login'})


# ---------------------------------------------------------------------------
# First-login password change
# ---------------------------------------------------------------------------

@app.route('/change-password')
@login_required
def change_password_page():
    if not session.get('must_change_password'):
        return redirect(url_for('home'))
    return render_template('change_password.html')


@app.route('/api/auth/change-password', methods=['POST'])
@login_required
def api_change_password():
    if not session.get('must_change_password'):
        return jsonify({'success': False, 'error': 'Password change not required'}), 400

    data = request.get_json(silent=True) or {}
    new_password_a = data.get('new_password_a', '')

    if not new_password_a or len(new_password_a) < 8:
        return jsonify({'success': False, 'error': 'New password must be at least 8 characters'}), 400

    result = change_first_login_password(session['user_id'], new_password_a)
    if result['success']:
        session.pop('must_change_password', None)
        return jsonify({'success': True, 'redirect': '/home'})

    return jsonify(result), 400


# ---------------------------------------------------------------------------
# Authenticated user routes
# ---------------------------------------------------------------------------

@app.route('/home')
@login_required
def home():
    if session.get('must_change_password'):
        return redirect(url_for('change_password_page'))
    user = get_user_by_id(session['user_id'])
    return render_template('home.html', user=user)


# ---------------------------------------------------------------------------
# Admin routes
# ---------------------------------------------------------------------------

@app.route('/admin/login')
def admin_login():
    return render_template('admin_login.html')


@app.route('/api/admin/login', methods=['POST'])
def api_admin_login():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    password_a = data.get('password_a', '')
    password_b = data.get('password_b', '')

    if not username or not password_a or not password_b:
        return jsonify({'success': False, 'error': 'All fields are required'}), 400

    ip = request.remote_addr

    # Verify A
    result_a = verify_password_a(username, password_a, ip)
    if not result_a.get('success'):
        if result_a.get('notify'):
            send_security_alert(result_a['user_id'], result_a['event_type'])
        return jsonify({'success': False, 'error': result_a['error'], 'locked': result_a.get('locked', False)}), 401

    # Verify B
    result_b = verify_password_b(result_a['user_id'], password_b, ip)
    if not result_b.get('success'):
        if result_b.get('notify'):
            send_security_alert(result_b['user_id'], result_b['event_type'])
        return jsonify({'success': False, 'error': result_b['error']}), 401

    # Check admin flag
    user = get_user_by_id(result_b['user_id'])
    if not user['is_admin']:
        return jsonify({'success': False, 'error': 'Access denied'}), 403

    session['user_id'] = user['id']
    session['is_admin'] = True
    session.permanent = True
    return jsonify({'success': True, 'redirect': '/admin/dashboard'})


@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    return render_template('admin_dashboard.html')


@app.route('/api/admin/users')
@admin_required
def api_admin_users():
    db = get_db()
    rows = db.execute(
        """SELECT id, username, email, is_locked, failed_a_count, failed_b_count,
                  is_first_login, is_admin, created_at
           FROM users ORDER BY created_at DESC"""
    ).fetchall()
    users = [dict(r) for r in rows]
    return jsonify(users)


@app.route('/api/admin/events')
@admin_required
def api_admin_events():
    db = get_db()
    page = max(1, request.args.get('page', 1, type=int))
    per_page = min(100, request.args.get('per_page', 50, type=int))
    user_id = request.args.get('user_id', type=int)
    event_type = request.args.get('event_type', '')

    query = """
        SELECT e.*, u.username
        FROM security_events e
        JOIN users u ON u.id = e.user_id
        WHERE 1=1
    """
    params = []

    if user_id:
        query += " AND e.user_id = ?"
        params.append(user_id)
    if event_type:
        query += " AND e.event_type = ?"
        params.append(event_type)

    query += " ORDER BY e.created_at DESC LIMIT ? OFFSET ?"
    params.extend([per_page, (page - 1) * per_page])

    rows = db.execute(query, params).fetchall()
    events = [dict(r) for r in rows]
    return jsonify(events)


@app.route('/api/admin/verify-token', methods=['POST'])
@admin_required
def api_admin_verify_token():
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    token = data.get('token_c', '').strip()

    if not user_id or not token:
        return jsonify({'valid': False, 'error': 'User ID and token are required'}), 400

    valid = verify_token_c(user_id, token)
    if valid:
        log_event(user_id, 'RECOVERY', 'Token C verified by administrator')
    return jsonify({'valid': valid})


@app.route('/api/admin/reset-user', methods=['POST'])
@admin_required
def api_admin_reset_user():
    data = request.get_json(silent=True) or {}
    user_id = data.get('user_id')
    new_a = data.get('new_password_a', '')
    new_b = data.get('new_password_b', '')

    if not user_id or not new_a or not new_b:
        return jsonify({'success': False, 'error': 'All fields are required'}), 400
    if len(new_a) < 8:
        return jsonify({'success': False, 'error': 'Password A must be at least 8 characters'}), 400

    new_token_c = reset_user(user_id, new_a, new_b)
    return jsonify({'success': True, 'new_token_c': new_token_c})


@app.route('/api/admin/create-user', methods=['POST'])
@admin_required
def api_admin_create_user():
    data = request.get_json(silent=True) or {}
    username = data.get('username', '').strip()
    email = data.get('email', '').strip()
    password_b = data.get('password_b', '')

    if not username or not email or not password_b:
        return jsonify({'success': False, 'error': 'Username, email, and Password B are required'}), 400
    if not validate_username(username):
        return jsonify({'success': False, 'error': 'Username must be alphanumeric/underscore, max 50 chars'}), 400

    try:
        result = create_user(username, email, password_b)
        return jsonify({
            'success': True,
            'token_c': result['token_c'],
            'dummy_password_a': result['dummy_password_a'],
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 409


# ---------------------------------------------------------------------------
# Ticket endpoints
# ---------------------------------------------------------------------------

@app.route('/api/admin/tickets')
@admin_required
def api_admin_tickets():
    tickets = get_pending_tickets()
    return jsonify(tickets)


@app.route('/api/admin/tickets/<int:event_id>/acknowledge', methods=['POST'])
@admin_required
def api_admin_acknowledge_ticket(event_id):
    acknowledge_ticket(event_id)
    return jsonify({'success': True})


# ---------------------------------------------------------------------------
# Admin settings
# ---------------------------------------------------------------------------

@app.route('/api/admin/settings', methods=['GET'])
@admin_required
def api_admin_get_settings():
    db = get_db()
    rows = db.execute("SELECT key, value FROM settings").fetchall()
    settings = {}
    for r in rows:
        val = r['value']
        if r['key'] == 'smtp_password' and val:
            val = '*' * 8  # mask
        settings[r['key']] = val
    return jsonify(settings)


@app.route('/api/admin/settings', methods=['POST'])
@admin_required
def api_admin_update_settings():
    data = request.get_json(silent=True) or {}
    allowed_keys = {
        'max_failed_a_attempts', 'max_failed_b_attempts',
        'smtp_server', 'smtp_port',
        'smtp_username', 'smtp_password', 'smtp_from_email',
        'smtp_enabled', 'admin_email',
    }
    for key, value in data.items():
        if key in allowed_keys:
            if key == 'smtp_password' and value == '*' * 8:
                continue  # don't overwrite with mask
            set_setting(key, str(value))
    return jsonify({'success': True})


@app.route('/api/admin/logout', methods=['POST'])
@admin_required
def api_admin_logout():
    session.clear()
    return jsonify({'success': True, 'redirect': '/admin/login'})


# ---------------------------------------------------------------------------
# Error handlers
# ---------------------------------------------------------------------------

@app.errorhandler(404)
def not_found(e):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)
