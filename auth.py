import secrets
import string
import bcrypt
from database import (
    get_db, get_setting, get_user_by_username, get_user_by_id,
    log_event,
)
from key_manager import create_key, verify_key


def hash_password(plaintext):
    return bcrypt.hashpw(plaintext.encode('utf-8'), bcrypt.gensalt(rounds=12))


def verify_password(plaintext, hashed):
    if isinstance(hashed, str):
        hashed = hashed.encode('utf-8')
    return bcrypt.checkpw(plaintext.encode('utf-8'), hashed)


def generate_token_c():
    return secrets.token_hex(16)


def generate_dummy_password_a(length=12):
    """Generate a random one-time dummy Password A for new users."""
    alphabet = string.ascii_letters + string.digits + '!@#$%'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def create_user(username, email, password_b, is_admin=False):
    """
    Create a new user with a dummy Password A and SHA-256 hashed Password B.

    Returns dict with keys: token_c, dummy_password_a
    """
    db = get_db()

    # Generate dummy one-time Password A
    dummy_password_a = generate_dummy_password_a()
    a_hash = hash_password(dummy_password_a).decode('utf-8')

    # Hash Password B with SHA-256 via key_manager
    b_key, b_salt = create_key(password_b)

    token_c = generate_token_c()

    db.execute(
        """INSERT INTO users
           (username, email, password_a_hash, password_b_key, password_b_salt,
            token_c, is_admin, is_first_login)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1)""",
        (username, email, a_hash, b_key, b_salt, token_c, 1 if is_admin else 0),
    )
    db.commit()

    user = get_user_by_username(username)

    # Log a ticket event for admin dashboard
    log_event(
        user['id'], 'USER_CREATED',
        f'New user account created: {username} ({email})',
    )

    return {'token_c': token_c, 'dummy_password_a': dummy_password_a}


def verify_password_a(username, password_a, ip_address=None):
    user = get_user_by_username(username)

    if user is None:
        return {'success': False, 'error': 'Invalid credentials'}

    if user['is_locked']:
        return {'success': False, 'locked': True,
                'error': 'Account is locked. Contact your administrator with your recovery token.'}

    # Check for dummy password reuse after first login change
    if not user['is_first_login'] and user['dummy_password_hash']:
        if verify_password(password_a, user['dummy_password_hash']):
            log_event(user['id'], 'DUMMY_REUSE',
                      'Attempted login with expired dummy password - possible credential leak',
                      ip_address)
            return {
                'success': False,
                'error': 'Invalid credentials',
                'notify': True,
                'user_id': user['id'],
                'event_type': 'DUMMY_REUSE',
            }

    if verify_password(password_a, user['password_a_hash']):
        db = get_db()
        db.execute("UPDATE users SET failed_a_count = 0, updated_at = datetime('now') WHERE id = ?", (user['id'],))
        db.commit()
        return {
            'success': True,
            'requires_b': True,
            'user_id': user['id'],
            'is_first_login': bool(user['is_first_login']),
        }

    # Password A failed
    db = get_db()
    new_count = user['failed_a_count'] + 1
    max_attempts = int(get_setting('max_failed_a_attempts') or 5)

    if new_count >= max_attempts:
        db.execute(
            "UPDATE users SET failed_a_count = ?, is_locked = 1, updated_at = datetime('now') WHERE id = ?",
            (new_count, user['id']),
        )
        db.commit()
        log_event(user['id'], 'A_LOCKOUT',
                  f"Account locked after {new_count} failed Password A attempts",
                  ip_address)
        return {
            'success': False,
            'locked': True,
            'error': 'Account locked due to too many failed attempts. Contact your administrator.',
            'notify': True,
            'user_id': user['id'],
            'event_type': 'A_LOCKOUT',
        }
    else:
        db.execute(
            "UPDATE users SET failed_a_count = ?, updated_at = datetime('now') WHERE id = ?",
            (new_count, user['id']),
        )
        db.commit()
        log_event(user['id'], 'A_FAIL',
                  f"Password A failed (attempt {new_count}/{max_attempts})",
                  ip_address)
        remaining = max_attempts - new_count
        return {
            'success': False,
            'error': 'Invalid credentials',
            'remaining': remaining,
        }


def verify_password_b(user_id, password_b, ip_address=None):
    user = get_user_by_id(user_id)

    if user is None:
        return {'success': False, 'error': 'Session expired. Please start over.'}

    if verify_key(password_b, user['password_b_key'], user['password_b_salt']):
        # Success - reset failed_b_count
        db = get_db()
        db.execute(
            "UPDATE users SET failed_b_count = 0, updated_at = datetime('now') WHERE id = ?",
            (user['id'],),
        )
        db.commit()
        log_event(user['id'], 'LOGIN_SUCCESS', 'Successful two-factor login', ip_address)
        return {
            'success': True,
            'user_id': user['id'],
            'is_admin': bool(user['is_admin']),
            'is_first_login': bool(user['is_first_login']),
        }

    # Password B failed
    db = get_db()
    new_b_count = user['failed_b_count'] + 1
    max_b_attempts = int(get_setting('max_failed_b_attempts') or 3)

    db.execute(
        "UPDATE users SET failed_b_count = ?, updated_at = datetime('now') WHERE id = ?",
        (new_b_count, user['id']),
    )
    db.commit()

    log_event(
        user['id'], 'B_FAIL',
        f'Password B verification failed (attempt {new_b_count}/{max_b_attempts})',
        ip_address,
    )

    # Notify only after reaching the threshold
    should_notify = new_b_count >= max_b_attempts
    if should_notify:
        db.execute(
            "UPDATE users SET failed_b_count = 0, updated_at = datetime('now') WHERE id = ?",
            (user['id'],),
        )
        db.commit()

    return {
        'success': False,
        'error': 'Verification failed.' + (' Security alert has been triggered.' if should_notify else ''),
        'notify': should_notify,
        'user_id': user['id'],
        'event_type': 'B_FAIL',
    }


def change_first_login_password(user_id, new_password_a):
    """
    Change Password A for a first-login user. Stores old dummy hash for reuse detection.
    """
    user = get_user_by_id(user_id)
    if user is None:
        return {'success': False, 'error': 'User not found'}
    if not user['is_first_login']:
        return {'success': False, 'error': 'Password change not required'}

    db = get_db()
    # Save old dummy password hash for reuse detection
    old_hash = user['password_a_hash']
    new_hash = hash_password(new_password_a).decode('utf-8')

    db.execute(
        """UPDATE users SET password_a_hash = ?, dummy_password_hash = ?,
           is_first_login = 0, updated_at = datetime('now') WHERE id = ?""",
        (new_hash, old_hash, user_id),
    )
    db.commit()
    log_event(user_id, 'PASSWORD_CHANGED', 'User changed Password A after first login')
    return {'success': True}


def verify_token_c(user_id, provided_token):
    user = get_user_by_id(user_id)
    if user is None:
        return False
    return secrets.compare_digest(user['token_c'], provided_token)


def reset_user(user_id, new_password_a, new_password_b):
    db = get_db()
    a_hash = hash_password(new_password_a).decode('utf-8')
    b_key, b_salt = create_key(new_password_b)
    new_token_c = generate_token_c()

    db.execute(
        """UPDATE users
           SET password_a_hash = ?, password_b_key = ?, password_b_salt = ?,
               token_c = ?, is_locked = 0, failed_a_count = 0, failed_b_count = 0,
               is_first_login = 0, dummy_password_hash = NULL,
               updated_at = datetime('now')
           WHERE id = ?""",
        (a_hash, b_key, b_salt, new_token_c, user_id),
    )
    db.commit()
    log_event(user_id, 'PASSWORD_RESET',
              'Passwords A and B reset by administrator. New Token C generated.')
    return new_token_c
