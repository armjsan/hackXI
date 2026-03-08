import sqlite3
from flask import g, current_app


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(current_app.config['DATABASE'])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript("""
        DROP TABLE IF EXISTS security_events;
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS settings;

        CREATE TABLE users (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            username            TEXT    NOT NULL UNIQUE,
            email               TEXT    NOT NULL,
            password_a_hash     TEXT    NOT NULL,
            password_b_key      TEXT    NOT NULL,
            password_b_salt     TEXT    NOT NULL,
            token_c             TEXT    NOT NULL,
            is_locked           INTEGER NOT NULL DEFAULT 0,
            failed_a_count      INTEGER NOT NULL DEFAULT 0,
            failed_b_count      INTEGER NOT NULL DEFAULT 0,
            is_first_login      INTEGER NOT NULL DEFAULT 1,
            dummy_password_hash TEXT,
            is_admin            INTEGER NOT NULL DEFAULT 0,
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at          TEXT    NOT NULL DEFAULT (datetime('now'))
        );

        CREATE TABLE security_events (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL,
            event_type  TEXT    NOT NULL,
            description TEXT    NOT NULL,
            ip_address  TEXT,
            notified    INTEGER NOT NULL DEFAULT 0,
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            FOREIGN KEY (user_id) REFERENCES users(id)
        );

        CREATE TABLE settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    """)

    # Seed default settings
    defaults = {
        'max_failed_a_attempts': '5',
        'max_failed_b_attempts': '3',
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': '587',
        'smtp_username': '',
        'smtp_password': '',
        'smtp_from_email': '',
        'smtp_enabled': 'false',
        'admin_email': '',
    }
    for key, value in defaults.items():
        db.execute(
            "INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)",
            (key, value),
        )
    db.commit()


def get_setting(key):
    db = get_db()
    row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row['value'] if row else None


def set_setting(key, value):
    db = get_db()
    db.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?",
        (key, value, value),
    )
    db.commit()


def log_event(user_id, event_type, description, ip_address=None):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO security_events (user_id, event_type, description, ip_address) VALUES (?, ?, ?, ?)",
        (user_id, event_type, description, ip_address),
    )
    db.commit()
    return cursor.lastrowid


def mark_event_notified(event_id):
    db = get_db()
    db.execute("UPDATE security_events SET notified = 1 WHERE id = ?", (event_id,))
    db.commit()


def get_user_by_username(username):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()


def get_user_by_id(user_id):
    db = get_db()
    return db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()


def get_pending_tickets():
    db = get_db()
    rows = db.execute("""
        SELECT e.*, u.username, u.email
        FROM security_events e
        JOIN users u ON u.id = e.user_id
        WHERE e.event_type = 'USER_CREATED' AND e.notified = 0
        ORDER BY e.created_at DESC
    """).fetchall()
    return [dict(r) for r in rows]


def acknowledge_ticket(event_id):
    db = get_db()
    db.execute(
        "UPDATE security_events SET notified = 1 WHERE id = ? AND event_type = 'USER_CREATED'",
        (event_id,),
    )
    db.commit()
