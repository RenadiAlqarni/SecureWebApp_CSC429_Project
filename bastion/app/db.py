"""
Database layer (SQLite, no ORM).

An ORM would hide the difference between a string-built query and a
parameterized one, so this project uses the sqlite3 module directly:

    query()/execute()                -> SECURE: SQL text and values travel
                                        separately; values are never parsed as SQL.
    query_unsafe()/execute_unsafe()  -> VULNERABLE: the caller has already glued
                                        user input into the SQL string. Only used
                                        by the vulnerable code paths in models.py.
"""
import os
import sqlite3

from flask import current_app, flash, g, has_request_context

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,          -- MD5 (vulnerable) or bcrypt (secure)
    full_name     TEXT,
    email         TEXT,                   -- Fernet-encrypted in secure mode
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    last_login    TEXT
);

CREATE TABLE IF NOT EXISTS comments (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body       TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Server-side session registry (secure mode). Only a SHA-256 of the session id
-- is stored, so a leaked database cannot be replayed as live sessions.
CREATE TABLE IF NOT EXISTS sessions (
    sid_hash   TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL
);
"""


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"])
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_app(app):
    app.teardown_appcontext(close_db)


def init_db(reset=False):
    """Create tables and the two demo accounts (admin + alice) if missing."""
    path = current_app.config["DATABASE"]
    if reset and os.path.exists(path):
        close_db()
        os.remove(path)

    conn = get_db()
    conn.executescript(SCHEMA)
    conn.commit()

    from . import models  # local import avoids a circular import

    admin_pw = os.environ.get("BASTION_ADMIN_PASSWORD", "Admin@2026!")
    user_pw = os.environ.get("BASTION_USER_PASSWORD", "Alice@2026!")
    models.seed_user("admin", admin_pw, "Site Administrator", "admin@bastion.local", "admin")
    models.seed_user("alice", user_pw, "Alice Example", "alice@bastion.local", "user")


# --------------------------------------------------------------------------
# SECURE helpers: parameterized queries
# --------------------------------------------------------------------------
def query(sql, params=(), one=False, inspect=False):
    _inspect(sql, params, parameterized=True, enabled=inspect)
    cur = get_db().execute(sql, params)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute(sql, params=(), inspect=False):
    _inspect(sql, params, parameterized=True, enabled=inspect)
    conn = get_db()
    cur = conn.execute(sql, params)
    conn.commit()
    return cur


# --------------------------------------------------------------------------
# VULNERABLE helpers: the SQL string already contains user input
# --------------------------------------------------------------------------
def query_unsafe(sql, one=False, inspect=False):
    _inspect(sql, (), parameterized=False, enabled=inspect)
    cur = get_db().execute(sql)
    rows = cur.fetchall()
    return (rows[0] if rows else None) if one else rows


def execute_unsafe(sql, inspect=False):
    _inspect(sql, (), parameterized=False, enabled=inspect)
    conn = get_db()
    cur = conn.execute(sql)
    conn.commit()
    return cur


def _inspect(sql, params, parameterized, enabled):
    """Demo aid: show the executed SQL on the next page.

    Secure mode only shows the SQL *template* (with ? placeholders) and how many
    values were bound, never the values themselves.
    """
    if not (enabled and has_request_context() and current_app.config.get("SQL_INSPECTOR")):
        return
    text = " ".join(sql.split())
    if parameterized:
        flash(f"{text}\n-- {len(params)} value(s) bound separately as parameters", "sql-safe")
    else:
        flash(text, "sql-unsafe")
