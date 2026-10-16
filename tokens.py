import hashlib
import secrets
import sqlite3
import time

from config import DB_PATH, TOKEN_LIFETIME_DAYS


def hash_token(token):
    """SHA-256 fingerprint of a token. Only this is ever stored, never the token itself."""
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def create_token(username):
    """
    Makes a new random token for this user, replacing any old one.
    Returns the real token — the only time it exists outside the client.
    """
    token = secrets.token_urlsafe(32)
    expires_at = time.time() + TOKEN_LIFETIME_DAYS * 24 * 3600

    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM tokens WHERE username = ?", (username,))
        conn.execute(
            "INSERT INTO tokens (token_hash, username, expires_at) VALUES (?, ?, ?)",
            (hash_token(token), username, expires_at)
        )
        conn.commit()

    return token


def validate_token(token):
    """
    Returns the username this token belongs to, or None if it's unknown or expired.
    An expired token is deleted on the spot.
    """
    token_hash = hash_token(token)

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT username, expires_at FROM tokens WHERE token_hash = ?",
            (token_hash,)
        ).fetchone()

        if row is None:
            return None

        username, expires_at = row
        if expires_at <= time.time():
            conn.execute("DELETE FROM tokens WHERE token_hash = ?", (token_hash,))
            conn.commit()
            return None

    return username


def delete_token(username):
    """Deletes this user's token (used by logout). Safe to call if they have none."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM tokens WHERE username = ?", (username,))
        conn.commit()
