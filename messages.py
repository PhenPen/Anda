import sqlite3
import time

from config import DB_PATH, MESSAGE_HISTORY_LIMIT


def record_broadcast(sender, content):
    """Saves a public room message. recipient stays NULL — that's what marks it as a broadcast."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO messages (sender, recipient, content, timestamp) "
            "VALUES (?, NULL, ?, ?)",
            (sender, content, time.time())
        )
        conn.commit()


def record_dm(sender, recipient, content):
    """Saves a private message between two specific users."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO messages (sender, recipient, content, timestamp) "
            "VALUES (?, ?, ?, ?)",
            (sender, recipient, content, time.time())
        )
        conn.commit()


def get_broadcast_history(limit=MESSAGE_HISTORY_LIMIT):
    """
    Returns the most recent public messages as (sender, content, timestamp)
    tuples, oldest first. Ordered by id (insertion order), not timestamp,
    so order is always correct even if two messages share a timestamp.
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT sender, content, timestamp FROM messages "
            "WHERE recipient IS NULL "
            "ORDER BY id DESC LIMIT ?",
            (limit,)
        ).fetchall()
    return list(reversed(rows))


def get_dm_history(username, limit=MESSAGE_HISTORY_LIMIT):
    """
    Returns the most recent DMs this specific user sent or received, as
    (sender, recipient, content, timestamp) tuples, oldest first.
    The WHERE clause is what keeps other people's DMs private — a user
    only ever gets rows where they are the sender or the recipient.
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT sender, recipient, content, timestamp FROM messages "
            "WHERE recipient IS NOT NULL AND (sender = ? OR recipient = ?) "
            "ORDER BY id DESC LIMIT ?",
            (username, username, limit)
        ).fetchall()
    return list(reversed(rows))
