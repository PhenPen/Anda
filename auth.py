import sqlite3
import time
import bcrypt

from config import (
    DB_PATH,
    BCRYPT_ROUNDS,
    FAILED_ATTEMPT_THRESHOLD,
    DETECTION_WINDOW_MINUTES,
    LOCKOUT_DURATION_MINUTES,
    ATTEMPT_LOG_RETENTION_HOURS,
)
from logger import logger


def register_user(username, password):
    """
    Attempts to create a new account.
    Returns (success: bool, message: str).
    """
    with sqlite3.connect(DB_PATH) as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()

        if existing:
            return False, "Username already exists. Please log in instead."

        hashed = bcrypt.hashpw(
            password.encode('utf-8'),
            bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
        )
        conn.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            (username, hashed.decode('utf-8'))
        )
        conn.commit()

    logger.info(f"New user registered: {username}")
    return True, "Registration successful. You can now log in."


def record_failed_attempt(username):
    """Logs one failed login attempt for this username, both to the DB event log and the log file."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO login_attempts (username, timestamp) VALUES (?, ?)",
            (username, time.time())
        )
        conn.commit()
    logger.warning(f"Failed login attempt for username: {username}")


def get_lockout_status(username):
    """
    Returns (locked: bool, retry_after_seconds: float or None).

    Looks for any run of FAILED_ATTEMPT_THRESHOLD consecutive failed
    attempts (for this username) that all fall within
    DETECTION_WINDOW_MINUTES of each other. If such a burst exists and
    LOCKOUT_DURATION_MINUTES hasn't yet passed since the last attempt in
    that burst, the account is still locked.
    """
    now = time.time()
    lookback = now - (LOCKOUT_DURATION_MINUTES * 60)
    detection_window_seconds = DETECTION_WINDOW_MINUTES * 60

    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT timestamp FROM login_attempts "
            "WHERE username = ? AND timestamp > ? "
            "ORDER BY timestamp ASC",
            (username, lookback)
        ).fetchall()

    timestamps = [r[0] for r in rows]

    for i in range(len(timestamps) - FAILED_ATTEMPT_THRESHOLD + 1):
        window_start = timestamps[i]
        window_end = timestamps[i + FAILED_ATTEMPT_THRESHOLD - 1]

        if window_end - window_start <= detection_window_seconds:
            unlock_at = window_end + (LOCKOUT_DURATION_MINUTES * 60)
            if now < unlock_at:
                return True, unlock_at - now

    return False, None


def verify_login(username, password):
    """
    Returns one of:
      ('locked',  retry_after_seconds)
      ('invalid', None)   -- covers both unknown username and wrong password
      ('success', None)
    """
    locked, retry_after = get_lockout_status(username)
    if locked:
        return 'locked', retry_after

    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT hash FROM users WHERE username = ?", (username,)
        ).fetchone()

    if row is None:
        # Unknown username. Still recorded, so behavior/timing stays
        # consistent with a real-but-wrong-password attempt.
        record_failed_attempt(username)
        return 'invalid', None

    stored_hash = row[0].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
        return 'success', None

    record_failed_attempt(username)
    return 'invalid', None


def prune_old_attempts():
    """
    Housekeeping only — deletes login_attempts rows older than
    ATTEMPT_LOG_RETENTION_HOURS. Safe to run any time; it's decoupled
    from lockout correctness by design (see config.py).
    """
    cutoff = time.time() - (ATTEMPT_LOG_RETENTION_HOURS * 3600)
    with sqlite3.connect(DB_PATH) as conn:
        deleted = conn.execute(
            "DELETE FROM login_attempts WHERE timestamp < ?", (cutoff,)
        ).rowcount
        conn.commit()
    if deleted:
        logger.info(f"Pruned {deleted} old login_attempts row(s)")
