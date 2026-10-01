SERVER_HOST = '0.0.0.0'
CLIENT_HOST = '127.0.0.1'
PORT = 5000
ECHO_DM = True

# --- Auth / database ---
DB_PATH = 'chat.db'
BCRYPT_ROUNDS = 12

# --- Account lockout ---
# A username is locked out once it has FAILED_ATTEMPT_THRESHOLD failed
# login attempts that all occurred within DETECTION_WINDOW_MINUTES of
# each other. Once triggered, the lockout lasts LOCKOUT_DURATION_MINUTES,
# counted from the last attempt in that burst.
FAILED_ATTEMPT_THRESHOLD = 5
DETECTION_WINDOW_MINUTES = 5
LOCKOUT_DURATION_MINUTES = 30

# Pure housekeeping: how long failed-attempt rows are kept before a
# cleanup pass deletes them. This is intentionally much larger than
# DETECTION_WINDOW_MINUTES / LOCKOUT_DURATION_MINUTES so cleanup timing
# can never interfere with lockout correctness.
ATTEMPT_LOG_RETENTION_HOURS = 24

# NOTE: the old MAX_LOGIN_ATTEMPTS (per-connection, username-only auth)
# has been removed — it's superseded by the account-level lockout above.

# --- Message history ---
# How many past messages to send a client right after login — applied
# separately to broadcast history and DM history.
MESSAGE_HISTORY_LIMIT = 50

# --- TLS ---
CERT_FILE = 'cert.pem'
KEY_FILE = 'key.pem'
