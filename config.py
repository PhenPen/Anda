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

# --- Session tokens ---
TOKEN_LIFETIME_DAYS = 7

# Where the client keeps its saved login. A folder in the user's home
# directory, outside the project so it can never be committed to git.
SESSION_DIR = '~/.anda'
SESSION_FILE_NAME = 'session.anda'

# --- Heartbeat (detecting a dead connection) ---
# Each side watches how long it has been since it last heard ANYTHING from
# the other side (not only a pong). After *_PING_AFTER_SECONDS of silence it
# sends a ping, then waits *_PING_REPLY_SECONDS for any sign of life. The
# connection is declared dead after *_MAX_MISSED_PINGS unanswered pings in a
# row. Worst case until "dead" = AFTER + REPLY * MAX_MISSED.
#   client: 10 + 5 * 2 = about 20 s     server: 20 + 5 * 2 = about 30 s
# The client is the main pinger; the server's pings are a backup.
CLIENT_PING_AFTER_SECONDS = 10
CLIENT_PING_REPLY_SECONDS = 5
CLIENT_MAX_MISSED_PINGS = 2

SERVER_PING_AFTER_SECONDS = 20
SERVER_PING_REPLY_SECONDS = 5
SERVER_MAX_MISSED_PINGS = 2

# How often each watcher thread wakes up to check the clock.
HEARTBEAT_TICK_SECONDS = 1

# --- Server outgoing queue ---
# Every client connection has its own outgoing queue and a writer thread.
# If a client is so far behind that this many messages are waiting for it,
# the server drops that connection (its client can log back in).
OUTBOX_MAX_MESSAGES = 1000

# When the server closes a connection on purpose (logout, session replaced),
# it waits up to this long for the queued last messages to be sent first.
CLOSE_FLUSH_SECONDS = 2

# --- Client: waiting for answers ---
# How long login / register / token login wait for the server's reply. If it
# runs out, the connection is treated as bad and closed.
LOGIN_REPLY_TIMEOUT_SECONDS = 10
