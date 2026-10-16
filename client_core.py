"""
Reusable client-side protocol logic.

Knows how to talk to the server (connect, send, receive, the shape of
every message type). Knows nothing about how input is gathered or output
is displayed — that's left entirely to whatever uses this class (the
terminal client today, potentially a GUI later).

Threads (all started by connect()):
- listener: the ONLY thing that reads from the socket. It answers pings,
  hands answers (login_result etc.) to whoever is waiting for them, and
  passes everything else on to the display code.
- watcher: pings after CLIENT_PING_AFTER_SECONDS of silence and declares
  the connection dead after CLIENT_MAX_MISSED_PINGS unanswered pings.
Writes can come from the typing thread, the listener (pongs) and the
watcher (pings), so they take turns using a lock.
"""
import socket
import json
import threading
import queue
import time

import tls
from config import (
    CLIENT_HOST,
    PORT,
    CLIENT_PING_AFTER_SECONDS,
    CLIENT_PING_REPLY_SECONDS,
    CLIENT_MAX_MISSED_PINGS,
    HEARTBEAT_TICK_SECONDS,
    LOGIN_REPLY_TIMEOUT_SECONDS,
)

# Message types that answer a request the client is waiting on. ("error" is
# included because the server sends it instead of a result when a login or
# register request is malformed.)
ANSWER_TYPES = {"login_result", "register_result", "logout_result", "error"}


class ChatClient:
    def __init__(self, on_disconnect=None):
        """
        on_disconnect(reason) is called once, from a background thread, when
        the connection ends — unless we closed it ourselves with close().
        reason is one of: "server_closed", "heartbeat", "reply_timeout", "send_failed".
        """
        self.socket = None
        self.reader = None
        self.writer = None
        self.on_disconnect = on_disconnect
        self.on_message = None
        self.close_reason = None

        self.last_heard = time.monotonic()
        self._connected = False
        self._user_closed = False
        self._state_lock = threading.Lock()
        self._write_lock = threading.Lock()
        self._stopped = threading.Event()   # set once the connection is over

        # Answers to requests (login_result etc.) go through this queue.
        # None in it means "the connection ended while you were waiting".
        self._answers = queue.Queue()
        self._awaiting = False

        # Messages that arrive before the display code is ready (for example
        # the history sent right after login) wait here, in order.
        self._deliver_lock = threading.Lock()
        self._ready = False
        self._backlog = []

    @property
    def connected(self):
        return self._connected

    # ------------------------------------------------------------------
    # Connecting and closing
    # ------------------------------------------------------------------
    def connect(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.connect((CLIENT_HOST, PORT))

        context = tls.get_client_context()
        self.socket = context.wrap_socket(raw_socket)

        self.reader = self.socket.makefile('r')
        self.writer = self.socket.makefile('w')

        self.last_heard = time.monotonic()
        self._connected = True

        threading.Thread(target=self._listen, daemon=True).start()
        threading.Thread(target=self._watch, daemon=True).start()

    def close(self):
        """Closes the connection on purpose (no on_disconnect notice)."""
        self._user_closed = True
        self._mark_disconnected("user_closed")

    def wait_until_closed(self, timeout=None):
        """Blocks until the connection is over. Returns True if it ended within the timeout."""
        return self._stopped.wait(timeout)

    def _mark_disconnected(self, reason):
        """The one place a connection ends. Safe to call many times; only the first call counts."""
        with self._state_lock:
            if not self._connected:
                return
            self._connected = False
            self.close_reason = reason

        # shutdown() is what wakes up the listener if it is stuck waiting to read.
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.socket.close()
        except Exception:
            pass

        self._answers.put(None)   # wake up anything waiting for an answer

        if self.on_disconnect and not self._user_closed:
            try:
                self.on_disconnect(reason)
            except Exception:
                pass
        self._stopped.set()       # also stops the watcher

    # ------------------------------------------------------------------
    # Sending
    # ------------------------------------------------------------------
    def _write(self, payload):
        self.writer.write(json.dumps(payload) + '\n')
        self.writer.flush()

    def _send(self, payload):
        """Sends one message. Returns True if it was sent, False if not connected or the send failed."""
        if not self._connected:
            return False
        try:
            with self._write_lock:
                self._write(payload)
            return True
        except (OSError, ValueError):
            self._mark_disconnected("send_failed")
            return False

    def _send_heartbeat(self, msg_type):
        """
        Sends a ping or pong. If the writing lock stays busy for a whole
        second, skip it: something else is already writing, and the watcher
        must never get stuck waiting.
        """
        if not self._write_lock.acquire(timeout=1):
            return
        try:
            self._write({"type": msg_type})
        except (OSError, ValueError):
            self._mark_disconnected("send_failed")
        finally:
            self._write_lock.release()

    # ------------------------------------------------------------------
    # The listener thread: the only reader
    # ------------------------------------------------------------------
    def _listen(self):
        while True:
            try:
                line = self.reader.readline()
            except (OSError, ValueError):
                break
            if not line:
                break

            self.last_heard = time.monotonic()   # anything at all counts as proof of life

            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(data, dict):
                continue

            msg_type = data.get("type")
            if msg_type == "ping":
                self._send_heartbeat("pong")
            elif msg_type == "pong":
                pass
            elif self._awaiting and msg_type in ANSWER_TYPES:
                self._answers.put(data)
            else:
                self._deliver(data)

        self._mark_disconnected("server_closed")

    def _deliver(self, data):
        with self._deliver_lock:
            if not self._ready:
                self._backlog.append(data)
                return
        self.on_message(data)

    def begin_chat(self, on_message):
        """
        Call once login is done and the display code is ready. Everything that
        arrived in the meantime (history, join notices) is handed over first,
        in order, then new messages follow.
        """
        with self._deliver_lock:
            self.on_message = on_message
            backlog, self._backlog = self._backlog, []
            for data in backlog:
                on_message(data)
            self._ready = True

    # ------------------------------------------------------------------
    # The watcher thread: heartbeat
    # ------------------------------------------------------------------
    def _watch(self):
        waiting_since = None   # when our outstanding ping was sent, or None
        misses = 0
        while not self._stopped.wait(HEARTBEAT_TICK_SECONDS):
            now = time.monotonic()

            if waiting_since is not None:
                if self.last_heard >= waiting_since:      # heard something since the ping
                    waiting_since = None
                    misses = 0
                elif now - waiting_since >= CLIENT_PING_REPLY_SECONDS:
                    misses += 1
                    if misses >= CLIENT_MAX_MISSED_PINGS:
                        self._mark_disconnected("heartbeat")
                        return
                    self._send_heartbeat("ping")
                    waiting_since = time.monotonic()

            if waiting_since is None and now - self.last_heard >= CLIENT_PING_AFTER_SECONDS:
                self._send_heartbeat("ping")
                waiting_since = time.monotonic()

    # ------------------------------------------------------------------
    # Requests (send, then wait for the answer)
    # ------------------------------------------------------------------
    def _request(self, payload):
        """
        Sends one request and waits for its answer (up to LOGIN_REPLY_TIMEOUT_SECONDS).
        Returns the answer dict, or None if the connection ended or timed out.
        On a timeout the connection is closed: it can't be trusted any more.
        """
        if not self._connected:
            return None

        while True:   # throw away any old unclaimed answer
            try:
                self._answers.get_nowait()
            except queue.Empty:
                break

        self._awaiting = True
        try:
            if not self._send(payload):
                return None
            try:
                return self._answers.get(timeout=LOGIN_REPLY_TIMEOUT_SECONDS)
            except queue.Empty:
                self._mark_disconnected("reply_timeout")
                return None
        finally:
            self._awaiting = False

    def register(self, username, password):
        """Sends a register request, returns the server's response dict (or None if the connection ended)."""
        return self._request({"type": "register", "username": username, "password": password})

    def login(self, username, password):
        """Sends a login request, returns the server's response dict (or None if the connection ended)."""
        return self._request({"type": "login", "username": username, "password": password})

    def token_login(self, token):
        """Logs in with a saved session token. Returns the server's response dict (or None if the connection ended)."""
        return self._request({"type": "token_login", "token": token})

    # ------------------------------------------------------------------
    # Chat-phase messages (no waiting for an answer)
    # ------------------------------------------------------------------
    def send_logout(self):
        """Asks the server to forget this login's token and end the session. Returns True if sent."""
        return self._send({"type": "logout"})

    def send_broadcast(self, message):
        """Returns True if the message was sent."""
        return self._send({"type": "broadcast", "message": message})

    def send_dm(self, target, content):
        """Returns True if the message was sent."""
        return self._send({"type": "dm", "target": target, "message": content})
