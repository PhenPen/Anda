import socket
import threading
import json
import re
import ssl
import time
import queue

import db
import auth
import messages
import tls
import tokens
from config import (
    SERVER_HOST,
    PORT,
    ECHO_DM,
    SERVER_PING_AFTER_SECONDS,
    SERVER_PING_REPLY_SECONDS,
    SERVER_MAX_MISSED_PINGS,
    HEARTBEAT_TICK_SECONDS,
    OUTBOX_MAX_MESSAGES,
    CLOSE_FLUSH_SECONDS,
)
from logger import logger

clients = []
clients_lock = threading.Lock()

MENTION_PATTERN = re.compile(r'@(\w+)')


class ClientHandler:
    def __init__(self, client_socket, address):
        self.client_socket = client_socket
        self.address = address
        self.username = None
        self.authenticated = False
        self.replaced = False            # True if a newer login for this account kicked this connection out
        self.took_over_session = False   # True if this connection kicked an older one out
        self.logging_out = False         # True if the client asked to log out (so we flush "Logged out." before closing)
        self.reader = client_socket.makefile('r')
        self.writer = client_socket.makefile('w')

        # Heartbeat: when did we last hear ANYTHING from this client?
        self.last_heard = time.monotonic()

        # Outgoing queue: everyone who wants to send to this client drops the
        # message in here, and ONE writer thread is the only thing that ever
        # writes to the socket. That is what keeps two messages from mixing.
        self.outbox = queue.Queue(maxsize=OUTBOX_MAX_MESSAGES)
        self.writer_thread = threading.Thread(target=self._writer_loop, daemon=True)
        self.writer_thread.start()

        self._closed = False
        self._close_lock = threading.Lock()
        self._closed_event = threading.Event()   # set once closed; also stops the watcher thread

    # ------------------------------------------------------------------
    # Sending: queue + writer thread
    # ------------------------------------------------------------------
    def send(self, message):
        """Queues a line for this client. Never blocks and never raises."""
        if self._closed:
            return
        try:
            self.outbox.put_nowait(message)
        except queue.Full:
            logger.warning(f"{self.username or self.address}: outgoing queue full, dropping connection")
            self.close(graceful=False)

    def _writer_loop(self):
        """The only code that writes to this client's socket."""
        while True:
            message = self.outbox.get()      # sleeps until something arrives
            if message is None:              # stop signal
                break
            try:
                self.writer.write(message + '\n')
                self.writer.flush()
            except (OSError, ValueError):    # socket died (ValueError = already closed)
                self.close(graceful=False)
                break

    def close(self, graceful=True):
        """
        Closes this connection. Safe to call from any thread, any number of times.
        graceful=True: lets the writer send what is already queued (up to
        CLOSE_FLUSH_SECONDS), then closes. graceful=False: closes right away.
        """
        with self._close_lock:
            if self._closed:
                return
            self._closed = True
        self._closed_event.set()

        if graceful:
            try:
                self.outbox.put_nowait(None)   # stop signal goes AFTER everything already queued
                if threading.current_thread() is not self.writer_thread:
                    self.writer_thread.join(timeout=CLOSE_FLUSH_SECONDS)
            except queue.Full:
                pass  # queue is jammed; just close

        # shutdown() is what wakes up a thread stuck waiting to read.
        try:
            self.client_socket.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
        try:
            self.client_socket.close()
        except Exception:
            pass

        # Make sure the writer thread can't be left waiting forever.
        try:
            self.outbox.put_nowait(None)
        except queue.Full:
            pass

    def send_json(self, data):
        self.send(json.dumps(data))

    # ------------------------------------------------------------------
    # Reading + heartbeat
    # ------------------------------------------------------------------
    def _read_line(self):
        """Reads one line. Returns '' if the connection ended. Any line at all counts as proof of life."""
        try:
            line = self.reader.readline()
        except (OSError, ValueError):   # closed or reset underneath us
            return ''
        if line:
            self.last_heard = time.monotonic()
        return line

    def _handle_heartbeat(self, data):
        """Answers pings. Returns True if this message was a heartbeat (so callers skip it)."""
        msg_type = data.get("type")
        if msg_type == "ping":
            self.send_json({"type": "pong"})
            return True
        return msg_type == "pong"

    def _watch(self):
        """
        Watcher thread, one per connection. Pings after SERVER_PING_AFTER_SECONDS
        of silence, gives each ping SERVER_PING_REPLY_SECONDS, and closes the
        connection after SERVER_MAX_MISSED_PINGS misses in a row.
        """
        waiting_since = None   # when our outstanding ping was sent, or None
        misses = 0
        while not self._closed_event.wait(HEARTBEAT_TICK_SECONDS):
            now = time.monotonic()

            if waiting_since is not None:
                if self.last_heard >= waiting_since:      # heard something since the ping
                    waiting_since = None
                    misses = 0
                elif now - waiting_since >= SERVER_PING_REPLY_SECONDS:
                    misses += 1
                    if misses >= SERVER_MAX_MISSED_PINGS:
                        logger.warning(f"{self.username or self.address}: no response to heartbeat, closing connection")
                        self.close(graceful=False)
                        return
                    self.send_json({"type": "ping"})
                    waiting_since = time.monotonic()

            if waiting_since is None and now - self.last_heard >= SERVER_PING_AFTER_SECONDS:
                self.send_json({"type": "ping"})
                waiting_since = time.monotonic()

    def authenticate(self):
        """
        Handshake loop before a connection is allowed to join the chat.
        Client sends {"type": "register" | "login", "username": ..., "password": ...}
        until a login succeeds (registration alone does not log the user in).
        A {"type": "token_login", "token": ...} message can be used instead of a
        password login.
        """
        while True:
            line = self._read_line()
            if not line:
                return False  # client disconnected before authenticating

            raw = line.strip()
            if not raw:
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                self.send_json({"type": "error", "message": "Invalid request format."})
                continue

            if not isinstance(data, dict):
                continue
            if self._handle_heartbeat(data):
                continue

            msg_type = data.get("type")

            # Token login has no username/password, so it must be handled
            # before the username/password check below.
            if msg_type == "token_login":
                token = data.get("token")
                token_user = tokens.validate_token(token) if isinstance(token, str) else None

                if token_user is None:
                    self.send_json({
                        "type": "login_result",
                        "success": False,
                        "token_rejected": True,
                        "message": "Session expired. Please log in again."
                    })
                    continue

                self.username = token_user
                self.authenticated = True
                self.replace_existing_session()
                self.send_json({
                    "type": "login_result",
                    "success": True,
                    "username": token_user,
                    "message": f"Welcome back, {token_user}!"
                })
                self.send_history()
                return True

            username = (data.get("username") or "").strip()
            password = data.get("password") or ""

            if not username or not password:
                self.send_json({"type": "error", "message": "Username and password are required."})
                continue

            if msg_type == "register":
                success, message = auth.register_user(username, password)
                self.send_json({"type": "register_result", "success": success, "message": message})

            elif msg_type == "login":
                status, retry_after = auth.verify_login(username, password)

                if status == 'success':
                    self.username = username
                    self.authenticated = True
                    self.replace_existing_session()
                    token = tokens.create_token(username)
                    self.send_json({
                        "type": "login_result",
                        "success": True,
                        "message": f"Welcome, {username}!",
                        "token": token
                    })
                    self.send_history()
                    return True

                elif status == 'locked':
                    minutes = max(1, int(retry_after // 60) + 1)
                    self.send_json({
                        "type": "login_result",
                        "success": False,
                        "message": f"Account temporarily locked. Try again in about {minutes} minute(s)."
                    })

                else:  # 'invalid'
                    self.send_json({
                        "type": "login_result",
                        "success": False,
                        "message": "Invalid username or password."
                    })

            else:
                self.send_json({"type": "error", "message": "Expected a 'login' or 'register' request."})

    def replace_existing_session(self):
        """
        Called once this connection's login is proven valid (password or token).
        If the same account is already connected, that older connection is told
        it was replaced and closed, and this one takes over silently — nobody
        sees "left" or "joined", because from the chat's point of view the user
        never went away.
        """
        with clients_lock:
            old = next((c for c in clients if c.username == self.username), None)
            if old is not None:
                old.replaced = True   # set before closing, so old.disconnect() stays quiet
                clients.remove(old)

        if old is None:
            return

        self.took_over_session = True
        logger.info(f"{self.username}: replacing older session from {old.address}")

        # Queue the notice, then close gracefully so the writer thread gets
        # (up to CLOSE_FLUSH_SECONDS) to actually send it before the socket closes.
        old.send_json({"type": "session_replaced", "message": "You were logged in from another place."})
        old.close(graceful=True)

    def send_history(self):
        """
        Sends recent broadcast history and this user's own DM history to
        this one client only, right after login and before they're added
        to the live clients list — so history can never interleave with
        live messages.
        """
        for sender, content, timestamp in messages.get_broadcast_history():
            self.send_json({
                "type": "history",
                "kind": "broadcast",
                "from": sender,
                "message": content,
                "timestamp": timestamp,
            })

        for sender, recipient, content, timestamp in messages.get_dm_history(self.username):
            self.send_json({
                "type": "history",
                "kind": "dm",
                "from": sender,
                "to": recipient,
                "message": content,
                "timestamp": timestamp,
            })

    def listen(self):
        while True:
            line = self._read_line()
            if not line:
                break
            raw = line.strip()
            if not raw:
                continue

            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                logger.warning(f"Invalid JSON from {self.username}: {raw}")
                continue

            if not isinstance(data, dict):
                continue

            # Heartbeat first: otherwise a ping would fall through to the
            # "everything else is chat" branch below and be broadcast.
            if self._handle_heartbeat(data):
                continue

            msg_type = data.get("type")
            message = data.get("message", "")

            if msg_type == "logout":
                # Like quitting, but also kills the saved token so the next
                # launch has to ask for the password again.
                tokens.delete_token(self.username)
                self.logging_out = True
                self.send_json({"type": "logout_result", "success": True, "message": "Logged out."})
                break
            elif msg_type == "dm":
                self.handle_dm(data.get("target"), message)
            else:
                self.handle_broadcast(message)

    def handle_broadcast(self, message):
        with clients_lock:
            connected_usernames = {c.username for c in clients}

        mentioned = [name for name in MENTION_PATTERN.findall(message) if name in connected_usernames]

        logger.info(f"{self.username}: {message}")
        messages.record_broadcast(self.username, message)

        payload = {"type": "broadcast", "from": self.username, "message": message}
        if mentioned:
            payload["mentions"] = mentioned

        self.broadcast(payload)

    def handle_dm(self, target, message):
        with clients_lock:
            target_client = next((c for c in clients if c.username == target), None)

        if target_client is None:
            self.send_json({"type": "error", "message": f"{target} is not currently connected."})
            return

        target_client.send_json({"type": "dm", "from": self.username, "message": message})
        logger.info(f"{self.username} -> {target} (DM): {message}")
        messages.record_dm(self.username, target, message)

        if ECHO_DM:
            self.send_json({"type": "dm_sent", "to": target, "message": message})

    def broadcast(self, payload):
        with clients_lock:
            recipients = [c for c in clients if c is not self]
        for client in recipients:
            client.send_json(payload)   # just queues; a stuck client can't hold anyone up

    def broadcast_system(self, message):
        self.broadcast({"type": "system", "message": message})

    def run(self):
        logger.info(f"New connection from {self.address}")

        # The watcher runs from the moment of connecting, so a connection that
        # dies during login is noticed too.
        threading.Thread(target=self._watch, daemon=True).start()

        try:
            authenticated = self.authenticate()
        except Exception:
            logger.exception(f"Error while authenticating {self.address}")
            authenticated = False

        if not authenticated:
            self.close(graceful=False)
            return

        with clients_lock:
            clients.append(self)
        logger.info(f"{self.username} authenticated from {self.address}")

        if not self.took_over_session:
            self.broadcast_system(f"{self.username} joined the chat")

        try:
            self.listen()
        finally:
            self.disconnect()

    def disconnect(self):
        with clients_lock:
            if self in clients:
                clients.remove(self)
        # After a /logout, give "Logged out." a moment to be sent first.
        # Otherwise (client left, or connection died) there is nobody to flush to.
        self.close(graceful=self.logging_out)
        logger.info(f"{self.username} disconnected")
        if not self.replaced:
            self.broadcast_system(f"{self.username} left the chat")


def main():
    db.init_db()
    auth.prune_old_attempts()  # housekeeping pass on startup; see note below on real cron scheduling

    ssl_context = tls.get_server_context()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, PORT))
    server_socket.listen()
    logger.info(f"Server listening on {SERVER_HOST}:{PORT}")

    while True:
        raw_socket, address = server_socket.accept()

        try:
            client_socket = ssl_context.wrap_socket(raw_socket, server_side=True)
        except ssl.SSLError:
            logger.warning(f"TLS handshake failed for {address}")
            raw_socket.close()
            continue  # this one connection failed — the server keeps accepting others

        handler = ClientHandler(client_socket, address)
        threading.Thread(target=handler.run).start()


if __name__ == "__main__":
    main()
