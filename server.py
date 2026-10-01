import socket
import threading
import json
import re
import ssl

import schema
import auth
import messages
import tls
from config import SERVER_HOST, PORT, ECHO_DM
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
        self.reader = client_socket.makefile('r')
        self.writer = client_socket.makefile('w')

    def send(self, message):
        self.writer.write(message + '\n')
        self.writer.flush()

    def send_json(self, data):
        self.send(json.dumps(data))

    def authenticate(self):
        """
        Handshake loop before a connection is allowed to join the chat.
        Client sends {"type": "register" | "login", "username": ..., "password": ...}
        until a login succeeds (registration alone does not log the user in).
        """
        while True:
            line = self.reader.readline()
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

            msg_type = data.get("type")
            username = (data.get("username") or "").strip()
            password = data.get("password") or ""

            if not username or not password:
                self.send_json({"type": "error", "message": "Username and password are required."})
                continue

            if msg_type == "register":
                success, message = auth.register_user(username, password)
                self.send_json({"type": "register_result", "success": success, "message": message})

            elif msg_type == "login":
                with clients_lock:
                    already_connected = any(c.username == username for c in clients)
                if already_connected:
                    self.send_json({
                        "type": "login_result",
                        "success": False,
                        "message": "That user is already logged in elsewhere."
                    })
                    continue

                status, retry_after = auth.verify_login(username, password)

                if status == 'success':
                    self.username = username
                    self.authenticated = True
                    self.send_json({"type": "login_result", "success": True, "message": f"Welcome, {username}!"})
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
            line = self.reader.readline()
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

            msg_type = data.get("type")
            message = data.get("message", "")

            if msg_type == "dm":
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
            try:
                client.send_json(payload)
            except Exception:
                logger.warning(f"Failed to send to {client.username}, dropping them")

    def broadcast_system(self, message):
        with clients_lock:
            recipients = [c for c in clients if c is not self]
        payload = {"type": "system", "message": message}
        for client in recipients:
            try:
                client.send_json(payload)
            except Exception:
                logger.warning(f"Failed to send system message to {client.username}")

    def run(self):
        logger.info(f"New connection from {self.address}")

        if not self.authenticate():
            self.client_socket.close()
            return

        with clients_lock:
            clients.append(self)
        logger.info(f"{self.username} authenticated from {self.address}")

        self.broadcast_system(f"{self.username} joined the chat")

        try:
            self.listen()
        finally:
            self.disconnect()

    def disconnect(self):
        with clients_lock:
            if self in clients:
                clients.remove(self)
        try:
            self.client_socket.close()
        except Exception:
            pass
        logger.info(f"{self.username} disconnected")
        self.broadcast_system(f"{self.username} left the chat")


def main():
    schema.init_db()
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
