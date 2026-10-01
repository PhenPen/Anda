"""
Reusable client-side protocol logic.

Knows how to talk to the server (connect, send, receive, the shape of
every message type). Knows nothing about how input is gathered or output
is displayed — that's left entirely to whatever uses this class (the
terminal client today, potentially a GUI later).
"""
import socket
import json
import tls
from config import CLIENT_HOST, PORT


class ChatClient:
    def __init__(self):
        self.socket = None
        self.reader = None
        self.writer = None

    def connect(self):
        raw_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_socket.connect((CLIENT_HOST, PORT))

        context = tls.get_client_context()
        self.socket = context.wrap_socket(raw_socket)

        self.reader = self.socket.makefile('r')
        self.writer = self.socket.makefile('w')

    def close(self):
        if self.socket:
            self.socket.close()

    def _send(self, payload):
        self.writer.write(json.dumps(payload) + '\n')
        self.writer.flush()

    def _receive(self):
        """Blocks until one JSON message arrives. Returns None if the server disconnected."""
        line = self.reader.readline()
        if not line:
            return None
        try:
            return json.loads(line.strip())
        except json.JSONDecodeError:
            return None

    def register(self, username, password):
        """Sends a register request, returns the server's response dict (or None on disconnect)."""
        self._send({"type": "register", "username": username, "password": password})
        return self._receive()

    def login(self, username, password):
        """Sends a login request, returns the server's response dict (or None on disconnect)."""
        self._send({"type": "login", "username": username, "password": password})
        return self._receive()

    def send_broadcast(self, message):
        self._send({"type": "broadcast", "message": message})

    def send_dm(self, target, content):
        self._send({"type": "dm", "target": target, "message": content})

    def receive_message(self):
        """Blocks for the next incoming message once chatting has started. Returns None on disconnect."""
        return self._receive()
