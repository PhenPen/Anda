"""
TLS setup, shared by server.py and client_core.py.

Both sides need an ssl.SSLContext, but configured differently:
- the server presents its cert+key to every connection
- the client checks an incoming cert against the one pinned file it trusts,
  skipping hostname checking since we connect by raw IP, not a domain name
"""
import ssl
from config import CERT_FILE, KEY_FILE


def get_server_context():
    """Loads cert.pem + key.pem so the server can present them during the TLS handshake."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    return context


def get_client_context():
    """Trusts only our own pinned cert.pem — no CA, no hostname check."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=CERT_FILE)
    context.check_hostname = False
    return context
