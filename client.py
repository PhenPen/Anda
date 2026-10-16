import getpass
from client_core import ChatClient
import session_store

username = None
authenticated = False

DISCONNECT_NOTICES = {
    "server_closed": "Disconnected from server.",
    "heartbeat": "Lost connection: the server stopped responding.",
    "reply_timeout": "The server didn't answer in time.",
    "send_failed": "Lost connection to the server.",
}


def on_disconnect(reason):
    """Called from a background thread the moment the connection ends."""
    print(DISCONNECT_NOTICES.get(reason, "Disconnected from server."))
    if authenticated:
        print("(Type 'quit' to exit.)")


def handle_message(data):
    """Prints one incoming chat-phase message (called from the listener thread)."""
    msg_type = data.get("type")
    message = data.get("message", "")

    if msg_type == "dm":
        print(f"[DM] {data.get('from')}: {message}")
    elif msg_type == "dm_sent":
        print(f"[DM to {data.get('to')}] {username}: {message}")
    elif msg_type == "history":
        sender = data.get("from")
        if data.get("kind") == "dm":
            recipient = data.get("to")
            if sender == username:
                print(f"[earlier DM to {recipient}] {username}: {message}")
            else:
                print(f"[earlier DM] {sender}: {message}")
        else:
            print(f"[earlier] {sender}: {message}")
    elif msg_type == "system":
        print(f"* {message}")
    elif msg_type == "error":
        print(message)
    elif msg_type == "broadcast":
        mentions = data.get("mentions", [])
        sender = data.get("from")
        if username in mentions:
            print(f"[MENTION] {sender}: {message}")
        else:
            print(f"{sender}: {message}")
    else:
        print(message)


client = ChatClient(on_disconnect=on_disconnect)
client.connect()
print("Connected to server.")

# If there's a saved login from last time, try it before asking for a password.
saved = session_store.load_session()
if saved:
    response = client.token_login(saved["token"])
    if response is None:
        # The connection ended while we waited; the notice was already printed.
        client.close()
        raise SystemExit
    print(response.get("message", ""))
    if response.get("success"):
        username = response.get("username", saved["username"])  # the server says who we are
        authenticated = True
    else:
        session_store.delete_session()  # that token is dead; forget it and fall through to the menu

while not authenticated:
    print("\n1) Log in")
    print("2) Register")
    choice = input("> ").strip()

    if not client.connected:
        # The connection died while we sat at the menu (notice already printed).
        client.close()
        raise SystemExit

    if choice not in ("1", "2"):
        print("Please enter 1 or 2.")
        continue

    entered_username = input("Username: ").strip()
    entered_password = getpass.getpass("Password: ")  # doesn't echo the password to the screen

    if choice == "2":
        response = client.register(entered_username, entered_password)
        if response is None:
            client.close()
            raise SystemExit
        print(response.get("message", ""))
        # Registering alone doesn't log you in — loop back to the menu to log in.

    else:  # choice == "1"
        response = client.login(entered_username, entered_password)
        if response is None:
            client.close()
            raise SystemExit
        print(response.get("message", ""))
        if response.get("success"):
            username = entered_username
            authenticated = True

            # Remember this login for next time.
            token = response.get("token")
            if token and not session_store.save_session(entered_username, token):
                print("(Couldn't save your login for next time.)")

# Login is done and `username` is set. From here on, incoming messages are
# printed — first the history that arrived while we were logging in.
client.begin_chat(handle_message)


def send_messages():
    while True:
        message = input()
        command = message.strip().lower()

        if command == "quit":
            break  # quit keeps the saved login for next time

        if command == "/logout":
            session_store.delete_session()  # forget the login on this device first
            if client.send_logout():        # then tell the server to forget it too
                client.wait_until_closed(timeout=3)  # let the "Logged out." reply print
            else:
                print("(Not connected: your login was forgotten on this device only.)")
            break

        if not client.connected:
            print("Not connected, message not sent.")
            continue

        if message.startswith("/dm "):
            parts = message.split(" ", 2)
            if len(parts) < 3:
                print("Usage: /dm username message")
                continue
            _, target, content = parts
            sent = client.send_dm(target, content)
        else:
            sent = client.send_broadcast(message)

        if not sent:
            print("Not connected, message not sent.")


send_messages()
client.close()
