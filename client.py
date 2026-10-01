import threading
import getpass
from client_core import ChatClient

client = ChatClient()
client.connect()
print("Connected to server.")

username = None
authenticated = False

while not authenticated:
    print("\n1) Log in")
    print("2) Register")
    choice = input("> ").strip()

    if choice not in ("1", "2"):
        print("Please enter 1 or 2.")
        continue

    entered_username = input("Username: ").strip()
    entered_password = getpass.getpass("Password: ")  # doesn't echo the password to the screen

    if choice == "2":
        response = client.register(entered_username, entered_password)
        if response is None:
            print("Disconnected from server.")
            client.close()
            raise SystemExit
        print(response.get("message", ""))
        # Registering alone doesn't log you in — loop back to the menu to log in.

    else:  # choice == "1"
        response = client.login(entered_username, entered_password)
        if response is None:
            print("Disconnected from server.")
            client.close()
            raise SystemExit
        print(response.get("message", ""))
        if response.get("success"):
            username = entered_username
            authenticated = True


def receive_messages():
    while True:
        data = client.receive_message()
        if data is None:
            print("Disconnected from server.")
            break

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


def send_messages():
    while True:
        message = input()
        if message.strip().lower() == "quit":
            break

        if message.startswith("/dm "):
            parts = message.split(" ", 2)
            if len(parts) < 3:
                print("Usage: /dm username message")
                continue
            _, target, content = parts
            client.send_dm(target, content)
        else:
            client.send_broadcast(message)


receiver_thread = threading.Thread(target=receive_messages, daemon=True)
receiver_thread.start()

send_messages()
client.close()
