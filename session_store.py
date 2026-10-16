"""
The client's saved login.

Remembers the session token between runs so the user doesn't have to type
their password every time. Stored as JSON with a format label and a version,
in a private folder in the user's home directory (outside the project).
"""
import json
import os

from config import SESSION_DIR, SESSION_FILE_NAME

FORMAT_NAME = "anda-session"
FORMAT_VERSION = 1


def _folder():
    return os.path.expanduser(SESSION_DIR)


def _path():
    return os.path.join(_folder(), SESSION_FILE_NAME)


def save_session(username, token):
    """Saves the login. Returns True on success, False if the file couldn't be written."""
    data = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "username": username,
        "token": token,
    }
    try:
        os.makedirs(_folder(), mode=0o700, exist_ok=True)
        # Create the file so only its owner can read or write it (permission 600).
        fd = os.open(_path(), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(data, f)
        return True
    except OSError:
        return False


def load_session():
    """Returns {"username": ..., "token": ...}, or None if there's no usable saved login."""
    try:
        with open(_path()) as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(data, dict):
        return None
    if data.get("format") != FORMAT_NAME or data.get("version") != FORMAT_VERSION:
        return None  # not our file, or a version we don't understand
    if not isinstance(data.get("username"), str) or not isinstance(data.get("token"), str):
        return None
    return {"username": data["username"], "token": data["token"]}


def delete_session():
    """Removes the saved login. Does nothing if there isn't one."""
    try:
        os.remove(_path())
    except FileNotFoundError:
        pass
