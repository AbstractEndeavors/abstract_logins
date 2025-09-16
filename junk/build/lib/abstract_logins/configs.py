# abstract_logins/config.py
from pathlib import Path

HOMES_BASE = Path("/var/www/html/media/homes")
USERS_BASE = Path("/var/www/html/media/users")

def user_root(username: str) -> Path:
    return USERS_BASE / username

def user_home(username: str) -> Path:
    return user_root(username) / "Home"

def user_secure(username: str) -> Path:
    return user_root(username) / "secureFiles"

# Base used for DB relative paths so you can store "username/subdir/file.ext"
ABS_UPLOAD_DIR = USERS_BASE  # NOTE: DB paths will be relative to USERS_BASE

