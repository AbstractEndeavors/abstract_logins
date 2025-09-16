from ...login_utils.pass_utils import bcrypt_plain_text
from ...query_utils import insert_query, select_rows,initialize_call_log
from .get_users import *

def get_user(username: str) -> dict | None:
    """
    Returns a mapping (dict) with keys: 'username', 'password_hash', 'is_admin',
    or None if no such user exists.
    """
    # Use RealDictCursor → fetchone() gives a dict
    query =user_query()
    rows = select_rows(query,username)  # e.g. {'username': 'joe', 'password_hash': '…', 'is_admin': False}
    return rows
def add_or_update_user(username: str, plaintext_pwd: str, is_admin: bool = None) -> None:
    """
    Inserts a new user or updates an existing user’s password_hash and is_admin flag.
    """
    is_admin = is_admin or False
    initialize_call_log()
    hashed = bcrypt_plain_text(plaintext_pwd,rounds=12)
    query = add_or_update_user_query()
    insert_query(query, username, hashed, is_admin)
    

def get_existing_users() -> list[str]:
    initialize_call_log()
    query = existing_users_query()
    rows = select_rows(query)
    if not rows:
        return []
    return [r[0] for r in rows]

