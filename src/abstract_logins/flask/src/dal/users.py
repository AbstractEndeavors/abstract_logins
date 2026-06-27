"""
User table data access.

DAL modules should only talk to SQL. They should not import services.
"""
import psycopg2

from ..db import db
from ..imports.errors import UserExists, UserNotFound


_USER_COLS = """
id,
username,
email,
password_hash,
is_admin,
status,
status_reason,
status_changed_by,
status_changed_at,
created_at,
updated_at
"""


def get_by_username(username):
    return db.fetch_one(
        f"SELECT {_USER_COLS} FROM users WHERE username = %s;",
        (username,),
    )


def get_by_id(user_id):
    row = db.fetch_one(
        f"SELECT {_USER_COLS} FROM users WHERE id = %s;",
        (user_id,),
    )
    if row is None:
        raise UserNotFound(f"user id {user_id}")
    return row


def list_usernames():
    rows = db.fetch_all("SELECT username FROM users ORDER BY username ASC;")
    return [r["username"] for r in rows]


def list_by_status(status):
    return db.fetch_all(
        f"""
        SELECT {_USER_COLS}
          FROM users
         WHERE status = %s
         ORDER BY created_at ASC;
        """,
        (status,),
    )


def create(username, email, password_hash, is_admin=False, status="pending"):
    try:
        row = db.insert_returning(
            """
            INSERT INTO users (username, email, password_hash, is_admin, status)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id;
            """,
            (username, email, password_hash, is_admin, status),
        )
    except psycopg2.errors.UniqueViolation as exc:
        raise UserExists(f"username or email already exists: {username}") from exc

    return row["id"]


def update_password(user_id, new_password_hash):
    rowcount = db.execute(
        """
        UPDATE users
           SET password_hash = %s,
               updated_at = NOW()
         WHERE id = %s;
        """,
        (new_password_hash, user_id),
    )
    if rowcount == 0:
        raise UserNotFound(f"user id {user_id}")


def set_status(user_id, status, actor_id=None, reason=None):
    rowcount = db.execute(
        """
        UPDATE users
           SET status = %s,
               status_reason = %s,
               status_changed_by = %s,
               status_changed_at = NOW(),
               updated_at = NOW()
         WHERE id = %s;
        """,
        (status, reason, actor_id, user_id),
    )
    if rowcount == 0:
        raise UserNotFound(f"user id {user_id}")
