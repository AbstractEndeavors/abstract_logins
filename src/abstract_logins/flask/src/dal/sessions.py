"""
Session table data access. Sessions are a server-side opaque token
table -- no Flask session cookie state, just a random ID stored in a
cookie that maps to a row here.
"""
from ..db import db


def create(session_id, user_id, expires_at):
    db.execute(
        """
        INSERT INTO sessions (session_id, user_id, expires_at)
        VALUES (%s, %s, %s);
        """,
        (session_id, user_id, expires_at),
    )


def get(session_id):
    """Return the session row, or None. Does not check expiry."""
    return db.fetch_one(
        """
        SELECT session_id, user_id, created_at, expires_at, last_seen_at
          FROM sessions
         WHERE session_id = %s;
        """,
        (session_id,),
    )


def touch(session_id):
    """Update last_seen_at to now. Does not extend expiry."""
    db.execute(
        "UPDATE sessions SET last_seen_at = NOW() WHERE session_id = %s;",
        (session_id,),
    )


def delete(session_id):
    db.execute("DELETE FROM sessions WHERE session_id = %s;", (session_id,))


def delete_for_user(user_id):
    """Invalidate every session for a user. Useful on password change."""
    db.execute("DELETE FROM sessions WHERE user_id = %s;", (user_id,))


def purge_expired():
    """Delete sessions past their expiry. Run periodically."""
    db.execute("DELETE FROM sessions WHERE expires_at < NOW();")
