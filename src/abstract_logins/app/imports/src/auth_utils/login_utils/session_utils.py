"""
Bridge between the old JWT-based file endpoints and the new session-cookie auth.
Queries the same `sessions` and `users` tables used by flask/src/dal/*.
"""
import os
from datetime import datetime, timezone
from abstract_database import *


def _now():
    return datetime.now(timezone.utc)


def get_session_cookie_name() -> str:
    return os.environ.get("AUTH_SESSION_COOKIE", "auth_session")


def get_user_from_session_cookie(request):
    """
    Validate the session cookie and return the matching user row.
    Returns (user_dict, None) on success, (None, error_str) on failure.
    """
    cookie_name = get_session_cookie_name()
    sid = request.cookies.get(cookie_name)
    if not sid:
        return None, "no session cookie"
    logger.info(f"sessions columns == {get_column_names(('sessions'))}")
    logger.info(f"users columns == {get_column_names(('users'))}")
    sessions = fetch_any_combo(
        columnNames="*",
        tableName="sessions",
        searchColumn="session_id",
        searchValue=sid
    )
    logger.info(f"sessions == {sessions}")
    if not sessions:
        return None, "session not found"

    sess = sessions[0] if isinstance(sessions, list) else sessions
    logger.info(f"session == {sess}")
    expires_at = sess.get("expires_at")
    if expires_at is None:
        return None, "session has no expiry"
    logger.info(f"not expired")
    # Normalise: DB may return a naive datetime or an ISO string
    if isinstance(expires_at, str):
        try:
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        except ValueError:
            return None, "invalid expires_at"
    logger.info(f"not expired")
    if getattr(expires_at, "tzinfo", None) is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)

    if expires_at < _now():
        return None, "session expired"
    logger.info(f"not expired")

    user_id = sess.get("user_id")
    logger.info(f"user_id == {user_id}")
    if not user_id:
        return None, "session missing user_id"

    users = fetch_any_combo(
        columnNames="*",
        tableName="users",
        searchColumn="id",
        searchValue=user_id,
    )
    logger.info(f"users == {users}")
    if not users:
        return None, "user not found"
    logger.info(f"is_user == {(users[0] if isinstance(users, list) else users)}")
    return (users[0] if isinstance(users, list) else users), None


def get_username_from_session(request) -> "str | None":
    """Convenience wrapper – returns just the username or None."""
    user, _ = get_user_from_session_cookie(request)
    if user and isinstance(user, dict):
        return user.get("username")
    return None
