"""
Session management. The cookie holds a random opaque ID. The ID maps
to a row in the sessions table. Logout deletes the row. Password
change deletes every row for the user. Expiry is enforced both by the
cookie's Max-Age (client side) and by the expires_at column (server
side); the server side is the source of truth.

Why not Flask's built-in session? Flask's default session is signed
cookies -- the cookie *contains* the data, signed. That gives you the
same logout problem JWTs have: you can't revoke without a server-side
list. So we do server-side from the start.

current_user() reads the cookie, looks up the session, returns a User
or raises NotAuthenticated. Routes use the @login_required decorator.
"""
import secrets
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, g, make_response
from .imports.errors import NotAuthenticated, NotAuthorized
from .dal import sessions as session_dal
from .dal import users as user_dal


def _now():
    return datetime.now(timezone.utc)


def _new_session_id():
    # 32 bytes -> 256 bits of entropy, urlsafe-encoded.
    return secrets.token_urlsafe(32)


def login_user(cfg, response, user_id):
    """
    Create a session row, set the cookie on the response.
    Caller is responsible for password verification before calling this.
    """
    sid = _new_session_id()
    expires = _now() + timedelta(seconds=cfg.session_lifetime_seconds)
    session_dal.create(sid, user_id, expires)

    response.set_cookie(
        cfg.session_cookie_name,
        sid,
        max_age=cfg.session_lifetime_seconds,
        httponly=True,
        secure=getattr(cfg, "session_cookie_secure", True),
        samesite=getattr(cfg, "session_cookie_samesite", "None"),
        path="/",
    )

    return sid


def logout_user(cfg, response):
    """Delete the current session row and clear the cookie. Idempotent."""
    sid = request.cookies.get(cfg.session_cookie_name)

    if sid:
        session_dal.delete(sid)

    response.delete_cookie(
        cfg.session_cookie_name,
        path="/",
        secure=getattr(cfg, "session_cookie_secure", True),
        samesite=getattr(cfg, "session_cookie_samesite", "None"),
    )


def logout_all_for_user(user_id):
    """Invalidate every session for a user (e.g. after password change)."""
    session_dal.delete_for_user(user_id)


def current_user(cfg):
    """
    Resolve the session cookie to a User row. Caches per-request on
    flask.g so repeated calls within one request hit the DB once.
    Raises NotAuthenticated if there's no valid session.
    """
    if hasattr(g, "_current_user"):
        return g._current_user

    sid = request.cookies.get(cfg.session_cookie_name)
    if not sid:
        raise NotAuthenticated("no session cookie")

    sess = session_dal.get(sid)
    if sess is None:
        raise NotAuthenticated("session not found")

    if sess["expires_at"] < _now():
        session_dal.delete(sid)
        raise NotAuthenticated("session expired")

    user = user_dal.get_by_id(sess["user_id"])
    session_dal.touch(sid)
    g._current_user = user
    return user


def login_required(cfg):
    """Decorator factory. Usage: @login_required(cfg)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            current_user(cfg)  # raises NotAuthenticated if missing
            return fn(*args, **kwargs)
        return wrapper
    return deco


def admin_required(cfg):
    """Decorator factory. Usage: @admin_required(cfg)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user = current_user(cfg)
            if not user["is_admin"]:
                raise NotAuthorized("admin only")
            return fn(*args, **kwargs)
        return wrapper
    return deco
