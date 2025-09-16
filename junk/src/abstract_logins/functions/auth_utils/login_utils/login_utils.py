from functools import wraps
import jwt
from abstract_flask import request, jsonify

from .token_utils import decode_token
from ..user_store.table_utils.routes import (
    is_token_blacklisted,
    ensure_blacklist_table_exists,
)
from ..user_store.get_users import get_user_by_username

# create blacklist table once
ensure_blacklist_table_exists()

def _login_required(allow_options=True, check_blacklist=False):
    """Decorator factory. Prefer @login_required() in routes."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if allow_options and request.method == "OPTIONS":
                return "", 200

            auth_header = request.headers.get("Authorization", "")
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({"message": "Missing or invalid Authorization header"}), 401

            token = parts[1]
            if check_blacklist and is_token_blacklisted(token):
                return jsonify({"message": "Token has been revoked"}), 401

            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid token"}), 401

            username = payload.get("username")
            is_admin = bool(payload.get("is_admin", False))

            sub = payload.get("sub")
            if isinstance(sub, int) or (isinstance(sub, str) and sub.isdigit()):
                user_id = int(sub)
            else:
                if not username:
                    return jsonify({"message": "Token missing identity"}), 401
                row = get_user_by_username(username)
                if not row:
                    return jsonify({"message": "Unknown user"}), 404
                user_id = int(row["id"])

            request.user = {"id": user_id, "username": username, "is_admin": is_admin}
            return f(*args, **kwargs)
        return wrapper
    return decorator

# Support both @login_required() and @login_required
def login_required(func=None, **opts):
    if func is None:
        return _login_required(**opts)
    return _login_required(**opts)(func)
