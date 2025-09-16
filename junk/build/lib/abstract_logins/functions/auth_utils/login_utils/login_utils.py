import jwt
from functools import wraps
from abstract_flask import request, jsonify
from .token_utils import decode_token
from ..user_store.table_utils.routes import is_token_blacklisted, ensure_blacklist_table_exists
from ..user_store.get_users import get_user_by_username

# Ensure the blacklist table exists once at import time
ensure_blacklist_table_exists()

def login_required(allow_options: bool = True, check_blacklist: bool = False):
    """
    Decorator enforcing JWT auth.

    Params:
      allow_options   - if True, lets CORS preflight through without auth
      check_blacklist - if True, rejects tokens found in the blacklist table
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            # 0) CORS preflight
            if allow_options and request.method == "OPTIONS":
                return "", 200

            # 1) Parse Authorization: Bearer <token>
            auth_header = request.headers.get("Authorization", "")
            parts = auth_header.split()
            if len(parts) != 2 or parts[0].lower() != "bearer":
                return jsonify({"message": "Missing or invalid Authorization header"}), 401
            token = parts[1]

            # 2) Optional: token blacklist
            if check_blacklist and is_token_blacklisted(token):
                return jsonify({"message": "Token has been revoked"}), 401

            # 3) Decode/validate token
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"message": "Invalid token"}), 401

            # 4) Extract identity
            username = payload.get("username")
            is_admin = bool(payload.get("is_admin", False))
            sub = payload.get("sub")

            user_id = None
            # Prefer numeric sub if present
            if isinstance(sub, int) or (isinstance(sub, str) and sub.isdigit()):
                user_id = int(sub)

            # Fallback: lookup by username
            user_row = None
            if user_id is None:
                if not username:
                    return jsonify({"message": "Token missing identity"}), 401
                user_row = get_user_by_username(username)
                if not user_row:
                    return jsonify({"message": "Unknown user"}), 404
                user_id = int(user_row["id"])

            # 5) Attach to request for downstream routes
            request.user = {
                "id":       user_id,
                "username": username or (user_row["username"] if user_row else None),
                "is_admin": is_admin,
            }

            # 6) Continue
            return f(*args, **kwargs)
        return wrapper
    return decorator
