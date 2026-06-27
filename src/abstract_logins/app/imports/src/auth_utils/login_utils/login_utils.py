import datetime
import jwt
from functools import wraps
from abstract_flask import request, jsonify
from .token_utils import decode_token
from .session_utils import get_user_from_session_cookie
from ..user_store.get_users import get_user_by_username


def login_required(f):
    """
    Accepts both session-cookie auth (new flask/ system) and JWT Bearer tokens
    (legacy). Session cookie is checked first; falls back to the Authorization
    header. Sets request.user = {"id": ..., "username": ..., "is_admin": ...}
    in both cases so downstream handlers stay unchanged.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Session-cookie path (new auth)
        user, _err = get_user_from_session_cookie(request)
        if user:
            request.user = {
                "id":       user["id"],
                "username": user["username"],
                "is_admin": bool(user.get("is_admin", False)),
            }
            return f(*args, **kwargs)

        # 2. JWT Bearer-token path (legacy)
        auth_header = request.headers.get("Authorization", "")
        parts = auth_header.split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return jsonify({"message": "Authentication required"}), 401

        token = parts[1]
        try:
            payload = decode_token(token)
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401

        username = payload.get("username")
        is_admin  = payload.get("is_admin", False)

        if "sub" in payload:
            user_id = int(payload["sub"])
        else:
            db_user = get_user_by_username(username)
            if not db_user:
                return jsonify({"message": "Unknown user"}), 404
            user_id = db_user["id"]

        request.user = {
            "id":       user_id,
            "username": username,
            "is_admin": is_admin,
        }
        return f(*args, **kwargs)
    return decorated
