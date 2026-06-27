import os
import datetime
import jwt
from abstract_security import get_env_value

JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600 * 24


def get_app_secret():
    APP_SECRET = get_env_value("JWT_SECRET")
    if not APP_SECRET:
        raise RuntimeError("JWT_SECRET environment variable is required")
    return APP_SECRET


def get_exp_delta(delta_seconds=None):
    return datetime.timedelta(seconds=delta_seconds or JWT_EXP_DELTA_SECONDS)


def get_current_time():
    return datetime.datetime.utcnow()


def get_token_exp(delta_seconds=None):
    return get_current_time() + get_exp_delta(delta_seconds=delta_seconds)


def generate_token(**payload) -> str:
    payload["exp"] = payload.get("exp", get_token_exp())
    return jwt.encode(payload, get_app_secret(), algorithm=JWT_ALGORITHM)


def generate_user_token(
    username: str = None, is_admin: bool = None, exp: int = None
) -> str:
    return generate_token(
        username=username or "guest",
        is_admin=is_admin or False,
        exp=exp or get_token_exp(),
    )


def generate_download_token(
    username: str = None, rel_path: str = None, exp: int = None
) -> str:
    return generate_token(
        sub=username, path=rel_path, exp=exp or get_token_exp()
    )


def decode_token(token: str) -> dict:
    return jwt.decode(token, get_app_secret(), algorithms=[JWT_ALGORITHM])


def get_user_id_from_request(req):
    """
    Return (username, None) from session cookie or JWT bearer token.
    Returns (None, error_str) if neither is present or valid.
    """
    # 1. Session cookie (new auth) – avoids JWT dependency
    try:
        from .session_utils import get_username_from_session
        username = get_username_from_session(req)
        if username:
            return username, None
    except Exception:
        pass

    # 2. JWT bearer token (legacy)
    auth = req.headers.get("Authorization", "")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None, "Missing or invalid Authorization header"

    try:
        payload = decode_token(parts[1])
    except Exception as e:
        return None, f"Token decode error: {e}"

    user_id = payload.get("username") or payload.get("sub")
    if not user_id:
        return None, "Token missing user identity"
    return user_id, None
