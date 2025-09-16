import os,datetime,jwt,datetime
from flask import abort
from abstract_security import get_env_value
JWT_ALGORITHM = "HS256"
JWT_EXP_DELTA_SECONDS = 3600*24
from abstract_utilities import print_or_log
def get_app_secret():
    APP_SECRET = get_env_value("JWT_SECRET")
    if not APP_SECRET:
        raise RuntimeError("JWT_SECRET environment variable is required")
    return APP_SECRET
def get_exp_delta(delta_seconds=None):
    delta_seconds = delta_seconds or JWT_EXP_DELTA_SECONDS
    exp_delta =  datetime.timedelta(seconds=delta_seconds)
    return exp_delta
def get_current_time():
    return datetime.datetime.utcnow()
def get_token_exp(delta_seconds=None):
    exp_delta = get_exp_delta(delta_seconds=delta_seconds)
    current_time = get_current_time()
    exp = current_time + exp_delta
    return exp
def generate_token(**payload) -> str:
    payload["exp"]= payload.get("exp",get_token_exp())
    print_or_log(payload)
    return jwt.encode(payload, get_app_secret(), algorithm=JWT_ALGORITHM)

# Make a folder named “uploads” parallel to “public”:
def generate_user_token(username: str=None,
                        is_admin: bool=None,
                        exp:int=None) -> str:
    token_js = {"username": username or 'guest',
                "is_admin": is_admin or False,
                "exp":exp or get_token_exp()}
    return generate_token(**token_js)

def generate_download_token(username: str =None,
                            rel_path: str =None,
                            exp:int=None) -> str:
    token_js = {"sub": username,
                "path": rel_path,
                "exp":exp or get_token_exp()}

    return generate_token(**token_js)
    

def decode_token(token: str) -> dict:
    app_secret = get_app_secret()
    return jwt.decode(token, app_secret, algorithms=[JWT_ALGORITHM])

def get_user_id_from_request(req):
    auth = req.headers.get("Authorization", "")
    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None,"Missing or invalid Authorization header"
    token = parts[1]

    try:
        payload = decode_token(token)
    except Exception as e:
        return None,f"Token decode error: {e}"

    # You stored the username in "username" when you generated the token, 
    # or in "sub" for your download‐token:
    user_id = payload.get("username") or payload.get("sub")
    if not user_id:
        return None,"Token missing user identity"
    return user_id,None
