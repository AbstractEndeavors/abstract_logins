# secure_files.py
from ..imports import *
secure_login_bp,logger = get_bp(
    "secure_login",
    __name__,
    static_folder=ABS_HTML_AUTHS_FOLDER,   # <-- serve HTML out of here
)

@secure_login_bp.route("/login.html")
@secure_login_bp.route("/login")
def serve_login():
    return send_from_directory(ABS_HTML_AUTHS_FOLDER, "index.html")

@secure_login_bp.route("/api/secure-login", methods=["POST","GET"])
def login():
    #initialize_call_log()
    strings = ["username","password"]
    data = parse_and_spec_vars(request,strings)
    username = data.get("username", "").strip()
    password = data.get("password", "")
    
    if not username or not password:
        return get_json_call_response(
            value={"error": "Username and password required."},
            status_code=400
        )

    user = get_user(username)
    if user is None or not verify_password(password, user["password_hash"]):
        return get_json_call_response(
            value={"error": "Invalid username or password."},
            status_code=401
        )

    # Generate a JWT (payload includes username and is_admin flag)
    token = generate_user_token(username=user["username"], is_admin=user["is_admin"])
    return get_json_call_response(
        value={"token": token},
        status_code=200
    )
