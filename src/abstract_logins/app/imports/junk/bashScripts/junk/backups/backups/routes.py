#/flask_app/login_app/endpoints/users/routes.py
from ..routes import *

secure_users_bp, logger = get_bp(
    "secure_users_bp",
    __name__,
    static_folder=STATIC_FOLDER,

)

@secure_users_bp.route("/users", methods=["GET"])
@login_required
def list_users():
    initialize_call_log()
    try:
        users = get_existing_users()
    except Exception as e:
        return get_json_call_response(
            value={"error": "Unauthorized user"},
            status_code=500,
            logMsg=f"Error fetching users: {e}"
        )

    return get_json_call_response(value=users, status_code=200)


@secure_users_bp.route("/login", methods=["POST"])
def login():
    initialize_call_log()
    data = get_request_data(request)  # or request.get_json(force=True)
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

    token = generate_token(username=user["username"], is_admin=user["is_admin"])
    # Wrap the token in an object so the front‐end’s `json.token` finds it.
    return get_json_call_response(value={"token": token}, status_code=200)


@secure_users_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    initialize_call_log()
    data = get_request_data(request)
    current_password = data.get("currentPassword", "")
    new_password = data.get("newPassword", "")

    if not current_password or not new_password:
        return get_json_call_response(
            value={"error": "Both currentPassword and newPassword are required."},
            status_code=400
        )

    username = request.user["username"]
    user = get_user(username)
    if user is None:
        return get_json_call_response(value={"error": "User not found."}, status_code=404)

    if not verify_password(current_password, user["password_hash"]):
        return get_json_call_response(
            value={"error": "Current password is incorrect."},
            status_code=401
        )

    try:
        add_or_update_user(username=username, plaintext_pwd=new_password, is_admin=user["is_admin"])
    except Exception as e:
        return get_json_call_response(
            value={"error": "Error updating password"},
            status_code=500,
            logMsg=f"Error updating password: {e}"
        )

    return get_json_call_response(value={"message": "Password updated successfully."}, status_code=200)
