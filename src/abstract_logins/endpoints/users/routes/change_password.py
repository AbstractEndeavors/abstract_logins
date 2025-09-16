# /flask_app/login_app/endpoints/users/routes.py
from ..imports import *   # brings in: get_bp, login_required, get_request_data, get_user, verify_password,
                         # add_or_update_user, generate_token, get_json_call_response, initialize_call_log, etc.
change_passwords_bp, logger = get_bp(
    "change_passwords",
    __name__,
)
# ------------------------------------------------------------
# 4) Change Password (already existing)
#    POST /secure-files/change-password
#    Body (JSON): { "currentPassword": "...", "newPassword": "..." }
#    Requires login_required → request.user is set
# ------------------------------------------------------------
@change_passwords_bp.route("/api/secure-files/secure-change-password", methods=["POST","GET","OPTIONS"])
@login_required
def change_password():
    #initialize_call_log()
    if request.method == "OPTIONS":
        return "OPTIONS", 200
    # parse_and_spec_vars(...) pulls out “username”, “currentPassword”, “newPassword” from JSON or form
    data = parse_and_spec_vars(request, ["currentPassword","newPassword"])
    current_password = data.get("currentPassword", "")
    new_password     = data.get("newPassword", "")

    # 1) Check if both passwords were provided
    if not current_password or not new_password:
        return get_json_call_response(
            value="Both currentPassword and newPassword are required.",
            status_code=400
        )

    # 2) Get the username from request.user
    username = request.user["username"]

    # 3) Load the user record from the database
    user = get_user(username)
    if user is None:
        return get_json_call_response(
            value="User not found.",
            status_code=404
        )

    # 4) Verify the provided currentPassword matches the stored hash
    if not verify_password(current_password, user["password_hash"]):
        return get_json_call_response(
            value="Current password is incorrect.",
            status_code=401
        )

    # 5) Finally, update the password
    try:
        add_or_update_user(
            username=username,
            plaintext_pwd=new_password,
            is_admin=user["is_admin"]
        )
    except Exception as e:
        return get_json_call_response(
            value={"error": "Error updating password."},
            status_code=500,
            logMsg=f"Error updating password: {e}"
        )

    return get_json_call_response(
        value="Password updated successfully.",
        status_code=200
    )


