# /flask_app/login_app/endpoints/users/routes.py
from ..imports import *   # brings in: get_bp, login_required, get_request_data, get_user, verify_password,
                         # add_or_update_user, generate_token, get_json_call_response, initialize_call_log, etc.
secure_users_bp, logger = get_bp(
    "secure_user",
    __name__,
    static_folder=STATIC_FOLDER,
)
@secure_users_bp.route("/users", methods=["GET"])
@login_required
def list_users():
    #initialize_call_log()
    try:
        users = get_existing_users()
    except Exception as e:
        return get_json_call_response(
            value={"error": "Unauthorized user"},
            status_code=500,
            logMsg=f"Error fetching users: {e}"
        )

    return get_json_call_response(value=users,
                                  status_code=200)


@secure_users_bp.route("/admin/ip_lookup/<ip>")
@login_required  # restrict to admins
def ip_lookup(ip):
    rows = get_users_by_ip(ip)
    return jsonify(rows), 200



@secure_users_bp.route("/test", methods=["GET","POST"])
@login_required
def test_users():
    #initialize_call_log()
    username,user_err = get_user_id_from_request(req)

    return get_json_call_response(value=username,
                                  status_code=200)


