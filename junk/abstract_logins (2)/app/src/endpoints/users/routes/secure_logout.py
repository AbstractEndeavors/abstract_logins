
# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/secure_files.py
from flask import request
from ...imports import *          # brings in get_bp, get_json_call_response, etc.

secure_logout_bp, logger = get_bp(
    "secure_logout_bp",
    __name__,
    static_folder=STATIC_FOLDER,
    url_prefix=API_URL_PREFIX# if you ever serve a logout.html, but can be unused
       # blueprint sits under /secure-files
)

@secure_logout_bp.route("/secure-logout", methods=["POST"])
@login_required
def logout():
    #initialize_call_log()

    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    # @login_required guarantees there is a valid Bearer token and it’s not blacklisted yet
    token = parts[1]

    try:
        blacklist_token(token)
    except Exception as e:
        logger.error(f"Error blacklisting token: {e}")
        return get_json_call_response(
            value={"error": "Error logging out."},
            status_code=500,
            logMsg=f"Error inserting into blacklist: {e}"
        )

    return get_json_call_response(
        value={"message": "Logged out successfully."},
        status_code=200
    )
