# /flask_app/login_app/endpoints/files/secure_files.py
from ..imports import *
# Correct get_bp signature:  get_bp(name, *, url_prefix=None, static_folder=None)
secure_files_bp, logger = get_bp(
    "secure_files_bp",
    __name__


)
@secure_files_bp.route("/api/secure-files/list", methods=["GET", "POST"], strict_slashes=False)
@login_required
def list_files():
    user_name = get_user_name(req=request)
    items = get_upload_items(
        req=request,
        user_name=user_name,
        include_untracked=False,   # ← skip the FS-scan on your "initial" list call
        prune_files=True
    )
    return get_json_call_response(items, 200)

@secure_files_bp.route("/api/secure-files/userInfo", methods=["GET", "POST"], strict_slashes=False)
@login_required
def list_user_info():
    user_name = get_user_name(req=request)
    user_dir = get_user_upload_dir(request, user_name)
    items = get_upload_items(
        req=request,
        user_name=user_name,
        include_untracked=False   # ← skip the FS-scan on your "initial" list call
    )
    data = {
        "user_name": user_name,
        "user_dir": user_dir,
        "list":items
        
    }
    return get_json_call_response(data, 200)



