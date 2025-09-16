# /flask_app/login_app/endpoints/files/secure_files.py
from ....imports import *
import glob
from flask import send_file
from abstract_ocr.functions import generate_file_id
# Correct get_bp signature:  get_bp(name, *, url_prefix=None, static_folder=None)
secure_files_bp, logger = get_bp(
    "secure_files_bp",
    __name__,
    url_prefix=ABS_URL_PREFIX

)



@secure_files_bp.route("/list", methods=["POST","GET"])
@login_required
def list_files():
    user_name = get_user_name(req=request)
    items = get_upload_items(
        req=request,
        user_name=user_name,
        include_untracked=False   # ← skip the FS-scan on your "initial" list call
    )
    return get_json_call_response(items, 200)


