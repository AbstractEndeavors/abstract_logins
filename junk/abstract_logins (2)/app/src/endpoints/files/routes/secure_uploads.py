from ...imports import *
import os

secure_upload_bp, logger = get_bp(
    "secure_upload_bp",
    __name__,
    url_prefix=ABS_URL_PREFIX
)

def get_upload_creds(req) -> tuple[str, "FileStorage"]:
    """
    Extracts and validates user_name and file from the request.
    Aborts with 400 if missing.
    """
    user_name = req.user.get("username")
    if not user_name:
        abort(400, description="Missing user_name")

    file = req.files.get("file")
    if not file or not file.filename:
        abort(400, description="No file provided")

    return user_name, file
@secure_upload_bp.route("/upload", methods=["POST"])
@secure_upload_bp.route("/upload/<path:rel_path>", methods=["POST", "GET"])
@login_required
def upload_file(rel_path: str | None = None):
    initialize_call_log()

    # 1) get and validate creds
    user_name, file = get_upload_creds(request)
    logger.info(f"user_name={user_name}")
    logger.info(f"file={file}")
    # 2) determine where to save
    logger.info(f"file.filename={file.filename}")
    original_file_path= file.filename
    dirname = os.path.dirname(original_file_path)
    basename = os.path.basename(original_file_path)
    safe_filename = secure_filename(basename)
    rel_path = os.path.join(dirname,safe_filename)
    user_dir = get_user_upload_dir(request, user_name)
    logger.info(f"original_file_path={original_file_path}")
    item_path = make_full_upload_path(user_dir,original_file_path)
    logger.info(f"item_path={item_path}")

    logger.info(f"safe_filename={safe_filename}")
    rel_path = rel_path or safe_filename
    logger.info(f"rel_path={rel_path}")
    
    logger.info(f"user_dir={user_dir}")
    full_path = make_full_upload_path(user_dir, rel_path)
    logger.info(f"Saving upload to {full_path}")

    # 3) save to disk
    file.save(full_path)

    # 4) record in DB
    db_path = os.path.relpath(full_path, ABS_UPLOAD_DIR)
    file_id = insert_any_combo(
        table_name="uploads",
        insert_map={
            "filename": safe_filename,
            "filepath": db_path,
            "uploader_id": user_name,
            "shareable": request.form.get("shareable", False),
            "download_count": request.form.get("download_count", 0),
            "download_limit": request.form.get("download_limit"),
            "share_password": request.form.get("share_password"),
        },
        returning="id",
    )

    # 5) return a consistent response
    return jsonify({
        "message":     "File uploaded successfully.",
        "filename":    safe_filename,
        "filepath":    db_path,
        "file_id":     file_id,
        "uploader_id": user_name,
    }), 200
