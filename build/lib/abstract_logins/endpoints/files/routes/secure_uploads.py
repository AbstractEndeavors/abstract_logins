from ..imports import *

secure_upload_bp, logger = get_bp(
    "secure_upload_bp",
    __name__
)
def clean_rel_path(path: str) -> str:
    # prevent Flask placeholders or traversal junk
    if "<" in path or ">" in path:
        return os.path.basename(path)
    return secure_filename(path)
def get_upload_creds(req) -> tuple[str, "FileStorage"]:
    """
    Extracts and validates user_name and file from the request.
    Aborts with 400 if missing.
    """
    user_name = req.user.get("username")
    if not user_name:
        abort(400, "Missing username")

    file = req.files.get("file")
    if not file or not file.filename:
        abort(400, description="No file provided")

    return user_name, file
@secure_upload_bp.route("/api/secure-files/upload", methods=["POST", "GET"], strict_slashes=False)
@login_required
def upload_file(rel_path: str | None = None):
    initialize_call_log()

    # 1) get and validate creds
    user_name, file = get_upload_creds(request)
    logger.info(f"user_name={user_name}")
    logger.info(f"file={file}")

    # 2) determine where to save
    is_public = user_name == "public"
    user_dir = get_user_upload_dir(request, user_name, user_upload_dir=is_public)

    route_rel = rel_path
    form_rel = request.form.get("rel_path")
    basename = secure_filename(file.filename or "file")

    rel = route_rel or form_rel or basename
    rel = clean_rel_path(rel)

    full_path = safe_join(user_dir, rel)
    file.save(full_path)  # ✅ save once only

    db_path = os.path.relpath(full_path, user_dir)


    file_id = insert_any_combo(
        table_name="uploads",
        insert_map={
            "filename": secure_filename(basename),
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
        "filename":    secure_filename(basename),
        "filepath":    db_path,
        "file_id":     file_id,
        "uploader_id": user_name,
    }), 200
