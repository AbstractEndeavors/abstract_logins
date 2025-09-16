# /flask_app/login_app/endpoints/files/secure_files.py
from ....imports import *
import glob
from flask import send_file
from abstract_ocr.functions import generate_file_id
# Correct get_bp signature:  get_bp(name, *, url_prefix=None, static_folder=None)
secure_filess_bp, logger = get_bp(
    "secure_filess_bp",
    __name__,
    url_prefix=URL_PREFIX,
    static_folder = STATIC_FOLDER
)
ABS_UPLOAD_ROOT = "/var/www/abstractendeavors/secure-files/uploads"



@secure_filess_bp.route("/upload", methods=["POST"])
@login_required
def upload_file():
    initialize_call_log()
    user_name = get_user_name(req=request)
    if not user_name:
        logger.error("Missing user_name")
        return jsonify({"message": "Missing user_name"}), 400

    if 'file' not in request.files:
        logger.error(f"No file in request.files: {request.files}")
        return jsonify({"message": "No file provided."}), 400

    file = request.files['file']
    if not file or not file.filename:
        logger.error("No file selected or empty filename")
        return jsonify({"message": "No file selected."}), 400

    filename = secure_filename(file.filename)
    if not filename:
        logger.error("Invalid filename after secure_filename")
        return jsonify({"message": "Invalid filename."}), 400

    user_upload_dir = get_user_upload_dir(req=request, user_name=user_name)
    safe_subdir = get_safe_subdir(req=request) or ''
    user_upload_subdir = os.path.join(user_upload_dir, safe_subdir)
    os.makedirs(user_upload_subdir, exist_ok=True)
    full_path = os.path.join(user_upload_subdir, filename)

    logger.info(f"Received: file={filename}, subdir={safe_subdir}")


    file.save(full_path)
    rel_path = os.path.relpath(full_path, ABS_UPLOAD_ROOT)
    file_id = create_file_id(
        filename=filename,
        filepath=rel_path,
        uploader_id=user_name,
        shareable=False
    )
    
    query = """
        INSERT INTO uploads (
            filename, filepath, uploader_id, shareable, download_count, download_limit, 
            share_password, created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        RETURNING id
    """
    params = (filename, rel_path, user_name, False, 0, None, None)
    insert_query(query, params)

    return jsonify({
        "message": "File uploaded successfully.",
        "path": rel_path,
        "file_id": file_id
    }), 200

@secure_filess_bp.route("/list", methods=["GET"])
@login_required
def list_files():
    initialize_call_log()
    user_name = get_user_name(req=request)
    logger.debug(f"List files for user: {user_name}, session: {request.cookies.get('session')}")
    try:
        query = """
            SELECT id, filename, filepath, shareable, download_count, download_limit
            FROM uploads
            WHERE uploader_id = %s
            ORDER BY created_at DESC
        """
        rows = select_rows(query, (user_name,))
        files = [
            {
                "id": row["id"],
                "filename": row["filename"],
                "rel_path": row["filepath"],
                "is_shareable": row["shareable"],
                "download_count": row["download_count"],
                "max_downloads": row["download_limit"]
            } for row in rows
        ]
        return jsonify({"files": files}), 200
    except Exception as e:
        logger.error(f"Error fetching files: {e}")
        return jsonify({"message": f"Unable to fetch files: {e}"}), 500

@secure_filess_bp.route("/download", methods=["GET", "POST"])
@login_required
def download_file():
    """
    GET /secure-files/download/<token>
    Streams the file if shareable, enforces password (if any) and download_limit.
    """
    initialize_call_log()
    data =parse_and_spec_vars(request,['file'])
    file_id = data.get('file')
    user_upload_dir = get_user_upload_dir(req=request)
    logger.info(f"Download request for file ID: {file_id}")
    # 6) Stream the file from disk
    absolute_path = os.path.join(user_upload_dir, file_id)
    if not os.path.isfile(absolute_path):
        return "File not found on disk.", 404

    # Flask’s send_file will set the headers for attachment download
    return send_file(
        absolute_path,
        as_attachment=True,
        download_name=os.path.basename(absolute_path)
    )
    # 1) Lookup the row
    try:
        query = """
            SELECT 
              filename, 
              filepath, 
              shareable, 
              share_password, 
              download_count, 
              download_limit
            FROM uploads
            WHERE id = %s
        """
        rows = select_rows(query, (token,))
        if not rows:
            return get_json_call_response(
                value="File not found.",
                logMsg="File not found.",
                status_code=404
            )
        row = rows[0]
    except Exception as e:
        return get_json_call_response(
            value="Database error.",
            logMsg=f"DB error in download_file (fetch): {e}",
            status_code=500
        )

    # 2) Check shareable
    if not row["shareable"]:
        return get_json_call_response(
            value="This file is not shareable.",
            logMsg="This file is not shareable.",
            status_code=403
        )

    # 3) Enforce password if set
    pwd_given = request.args.get("pwd")
    if row["share_password"]:
        if not pwd_given:
            form_html = (
                "<html><body>"
                "<h3>Enter password to download:</h3>"
                "<form method='GET'>"
                "  <input type='password' name='pwd' />"
                "  <button type='submit'>Download</button>"
                "</form>"
                "</body></html>"
            )
            return get_json_call_response(value=form_html, status_code=200)

        try:
            valid = verify_password(
                plaintext=pwd_given.encode("utf-8"),
                stored_hash=row.get("share_password", "").encode("utf-8")
            )
        except Exception as e:
            return get_json_call_response(
                value="Server error verifying password.",
                logMsg=f"Error verifying password: {e}",
                status_code=500
            )

        if not valid:
            return get_json_call_response(value="Incorrect password.", status_code=401)

    # 4) Check download limit
    if row["download_limit"] is not None and row["download_count"] >= row["download_limit"]:
        return get_json_call_response(value="Download limit reached.", status_code=410)

    # 5) Increment download_count
    try:
        update_q = """
            UPDATE uploads
               SET download_count = download_count + 1
             WHERE id = %s
        """
        insert_query(update_q, (token,))
    except Exception as e:
        current_app.logger.error(f"DB error incrementing download_count: {e}")
        # Even if this fails, we’ll still attempt to stream the file.

    # 6) Stream the file from disk
    absolute_path = os.path.join(ABS_UPLOAD_FOLDER, row["filepath"])
    if not os.path.isfile(absolute_path):
        return "File not found on disk.", 404

    # Flask’s send_file will set the headers for attachment download
    return send_file(
        absolute_path,
        as_attachment=True,
        download_name=row["filename"]
    )
