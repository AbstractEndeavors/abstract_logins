# secure_files.py

from ..auth_utils import (insert_query,
                          select_rows,
                          bcrypt_plain_text,
                          jwt_required,
                          get_jwt_identity)
from ..routes import *
secure_files_bp,logger = get_bp('secure_files',
                                __name__,
                                static_folder=STATIC_FOLDER,
                                url_prefix=URL_PREFIX)

# -----------------------------------------------
# 1) Use your connectionManager to get the DB URL
# -----------------------------------------------



# Base directory where uploaded files are stored (adjust if yours is elsewhere)

# ----------------- ROUTES -----------------

@secure_files_bp.route('/list', methods=['GET','POST'])
@jwt_required
def list_files():
    """
    GET /secure-files/list
    Returns JSON: an array of { id, filename, filepath, shareable, download_count, download_limit } for the current user.
    """
    user_id = get_jwt_identity()
    try:
       query = """
            SELECT
              id,
              filename,
              filepath,
              shareable,
              download_count,
              download_limit
            FROM uploads
            WHERE uploader_id = %s
            ORDER BY created_at DESC
        """
       rows = select_rows(query, user_id)
    except Exception as e:
        return get_json_call_response(value="Unable to fetch files.",
                                      logMsg=f"Error fetching uploads for user {user_id}: {e}",
                                      status_code=500)

    # We return exactly the fields the front end expects:
    files = [
        {
            "id":             row["id"],
            "filename":       row["filename"],
            "filepath":       row["filepath"],
            "shareable":      row["shareable"],
            "download_count": row["download_count"],
            "download_limit": row["download_limit"]
        }
        for row in rows
    ]
    return get_json_call_response(value=files,
                                      status_code=200)


@secure_files_bp.route('/files/<int:file_id>/share', methods=['PATCH'])
@jwt_required()
def update_share_settings(file_id):
    """
    PATCH /secure-files/files/<file_id>/share
    Body JSON: { shareable: bool, share_password: (string|null), download_limit: (int|null) }
    """
    user_id = get_jwt_identity()
    data = request.get_json(force=True)

    shareable     = bool(data.get('shareable', False))
    pwd_plain     = data.get('share_password')
    download_lim  = data.get('download_limit')

    # 1) Verify file exists and belongs to user
    try:
        query = """
            SELECT uploader_id, download_count
              FROM uploads
             WHERE id = %s
        """
        row = select_rows(query, (file_id,))
        if not row:
            return get_json_call_response("File not found.", status_code=404)

        row = row[0]  # Ensure you're using the dict result
        if row["uploader_id"] != user_id:
            return get_json_call_response("Not authorized to update.", status_code=403)

        current_download_count = row["download_count"]
    except Exception as e:
        return get_json_call_response("DB error.", logMsg=str(e), status_code=500)

    # 2) Decide new values
    new_pass_hash = None
    new_download_limit = None
    new_download_count = current_download_count if shareable else 0

    if shareable:
        if isinstance(pwd_plain, str) and pwd_plain.strip():
            new_pass_hash = bcrypt.hashpw(pwd_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            download_lim_int = int(download_lim)
            if download_lim_int > 0:
                new_download_limit = download_lim_int
        except:
            new_download_limit = None

    # 3) Update DB
    try:
        query = """
            UPDATE uploads
               SET shareable = %s,
                   share_password = %s,
                   download_limit = %s,
                   download_count = %s
             WHERE id = %s
        """
        insert_query(query, (
            shareable,
            new_pass_hash,
            new_download_limit,
            new_download_count,
            file_id
        ))
    except Exception as e:
        return get_json_call_response("Update failed.", logMsg=str(e), status_code=500)

    return get_json_call_response("Share settings updated.", status_code=200)



@secure_files_bp.route('/files/<int:file_id>/share-link', methods=['GET','POST'])
@jwt_required()
def generate_share_link():
    """
    POST /secure-files/files/<file_id>/share-link
    Confirms the file belongs to this user AND is shareable, then returns JSON { share_url: <url> }.
    """
    initialize_call_log()
    user_id = get_jwt_identity()
    kwargs = parse_and_spec_vars(request,['file_id'])
    file_id = kwargs.get('file_id')
    # 1) Verify ownership and shareable flag
    try:
        query="""
            SELECT shareable
              FROM uploads
             WHERE id = %s AND uploader_id = %s
        """, 
        row = select_rows(query,file_id, user_id)
        if row is None:
            return get_json_call_response(value ="File not found.",
                                          logMsg="File not found.",
                                          status_code=404)
        if not row.get("shareable"):
            return get_json_call_response(value="File is not shareable.",
                                          logMsg="File is not shareable.",
                                          status_code=403)
    
       
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in generate_share_link: {e}",
                                      status_code=500)

    # 2) Build the share URL (simply using the numeric ID as token)
    host = request.host_url.rstrip('/')
    share_url = f"{host}/secure-files/download/{file_id}"
    return get_json_call_response(value=share_url, status_code=200)



@secure_files_bp.route('/download/<int:token>', methods=['GET','POST'])
def download_file():
    """
    GET /secure-files/download/<token>
    Streams the file if shareable, enforces password (if any) and download_limit.
    If a password is required, returns a minimal HTML form. Otherwise, streams immediately.
    """
    pwd_given = request.args.get('pwd', None)
    data = parse_and_spec_vars(request,['token'])
    token = data.get('token')
    # 1) Lookup the row
    try:
        query = """
            SELECT filename, filepath, shareable, share_password, download_count, download_limit
              FROM uploads
             WHERE id = %s
        """
        row = select_rows(query, token)
        if row is None:
            return get_json_call_response(value ="File not found.",
                                          logMsg="File not found.",
                                          status_code=404)
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in download_file (fetch): {e}",
                                      status_code=500)

    # 2) Check shareable
    if not row["shareable"]:
        return get_json_call_response(value ="This file is not shareable.",
                                          logMsg="This file is not shareable.",
                                          status_code=403)

    # 3) Enforce password if set
    if row["share_password"]:
        if not pwd_given:
            value = (
                "<html><body>"
                "<h3>Enter password to download:</h3>"
                "<form method='GET'>"
                "  <input type='password' name='pwd' />"
                "  <button type='submit'>Download</button>"
                "</form>"
                "</body></html>"
            )
            # Return a minimal HTML form to collect the password
            return get_json_call_response(value =value,
                                          status_code=200)
        # Verify the given password
        try:
            valid = verify_password(plaintext=pwd_given.encode('utf-8'),
                            stored_hash=row.get("share_password",'').encode('utf-8'))

        except Exception as e:
            return  get_json_call_response(value="Server error verifying password.",
                                      logMsg=f"Server error verifying password.: {e}",
                                      status_code=500),

        if not valid:
            return get_json_call_response(value ="Incorrect password.",
                                          status_code=401)

    # 4) Check download limit
    if row["download_limit"] is not None and row["download_count"] >= row["download_limit"]:
        return get_json_call_response(value ="Download limit reached.",
                                          status_code=410)

    # 5) Increment download_count
    try:

        query = """
            UPDATE uploads
               SET download_count = download_count + 1
             WHERE id = %s
        """
        args = (token,)
        row = insert_query(query, token)
    except Exception as e:
        current_app.logger.error(f"DB error incrementing download_count: {e}")
        # Continue to streaming even if increment fails

    # 6) Stream the file from disk
    # filepath is stored relative to UPLOADS_DIR, e.g. "2025/06/01/abcd1234-report.pdf"
    absolute_path = os.path.join(UPLOADS_DIR, row["filepath"])
    if not os.path.isfile(absolute_path):
        return "File not found on disk.", 404

    # Flask’s send_file will set appropriate headers
    return send_file(
        absolute_path,
        as_attachment=True,
        download_name=row["filename"]
    )
