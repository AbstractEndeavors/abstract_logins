@secure_files_bp.route('/files/<int:file_id>/share-link', methods=['GET', 'POST',"PATCH"])
@login_required
def generateShareLink():
    initialize_call_log()
    username = request.user['username']
    data = parse_and_spec_vars(request,['file_id'])
    file_id = data.get('file_id')
    try:
        rows = select_rows(
            'SELECT shareable FROM uploads WHERE id = %s AND uploader_id = %s',
            (file_id, username)
        )
        if not rows:
            return get_json_call_response('File not found.', 404)
        if not rows[0]['shareable']:
            return get_json_call_response('File is not shareable.', 403)
    except Exception as e:
        return get_json_call_response('Database error.', 500, logMsg=f'DB error in generate_share_link: {e}')

    host = request.host_url.rstrip('/')
    share_url = f'{host}/secure-files/download/{file_id}'
    return get_json_call_response(share_url, 200)


@secure_files_bp.route('/files/<int:file_id>/share', methods=['PATCH'])
@login_required
def updateShareSettings(file_id):
    user_id = get_jwt_identity()
    data = request.get_json(force=True) or {}

    shareable = bool(data.get('shareable', False))
    pwd_plain = data.get('share_password')
    download_lim = data.get('download_limit')

    try:
        row = select_one(
            "SELECT uploader_id, download_count FROM uploads WHERE id=%s",
            (file_id,)
        )
        if not row:
            return get_json_call_response("File not found.", 404)
        if (row['uploader_id'] or "") != user_id:
            return get_json_call_response("Not authorized.", 403)
        current_count = row['download_count'] or 0
    except Exception as e:
        return get_json_call_response("Database error.", 500, logMsg=f"{e}")

    new_shareable = shareable
    new_pass_hash = None
    new_limit = None
    new_count = current_count

    if not new_shareable:
        new_count = 0
    else:
        if isinstance(pwd_plain, str) and pwd_plain.strip():
            new_pass_hash = bcrypt.hashpw(pwd_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            if download_lim is not None and int(download_lim) > 0:
                new_limit = int(download_lim)
        except Exception:
            new_limit = None

    try:
        execute_sql(
            """
            UPDATE uploads
               SET shareable=%s, share_password=%s, download_limit=%s, download_count=%s
             WHERE id=%s
            """,
            (new_shareable, new_pass_hash, new_limit, new_count, file_id)
        )
    except Exception as e:
        return get_json_call_response("Unable to update share settings.", 500, logMsg=f"{e}")

    # optional: return a link
    host = request.host_url.rstrip('/')
    share_url = f"{host}/secure-files/download/{file_id}"
    return get_json_call_response({"message": "Share settings updated.", "share_url": share_url}, 200)
@secure_files_bp.route('/files/<int:file_id>/share-link', methods=['GET','POST'])
@login_required
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
