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
def updateShareSettings():
    """
    PATCH /secure-files/files/<file_id>/share
    Body JSON: { shareable: bool, share_password: (string|null), download_limit: (int|null) }
    Only the owner may update. If shareable=false, clears password & limit & resets count.
    If shareable=true, optionally hashes share_password and sets download_limit.
    """
    user_id = get_jwt_identity()
    data = parse_and_spec_vars(request,['file_id','shareable','share_password','download_limit'])
    file_id = data.get('file_id')
    # Validate inputs
    shareable     = bool(data.get('shareable', False))
    pwd_plain     = data.get('share_password')      # string or None
    download_lim  = data.get('download_limit')      # int or None

    # 1) Fetch existing row to confirm ownership and get current download_count
    try:
        query="""
            SELECT uploader_id, download_count
              FROM uploads
             WHERE id = %s
        """, 
        row = select_rows(query,(file_id,))
        if row is None:
            return get_json_call_response(value="File not found.",
                                          logMsg=f"DB error in update_share_settings (fetch): {e}",
                                          status_code=404)
        user_value = row.get("uploader_id")
        if user_value != user_id:
            return get_json_call_response(value="Not authorized.",
                                          logMsg="File is not shareable.",
                                          status_code=403)
        current_download_count = row["download_count"]
    except Exception as e:
        return get_json_call_response(value="Database error.",
                                      logMsg=f"DB error in update_share_settings (fetch): {e}",
                                      status_code=500)


    # 2) Decide on new column values
    new_shareable     = shareable
    new_pass_hash     = None
    new_download_limit = None
    new_download_count = current_download_count

    if not new_shareable:
        # Disabling sharing → clear everything
        new_download_count = 0
        new_download_limit = None
        new_pass_hash      = None
    else:
        # Enabling sharing → maybe hash the new password
        if isinstance(pwd_plain, str) and pwd_plain.strip():
            new_pass_hash = bcrypt.hashpw(pwd_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        # If download_lim is a positive integer, use it; else treat as unlimited
        try:
            if download_lim is not None and int(download_lim) > 0:
                new_download_limit = int(download_lim)
        except (ValueError, TypeError):
            new_download_limit = None

    # 3) Perform the UPDATE
    try:
        query = """
            UPDATE uploads
               SET shareable      = %s,
                   share_password = %s,
                   download_limit = %s,
                   download_count = %s
             WHERE id = %s
        """
        args = (
            
        )
        insert_query(query, new_shareable,
                            new_pass_hash,
                            new_download_limit,
                            new_download_count,
                            file_id)

    except Exception as e:
        return get_json_call_response(value="Unable to update share settings.",
                                          logMsg=f"DB error in update_share_settings (update): {e}",
                                          status_code=500)

    return get_json_call_response(value="Share settings updated.",
                                      status_code=200)


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
