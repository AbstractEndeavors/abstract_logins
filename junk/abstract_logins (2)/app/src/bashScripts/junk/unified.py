from .imports import *   # brings in: get_bp, login_required, get_request_data, get_user, verify_password,
                         # add_or_update_user, generate_token, get_json_call_response, initialize_call_log, etc.

secure_unified_bp, logger = get_bp(
    "secure_unified_bp",
    __name__,
    static_folder=STATIC_FOLDER,
    url_prefix=URL_PREFIX
)




@secure_unified_bp.route('/secure-files/download', methods=['GET'])
@login_required
def download_file():
    username = request.user['username']
    try:
        rows = select_rows(
            'SELECT id, filename, filepath, shareable, share_password, download_count, download_limit, uploader_id '
            'FROM uploads WHERE filepath = %s',
            (rel_path,)
        )
        if not rows:
            return get_json_call_response('File not found.', 404)
        row = rows[0]
    except Exception as e:
        return get_json_call_response('Database error.', 500, logMsg=f'DB error in download_file: {e}')

    if not row['shareable'] and row['uploader_id'] != username:
        return get_json_call_response('This file is not shareable.', 403)

    pwd_given = request.args.get('pwd')
    if row['share_password']:
        if not pwd_given:
            form_html = (
                '<html><body>'
                '<h3>Enter password to download:</h3>'
                '<form method="GET">'
                '  <input type="password" name="pwd" />'
                '  <button type="submit">Download</button>'
                '</form>'
                '</body></html>'
            )
            return form_html, 200
        if not verify_password(pwd_given, row['share_password']):
            return get_json_call_response('Incorrect password.', 401)

    if row['download_limit'] is not None and row['download_count'] >= row['download_limit']:
        return get_json_call_response('Download limit reached.', 410)

    try:
        insert_query(
            'UPDATE uploads SET download_count = download_count + 1 WHERE id = %s',
            (row['id'],)
        )
    except Exception as e:
        unified.logger.error(f'DB error incrementing download_count: {e}')

    absolute_path = os.path.join(ABS_UPLOAD_FOLDER, row['filepath'])
    if not os.path.isfile(absolute_path):
        return get_json_call_response('File not found on disk.', 404)

    return send_file(absolute_path, as_attachment=True, download_name=row['filename'])

@secure_unified_bp.route('/settings', methods=['POST'])
@login_required
def update_settings():
    data = request.get_json()
    if not data:
        return get_json_call_response('Missing JSON body.', 400)

    is_shareable = data.get('is_shareable')
    download_password = data.get('downloadPassword')
    max_downloads = data.get('maxDownloads')

    if is_shareable is None or download_password is None or max_downloads is None:
        return get_json_call_response('Required fields: is_shareable, downloadPassword, maxDownloads.', 400)

    username = request.user['username']
    try:
        rows = select_rows(
            'SELECT id, uploader_id FROM uploads WHERE filepath = %s',
            (rel_path,)
        )
        if not rows:
            return get_json_call_response('File not found.', 404)
        if rows[0]['uploader_id'] != username:
            return get_json_call_response('Not authorized.', 403)
        file_id = rows[0]['id']
    except Exception as e:
        return get_json_call_response('Database error.', 500, logMsg=f'DB error in update_settings: {e}')

    share_password = None
    if download_password.strip():
        share_password = bcrypt.hashpw(download_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    max_downloads = None if max_downloads == 0 else max_downloads
    try:
        insert_query(
            'UPDATE uploads SET shareable = %s, share_password = %s, download_limit = %s '
            'WHERE id = %s',
            (is_shareable, share_password, max_downloads, file_id)
        )
    except Exception as e:
        return get_json_call_response('Unable to update settings.', 500, logMsg=f'DB error in update_settings: {e}')

    return get_json_call_response('Settings updated.', 200)

@secure_unified_bp.route('/secure-files/files/<int:file_id>/share', methods=['PATCH'])
@login_required
def update_share_settings():
    data = parse_and_spec_vars(request,['file_id'])
    file_id = data.get('file_id')
    shareable = bool(data.get('shareable', False))
    pwd_plain = data.get('share_password')
    download_limit = data.get('download_limit')

    username = request.user['username']
    try:
        rows = select_rows(
            'SELECT uploader_id, download_count FROM uploads WHERE id = %s',
            (file_id,)
        )
        if not rows:
            return get_json_call_response('File not found.', 404)
        if rows[0]['uploader_id'] != username:
            return get_json_call_response('Not authorized.', 403)
        current_download_count = rows[0]['download_count']
    except Exception as e:
        return get_json_call_response('Database error.', 500, logMsg=f'DB error in update_share_settings: {e}')

    new_shareable = shareable
    new_pass_hash = None
    new_download_limit = None
    new_download_count = current_download_count

    if not new_shareable:
        new_download_count = 0
        new_download_limit = None
        new_pass_hash = None
    else:
        if isinstance(pwd_plain, str) and pwd_plain.strip():
            new_pass_hash = bcrypt.hashpw(pwd_plain.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        try:
            if download_limit is not None and int(download_limit) > 0:
                new_download_limit = int(download_limit)
        except (ValueError, TypeError):
            new_download_limit = None

    try:
        insert_query(
            'UPDATE uploads SET shareable = %s, share_password = %s, download_limit = %s, download_count = %s '
            'WHERE id = %s',
            (new_shareable, new_pass_hash, new_download_limit, new_download_count, file_id)
        )
    except Exception as e:
        return get_json_call_response('Unable to update share settings.', 500, logMsg=f'DB error in update_share_settings: {e}')

    return get_json_call_response('Share settings updated.', 200)

@secure_unified_bp.route('/secure-files/files/<int:file_id>/share-link', methods=['GET', 'POST'])
@login_required
def generate_share_link():
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


