# Routes
@unified.route('/secure-files/', methods=['GET'])
@unified.route('/secure-files/index', methods=['GET'])
@unified.route('/secure-files/index.html', methods=['GET'])
def secure_with_slash():
    return send_from_directory(ABS_HTML_FOLDER, 'index.html')

@unified.route('/secure-files/js/<path:filename>', methods=['GET'])
def serve_dist_js(filename):
    return send_from_directory(ABS_DIST_FOLDER, filename)

@unified.route('/secure-files/login.html', methods=['GET'])
@unified.route('/secure-files/login', methods=['GET'])
def override_login():
    return send_from_directory(ABS_HTML_AUTHS_FOLDER, 'login.html')

@unified.route('/secure-files/change_password.html', methods=['GET'])
def serve_change_password():
    return send_from_directory(ABS_HTML_FOLDER, 'change_password.html')

@unified.route('/secure-files/secure-login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return get_json_call_response('Username and password required.', 400)

    user = get_user(username)
    if not user or not verify_password(password, user['password_hash']):
        return get_json_call_response('Invalid username or password.', 401)

    access_token = create_access_token(identity=username)
    return get_json_call_response({'token': access_token}, 200)

@unified.route('/secure-files/secure-logout', methods=['POST'])
@login_required
def logout():
    auth_header = request.headers.get('Authorization', '')
    token = auth_header.split()[1]
    try:
        blacklist_token(token)
    except Exception as e:
        return get_json_call_response({'error': 'Error logging out.'}, 500, logMsg=f'Error blacklisting token: {e}')
    return get_json_call_response({'message': 'Logged out successfully.'}, 200)

@unified.route('/secure-files/secure-change-password', methods=['POST'])
@login_required
def change_password():
    data = request.get_json()
    current_password = data.get('currentPassword', '')
    new_password = data.get('newPassword', '')
    if not current_password or not new_password:
        return get_json_call_response('Both currentPassword and newPassword are required.', 400)

    username = request.user['username']
    user = get_user(username)
    if not user:
        return get_json_call_response('User not found.', 404)

    if not verify_password(current_password, user['password_hash']):
        return get_json_call_response('Current password is incorrect.', 401)

    try:
        add_or_update_user(username, new_password, user['is_admin'])
    except Exception as e:
        return get_json_call_response({'error': 'Error updating password.'}, 500, logMsg=f'Error updating password: {e}')
    return get_json_call_response('Password updated successfully.', 200)

@unified.route('/secure-files/list', methods=['GET'])
@login_required
def list_files():
    username = request.user['username']
    try:
        rows = select_rows(
            'SELECT id, filename, filepath, shareable, download_count, download_limit '
            'FROM uploads WHERE uploader_id = %s ORDER BY created_at DESC',
            (username,)
        )
    except Exception as e:
        return get_json_call_response('Unable to fetch files.', 500, logMsg=f'Error fetching uploads for user {username}: {e}')

    files = [
        {
            'id': row['id'],
            'filename': row['filename'],
            'rel_path': row['filepath'],
            'is_shareable': row['shareable'],
            'needsPassword': bool(row['share_password']),
            'download_count': row['download_count'],
            'max_downloads': row['download_limit'],
            'owner': username
        } for row in rows
    ]
    return get_json_call_response({'files': files}, 200)

@unified.route('/secure-files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return get_json_call_response('No file selected.', 400)

    f = request.files['file']
    if f.filename == '':
        return get_json_call_response('No file selected.', 400)

    subdir = request.form.get('subdir', '').strip()
    safe_subdir = secure_filename(subdir)
    target_folder = os.path.join(ABS_UPLOAD_FOLDER, safe_subdir)
    os.makedirs(target_folder, exist_ok=True)

    filename = secure_filename(f.filename)
    if filename == '':
        return get_json_call_response('Invalid filename.', 400)

    full_path = os.path.join(target_folder, filename)
    try:
        f.save(full_path)
    except Exception as e:
        return get_json_call_response(f'Error saving file: {e}', 500)

    rel_path = os.path.relpath(full_path, ABS_UPLOAD_FOLDER)
    username = request.user['username']
    try:
        insert_query(
            'INSERT INTO uploads (uploader_id, filename, filepath) VALUES (%s, %s, %s)',
            username, filename, rel_path
        )
    except Exception as e:
        return get_json_call_response(f'Error saving file metadata: {e}', 500)

    return get_json_call_response({'message': 'File uploaded successfully.', 'path': rel_path}, 200)

@unified.route('/secure-files/download/<path:rel_path>', methods=['GET'])
@login_required
def download_file(rel_path):
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

@unified.route('/secure-files/settings/<path:rel_path>', methods=['POST'])
@login_required
def update_settings(rel_path):
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

@unified.route('/secure-files/files/<int:file_id>/share', methods=['PATCH'])
@login_required
def update_share_settings(file_id):
    data = request.get_json()
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

@unified.route('/secure-files/files/<int:file_id>/share-link', methods=['GET', 'POST'])
@login_required
def generate_share_link(file_id):
    username = request.user['username']
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



