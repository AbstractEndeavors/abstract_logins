@secure_files_bp.route('/download', methods=['GET','POST'])
@login_required
def download_file(rel_path=None):
    initialize_call_log()
    keys = ['id', 'filename', 'filepath', 'shareable', 'share_password', 'download_count', 'download_limit', 'uploader_id']
    username = request.user['username']
    data = parse_and_spec_vars(request,keys)
    logger.info(data)
    rel_path = rel_path or data.get('rel_path')
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
