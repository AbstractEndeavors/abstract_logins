# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/routes.py
from ....imports import *
ensure_blacklist_table_exists()
secure_settings_bp, logger = get_bp('secure_settings',
                                    __name__,)

@secure_settings_bp.route('/api/secure-files/files/share', methods=['PATCH','POST','GET'])
@login_required
def share_settings():
    #initialize_call_log()
   
    request_data = extract_request_data(request)
    data = request_data.get('json')
    logger.info(f"data == {data}")
    username = request.user['username']
    data = request.get_json() or {}
    """
    PATCH /files/share
    Body JSON:
      {
        "id":               <int>,
        "shareable":        <bool>,
        "share_password": "<string>" or "",  # renamed for clarity; use share_password
        "download_limit":   <int> or null
      }
    """
    file_id = data.get('id')
#try:
    update_map={}
    search_map=get_search_map(data)
    logger.info(f"search_map == {search_map}")
    if search_map:
        row = fetch_any_combo(
            column_names='*',
            table_name='uploads',
            search_map=search_map
            )
        if isinstance(row,list) and len(row) ==1:
            row = row[0]
        total_row = row.copy()
        if row.get('uploader_id') != username:
            return jsonify(message="Forbidden"), 403
        if not row:
            return jsonify(message="File not found"), 404
        for key in UPDATE_KEYS:
            if key in data:
                key,value = get_update_map(
                    key,
                    data,
                    update_map,
                    ALL_KEYS
                    )
                update_map[key] = value
                total_row[key] = value
            
        logger.info(f"update_map == {update_map}")
        if update_map:
            update_map['id']=file_id
            share_password = total_row.get("share_password")
            password_str = total_row.get("password_str")
            logger.info(f"SHARE_PASSWORD == {share_password}")
            download_url=None
            shareable = total_row["shareable"]
            fullpath = total_row.get('fullpath')
            if not shareable:
                for key in ["download_limit","share_password"]:
                    if total_row[key] is not None:
                        update_map[key] = None
                        total_row[key] = None
            
            token = generate_download_token(
                  username=username,
                  rel_path=fullpath,
                  exp=3600*24
                      )
            if share_password:
                logger.info("Got new downloadPassword, hashing before save")
                pass_hash = bcrypt.hashpw(
                    password_str.encode("utf-8"),
                    bcrypt.gensalt()
                ).decode("utf-8")
                update_map["share_password"] = pass_hash
                update_map["password_str"] = password_str

            download_url = url_for(
                'secure_download_bp.download_with_token',
                token=token,
                _external=True
            )
            # now persist *all* of update_map, including our new hash
            update_any_combo(
                table_name='uploads',
                update_map=update_map,
                search_map=search_map
            )
            response = {"message": "Settings updated"}
            if download_url:
                response["download_url"] = download_url.replace('/api/secure-files/','/api/secure-files/').replace('/download/','/secure-download/')
            return jsonify(response), 200
        else:
            return jsonify(message="no settings to update"), 404
    else:
        return jsonify(message="no settings to update"), 404  
#except Exception as e:
#    logger.error(f"DB error: {e}")
#    return jsonify({"message": "Unable to update settings"}), 500

