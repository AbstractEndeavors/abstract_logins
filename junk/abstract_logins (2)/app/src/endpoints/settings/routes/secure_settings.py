# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/routes.py
from ....imports import *
# ──────────────────────────────────────────────────────────────────────────────
# 2) Hard‐code the absolute path to your “public/” folder, where index.html, login.html, main.js live:
# Make a folder named “uploads” parallel to “public”:
from typing import Optional, Union, Dict, Any, List
from flask import Request
from werkzeug.datastructures import MultiDict, FileStorage
from abstract_database import update_any_combo,fetch_any_combo
import json


ensure_blacklist_table_exists()
secure_settings_bp, logger = get_bp('secure_settings',
                                    __name__,
                                    url_prefix=ABS_URL_PREFIX)
def get_settings_js():
    settings_js={
        "created_at":
           {
               "type":str,
               "default":str
               },
         "download_count":
           {
               "type":int,
               "default":0
               },
         "download_limit":
           {
               "type":int,
               "default":None
               },
         "filename":
           {
               "type":str,
               "default":None
               },
         "filepath":
           {
               "type":str,
               "default":None
               },
         "fullpath":
           {
               "type":str,
               "default":None
               },
         "id":
           {
               "type":int,
               "default":None
               },
         "share_password":
           {
               "type":str,
               "default":None
               },
         "shareable":
           {
               "type":bool,
               "default":False
               },
         "uploader_id":
           {
               "type":str,
               "default":"user"
               },
         "needsPassword":
           {
               "type":bool,
               "default":False
               },
         "share_password":
           {
               "type":str,
               "default":None
               },
        "password_str":
           {
               "type":str,
               "default":None
               },
         "download_limit":
           {
               "type":int,
               "default":None
               }
           }
    return settings_js
def get_settings_keys():
    return list(get_settings_js().keys())
SEARCH_KEYS = [
    "id"
    ]
UPDATE_KEYS = [
        "download_count",
        "download_limit",
        "share_password",
        "password_str",
        "shareable",
        "download_limit"
        ]
SHARE_KEYS = [
    "shareable"
    ]
PASS_KEYS = [
    "share_password"
    ]
DOWN_KEYS = [
    "download_limit"
    ]
ALL_KEYS = [
    SHARE_KEYS,
    PASS_KEYS,
    DOWN_KEYS
    ]
SETTINGS_KEYS = get_settings_keys()
def get_all_key_infos(req,search_map=False):
    username = req.user['username']
    data = parse_and_spec_vars(req,settings_keys)
    settings_js = get_settings_js()
    return_js = {}
    for settings_key,values in settings_js.items():
        if (not search_map) or (search_map and settiings_key in data):
            value = data.get(settings_key,values.get('default'))
            return_js[settings_key] = get_correct_type(settings_key,value)
    return return_js
def get_correct_type(key,value):
    values = settings_js.get(key)
    typ = values.get('type')
    if not isinstance(value,typ):
        try:
            value = typ(value)
        except Exception as e:
            logger.info(f"key {settings_key} with value {value} was unable to traneform to the type {typ} needed")
    return value
def get_correct_value(key,data,search_map=None):
    if key in data and search_map is not None:
        value = data.get(key)
        search_map[key]=get_correct_type(key,value)
    return search_map
settings_js = get_settings_js()
def get_search_map(data,search_keys=None):
    search_keys = search_keys or SEARCH_KEYS
    search_map = {}
    for key in search_keys:
        search_map = get_correct_value(
            key,
            data,
            search_map=search_map
            )
    return search_map
def get_update_map(key,data,update_map,all_keys=None):
    value = data.get(key) 
    all_keys = all_keys or ALL_KEYS
    for all_key_list in all_keys:
        if key in all_key_list:
            key = all_key_list[0]
            for sub_key in all_key_list:
                nu_value = update_map.get(sub_key)
                value = nu_value or value
            break
    return key,value


@secure_settings_bp.route('/files/share', methods=['PATCH','POST','GET'])
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

