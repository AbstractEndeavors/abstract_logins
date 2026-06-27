from ..imports import *
# ──────────────────────────────────────────────────────────────────────────────
# 2) Hard‐code the absolute path to your “public/” folder, where index.html, login.html, main.js live:
# Make a folder named “uploads” parallel to “public”:


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
