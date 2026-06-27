from .src import *
from .src.constants import *
def verify_password(raw_pwd: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(raw_pwd.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False
def get_jkwargs_req(req=None, data=None, username=None):
    if not req:
        args = {}
        data = data or {}
    else:
        args, data, username = get_args_jwargs_user_req(req=req, var_types={})
        # merge all sources into data (so .get('pwd') works)
        merged = get_all_args(req)
        if data and isinstance(data,list):
            data[0].update({k: v for k, v in merged.items() if v is not None})
        elif isinstance(data,dict):
            data.update({k: v for k, v in merged.items() if v is not None})
    return args, data, username
def get_pwd_req(req, data=None):
    key = 'pwd'
    data = data or {}
    # prefer form (you said it only comes from HTML)
    return (req.form.get(key) if req and req.method == 'POST' else None) \
           or data.get(key) \
           or (req.args.get(key) if req else None)
def get_pwd_given(req=None, data=None, username=None):
    args, data, username = get_jkwargs_req(req=req, data=data, username=username)
    pwd_given = get_pwd_req(req, data=data)
    return pwd_given, args, data, username
def if_number_within(integer, error_range):
    """
    Returns True if integer falls into the 'hundreds' bucket of error_range.
    error_range can be a single number (100, 200, …) or a (min, max) tuple/list.
    """
    try:
        integer = int(integer)
    except (TypeError, ValueError):
        return False

    # If they passed a range
    if isinstance(error_range, (list, tuple)) and len(error_range) == 2:
        int_min, int_max = map(int, error_range)
    # Single number ⇒ treat as [n, n+100)
    elif isinstance(error_range, (int, float)):
        int_min = int(error_range)
        int_max = int(error_range) + 100
    else:
        return False

    return int_min <= integer < int_max



def get_value_from_keys(data, keys):
    for key in keys or []:
        val = data.get(key)
        if val not in (None, ''):
            return val
    return None
def get_file_id_search_map(data, key, keys=None, search_map=None, typ=None):
    search_map = search_map or {}
    value = get_value_from_keys(data or {}, keys or [])
    if value is not None:
        if typ:
            try:
                value = typ(value)
            except Exception as e:
                logger.warning(f"Type cast failed for {key}={value!r} to {typ}: {e}")
                return search_map
        search_map[key] = value
    return search_map
def get_search_map_from_vars(data, search_map_vars=None, search_map=None):
    search_map = search_map or {}
    search_map_vars = search_map_vars or SEARCH_MAP_VARS
    for key, spec in search_map_vars.items():
        search_map = get_file_id_search_map(
            data,
            key,
            spec.get('keys', []),
            search_map=search_map,
            typ=spec.get('type')
        )
    return search_map


def get_search_map(req=None, data=None, search_map_vars=None, search_map=None, username=None):
    # build from merged data
    merged = {}
    if req:
        merged.update(get_all_args(req))
    if data:
        merged.update(data)
    return get_search_map_from_vars(merged, search_map_vars, search_map)


def get_file_inits(req=None, data=None, username=None):
    msg = get_search_map(req=req, data=data, username=username)
    logger.info(f"search_map == {msg}")
    if not msg or (isinstance(msg, dict) and 'error' in msg):
        return {"status_code": 400, "success": False, "error": "No data provided", **(msg or {})}

    pwd_given, args, data, username = get_pwd_given(req=req, data=data, username=username)
    return {"search_map": msg, "pwd": pwd_given, "args": args, "data": data, "username": username}
def getAnyCombo(search_map,columnNames):
    if not isinstance(search_map,dict):
        if is_number(search_map):
            search_map = {"id":search_map}
    columnNames = make_list(columnNames)
    result = fetch_any_combo(column_names=columnNames,
                                 table_name='uploads',
                                 search_map=search_map)
    if len(columnNames) == 1:
        result = result[0].get(columnNames[0])
    return result
def get_download_limit(search_map):
    download_limit = getAnyCombo(search_map,"download_limit")
    return int(download_limit or 0)
def get_download_count(search_map):
    download_count = getAnyCombo(search_map,"download_count")
    return int(download_count or 0)
def is_download_limit(search_map):
    download_limit = get_download_limit(search_map)
    if download_limit == 0:
        return False
    return download_limit
def is_download_limit_exceeded(search_map):
    download_limit = is_download_limit(search_map)
    if download_limit == False:
        return False
    download_count = get_download_count(search_map)
    if download_limit > download_count:
        return False
    return True
def add_to_download_count(search_map):
    download_count = get_download_count(search_map)
    update_any_combo(table_name='uploads',
                                  update_map={"download_count":download_count+1},
                                  search_map=search_map)

def check_password(pwd_given: Optional[str], share_password: Optional[str]) -> Tuple[bool, Optional[str]]:
    if not share_password:
        return True, None
    if not pwd_given:
        return False, 'PASSWORD_REQUIRED'
    if not verify_password(pwd_given, share_password):
        return False, 'PASSWORD_INCORRECT'
    return True, None
def getRowValue(req=None,data=None,search_map=None,row=None,key=None):
   search_map,data,row = get_searchmap_data_row(req=req,data=data,search_map=search_map,row=row)
   logger.info(f"row == {row}\n{key} == {row.get(key)}")
   if key:
       return row.get(key)
def update_if_not_None(data={},update_data={}):
   for key,value in update_data.items():
      initValue = data.get(key)
      if value != None and initValue == None:
        data[key] = value
   return data
def get_all_args(req):
    if req is None:
        return {}

    # If we already got a dict, just return it
    if isinstance(req, dict):
        return dict(req)

    # Otherwise assume it's a Flask request
    all_args = {}
    result = extract_request_data(req) or {}
    all_args.update(result.get("json", {}) or {})
    all_args.update(req.view_args or {})
    all_args.update(req.args or {})
    all_args.update(req.form or {})
    all_args.update(req.get_json(silent=True) or {})
    if req.files:
        for key, storage in req.files.items():
            all_args[key] = storage
    return all_args

def get_search_map_data(req=None,data=None,search_map=None):
   search_map = search_map or {}
   data = data or {}
   search_map_vars = ['id',"uploader_id","filepath"]
   all_args = get_all_args(req)
   data = update_if_not_None(data,all_args)
   data = update_if_not_None(data,search_map)
   user_id, user_err = get_user_id_from_request(request)
   data = update_if_not_None(data,{'user':user_id})
   for key in search_map_vars:
      dataVar = data.get(key)
      search_map = update_if_not_None(search_map,{key:dataVar})
   return search_map,data
def get_searchmap_data_row(req=None,data=None,search_map=None,row=None):
    search_map,data = get_search_map_data(req=req,data=data,search_map=search_map)
    logger.info(f"SEARCHMAP==={search_map}")
    if row == None:
        rows = fetch_any_combo(column_names='*', table_name='uploads', search_map=search_map)
        rows = rows or {}
        if isinstance(rows, list) and len(rows)>0:
            for row in rows:
                logger.info(f"ROW === {row}")
                allVars = True
                for key,value in search_map.items():
                    if str(row.get(key,'')) != str(value):
                        allVars = False
                        break
                if allVars:
                    break        
    data = update_if_not_None(data,{'filepath':row.get('filepath')})
    return search_map,data,row
def get_download(req=None,data=None,search_map=None,row=None,username=None):
    search_map,data,row = get_searchmap_data_row(req=req,data=data,row=row,search_map=search_map)

    filepath = getRowValue(
        req=req,
        data=data,
        search_map=search_map,
        row=row,
        key='filepath'
        )
    uploader_id = getAnyCombo(search_map,['uploader_id'])

    logger.info(f"search_map == {search_map}")
    logger.info(f"data == {data}")
    logger.info(f"row == {row}")
    logger.info(f"uploader_id == {uploader_id}")
    abs_path = get_full_path(filepath,user=uploader_id,row=row,req=req,data=data)
    abs_dir = os.path.dirname(abs_path)
    basename = os.path.basename(filepath)
    filename,ext = os.path.splitext(basename)

    if not abs_path:
        return abs_path, filename, 'NO_FILE_FOUND'
    is_user = is_user_uploader(req=req, data=data)
    if is_user:
        return abs_path, filename, None
    shareable = getRowValue(
        req=req,
        data=data,
        search_map=search_map,
        row=row,
        key='shareable'
        )
    if not shareable:
        return abs_path, filename, 'NOT_SHAREABLE'
    if is_download_limit_exceeded(search_map) == True:
        return abs_path, filename, 'DOWNLOAD_LIMIT'

    share_password = getRowValue(req=req, data=data, search_map=search_map, row=row, key='share_password')

    # IMPORTANT: pass req so form pwd is seen
    init = get_file_inits(req=req, data=data)      # ← was get_file_inits(data=data)
    ok, err = check_password(init.get('pwd'), share_password)
    if not ok:
        return abs_path, filename, err
    return abs_path, filename, None

def get_row(search_map, column_names="*", table_name="uploads",username=None,req=None):
    """
    Fetches a single row from the database based on search criteria.

    Args:
        data (dict): Request data to build the search map.
        column_names (str, optional): Columns to select. Defaults to "*".
        table_name (str, optional): Table to query. Defaults to "uploads".

    Returns:
        tuple: (row_data, status_code)
            - row_data (dict or str): Fetched row or error message.
            - status_code (int): HTTP status code.
    """
    

    

    rows = fetch_any_combo(
        column_names=column_names,
        table_name=table_name,
        search_map=search_map
    )

    if not rows:
        msg = {}
        msg["error"] = "No matching row found"
        msg["status_code"] = 404
        msg["success"] = False
        return msg,400
    if rows and isinstance(rows,list) and len(rows) == 1:
        rows = rows[0]
    return rows, 200

def secure_remove(data, username=None, column_names="*", table_name="uploads",req=None):
    """
    Removes a file record from the database if the user is authorized.

    Args:
        data (dict): Request data containing file ID or path.
        username (str): Username of the requester.
        column_names (str, optional): Columns to select. Defaults to "*".
        table_name (str, optional): Table to query. Defaults to "uploads".

    Returns:
        tuple: (message, status_code)
            - message (str or bool): Result message or True if successful.
            - status_code (int): HTTP status code.
    """
    search_map = {}
    for key in ["id","filename","uploader_id","filepath"]:
        value = data.get(key)
        if value:
            search_map[key] = value
    if not search_map:
        return get_output(error=msg.get("error"),status_code=400,sent=True) 
    row, status_code = get_row(search_map, column_names=column_names, table_name=table_name,username=username,req=req)
    if status_code != 200:
        return row, status_code

    uploader_id = row.get("uploader_id")
    logger.info(f"uploader_id==={uploader_id}")
    logger.info(f"username==={username}")
    if uploader_id.lower() != username.lower():
        return f"Unauthorized user: {uploader_id}", 403

    
    try:
        remove_any_combo(table_name=table_name, search_map=search_map)
        return True, 200
    except Exception as e:
        logger.error(f"Failed to remove file: {e}")
        return f"Removal failed: {str(e)}", 500
