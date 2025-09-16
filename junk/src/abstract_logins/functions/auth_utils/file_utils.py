from .query_utils import *
from ..imports import *
from .login_utils.token_utils import get_user_id_from_request
# functions/auth_utils/file_utils.py
from .query_utils import *
from ..imports import *
from .login_utils.token_utils import get_user_id_from_request
from abstract_paths.secure_paths.paths.directories import ABS_UPLOAD_ROOT  # add
from abstract_paths.secure_paths.paths.src_dir import ABS_UPLOAD_DIR       # add
from werkzeug.utils import secure_filename                                # add
from pathlib import Path                                                  # add
from abstract_logins.endpoints.files.secure_utils import (                # add: point to your helpers' real import path
    make_full_upload_path, get_path_and_filename
)
# Define metadata keys (example, adjust based on UPLOAD_ITEM_KEYS)
UPLOAD_ITEM_KEYS = {
    'filename': {'default': '', 'function': lambda path: os.path.basename(path)},
    'filepath': {'default': '', 'function': lambda path: path},
    'uploader_id': {'default': '', 'function': lambda req, user_name: user_name},
    'shareable': {'default': False},
    'download_count': {'default': 0},
    'download_limit': {'default': None},
    'share_password': {'default':False},
    'password_str': {'default':""},
    'created_at': {'default': None},
}

def get_req_data(req=None,data=None):
   if data:
      return data
   result = extract_request_data(req) or {}
   data = result.get('json',{})
   return data
def get_uploader_id(req=None,data=None):
   data = get_req_data(req=req,data=data)
   uploader_id = data.get('uploader_id')
   return uploader_id

def get_user_upload_dir(req, username: str, public: bool=False) -> str:
    # Build per-user roots under ABS_UPLOAD_DIR
    base = Path(ABS_UPLOAD_DIR) / username / ("Home" if public else "secureFiles")
    base.mkdir(parents=True, exist_ok=True)
    return str(base)

def get_glob_files(req=None, user_name=None, user_upload_dir=None):
    # Respect provided dir or compute secureFiles root
    root = user_upload_dir or get_user_upload_dir(req=req, username=user_name, public=False)
    pattern = os.path.join(root, "**", "*")
    return glob.glob(pattern, recursive=True)

def get_upload_items(req=None, user_name=None, user_upload_dir=None, include_untracked: bool=False):
    user_name = get_user_name(req=req, user_name=user_name)

    sql = """
        SELECT id, filename, filepath, uploader_id, shareable,
               download_count, download_limit, share_password, password_str, created_at
          FROM uploads
    """
    params = ()
    if user_name:
        sql += " WHERE uploader_id = %s"
        params = (user_name,)

    try:
        rows = select_distinct_rows(sql, *params) if params else select_distinct_rows(sql)
    except Exception as e:
        logger.error(f"Database error in get_upload_items: {e}")
        return []

    files = []
    # Files in DB store "filepath" relative to ABS_UPLOAD_DIR
    for row in rows:
        file = dict(row)
        abs_path = Path(ABS_UPLOAD_DIR) / file['filepath']
        file['fullpath'] = str(abs_path)
        files.append(file)

    if include_untracked:
        root = user_upload_dir or get_user_upload_dir(req=req, username=user_name, public=False)
        for full_path in get_glob_files(req=req, user_name=user_name, user_upload_dir=root):
            if os.path.isfile(full_path) and not any((Path(ABS_UPLOAD_DIR) / f['filepath']) == Path(full_path) for f in files):
                # create untracked entry
                fname = os.path.basename(full_path)
                rel = os.path.relpath(full_path, ABS_UPLOAD_DIR)
                new_file = {
                    'filename': fname,
                    'filepath': rel,
                    'uploader_id': user_name,
                    'shareable': False,
                    'download_count': 0,
                    'download_limit': None,
                    'share_password': False,
                    'password_str': "",
                }
                new_id = insert_untracked_file(new_file)
                new_file['id'] = new_id
                new_file['fullpath'] = full_path
                files.append(new_file)

    return files

def insert_untracked_file(file):
    query = """
        INSERT INTO uploads (
            filename, filepath, uploader_id, shareable,
            download_count, download_limit, share_password, password_str, created_at
        ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP)
        RETURNING id
    """
    params = (
        file['filename'], file['filepath'], file['uploader_id'], file['shareable'],
        file['download_count'], file['download_limit'], file['share_password'], file['password_str'],
    )
    new_row = select_rows(query, *params)
    if new_row and 'id' in new_row:
        return new_row['id']
    raise ValueError('Failed to create fileId: no ID returned from database')

def get_user_from_path(path):
    path = str(path or "")
    base = str(Path(ABS_UPLOAD_ROOT).resolve())
    try:
        rel = os.path.relpath(path, base)
    except Exception:
        return None
    parts = rel.split(os.sep)
    return parts[0] if parts else None
