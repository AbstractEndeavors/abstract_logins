from datetime import datetime
from abstract_flask import *
from ..auth_utils.query_utils import *
from ..paths import *
import glob,os, shutil, hashlib
from abstract_utilities import get_logFile
from ..auth_utils.login_utils.token_utils import get_user_id_from_request
logger = get_logFile('file_utils')

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
from typing import Optional, Union
from flask import Request
from abstract_flask import (
    get_request_info,
    get_ip_addr,
    get_user_name,
    get_user_filename,
    get_safe_subdir,
    get_subdir,
    get_request_safe_filename,
    get_request_filename,
    get_request_file,
    get_request_files
    )
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

def is_user_uploader(req=None,data=None,user_id=None):
   if not user_id:
      user_id,user_err = get_user_id_from_request(req)
   uploader_id = get_uploader_id(req=req,data=data)
   return user_id and uploader_id and user_id == uploader_id
def get_user_upload_dir(req=None,user_name=None,user_upload_dir=None):
    user_name = user_name or get_user_name(req=req,user_name=user_name)
    user_upload_dir = user_upload_dir or os.path.join(ABS_UPLOAD_DIR, str(user_name))
    os.makedirs(user_upload_dir,exist_ok=True)
    return user_upload_dir
def get_glob_files(req=None,user_name=None,user_upload_dir=None):
    user_upload_dir = get_user_upload_dir(req=req,user_name=user_name,user_upload_dir=user_upload_dir)
    pattern = os.path.join(user_upload_dir, "**/*")  # include all files recursively
    glob_files = glob.glob(pattern, recursive=True)
    logger.info(f"glob_files == {glob_files}")
    return glob_files
def get_upload_items(
    req=None,
    user_name=None,
    user_upload_dir=None,
    include_untracked: bool = False
):
    user_name = get_user_name(req=req,user_name=user_name)
    #logger.info(f"user_name == {user_name}")
    # 1) build & run the query (all users if user_name is None)
    sql = """
        SELECT id, filename, filepath, uploader_id, shareable,
               download_count, download_limit, share_password, password_str,  created_at
        FROM uploads
    """
    params = ()
    if user_name:
        sql += " WHERE uploader_id = %s"
        params = (user_name,)

    try:
        rows = select_distinct_rows(sql, (user_name,))  # now returns List[Dict]
    except Exception as e:
        print(f"Database error in get_upload_items: {e}")
        return []

    # 2) map each tuple to a dict via zip
    keys = ['id', 'filename', 'filepath', 'uploader_id',
            'shareable', 'download_count', 'download_limit',
            'share_password','password_str' , 'created_at']
    files = []
    user_upload_dir = get_user_upload_dir(req=req,user_name=user_name,user_upload_dir=user_upload_dir)
    #logger.info(f"user_upload_dir == {user_upload_dir}")
    for row in rows:
        file = dict(row)     # safe, because row is already a dict
        file['fullpath'] = os.path.join(user_upload_dir, file['filepath'])
        #logger.info(f"user_upload_dir == {file['fullpath']}")
        files.append(file)

    # 3) optionally scan for untracked files (same as before)
    if include_untracked:
        glob_files = get_glob_files(req=req, user_name=user_name,
                                    user_upload_dir=user_upload_dir)
        for full_path in glob_files:
            #logger.info(f"full_path == {full_path}")
            if (os.path.isfile(full_path)
                and not any(f['filepath'] == full_path for f in files)
            ):
                new_file = {}
                for key, vals in UPLOAD_ITEM_KEYS.items():
                    val = vals.get('default')
                    fn  = vals.get('function')
                    if fn:
                        args = (full_path,) if key != 'uploader_id' else (req, user_name)
                        val = fn(*args)
                    new_file[key] = val
                new_file['id'] = create_file_id(**new_file)
                insert_untracked_file(new_file)
                files.append(new_file)

    return files
def insert_untracked_file(file):
    """Insert untracked filesystem file into uploads table."""

    query = """
        INSERT INTO uploads (
            filename, filepath, uploader_id, shareable, download_count, download_limit, 
            share_password,password_str , created_at
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        RETURNING id
    """
    params = (
        file['filename'],
        file['filepath'],
        file['uploader_id'],
        file['shareable'],
        file['download_count'],
        file['download_limit'],
        file['share_password'],
        file['password_str'],
    )
    result = select_rows(query, *params)
    if result and 'id' in result:
        return result['id']
    raise ValueError('Failed to create fileId: no ID returned from database')

def get_file_id(file_dict=None, row=None):
    """
    Derive the file ID from a file dictionary or row data.
    
    Args:
        file_dict (dict, optional): Dictionary containing file data (e.g., {'id': 123, 'filename': 'example.txt'}).
        row (dict, optional): Dictionary containing row data (e.g., {'fileId': '123'}).
    
    Returns:
        int: The numeric file ID.
    
    Raises:
        ValueError: If file ID cannot be derived from file_dict or row.
    """
    if file_dict and 'id' in file_dict and file_dict['id'] is not None:
        return int(file_dict['id'])  # Numeric ID from file dictionary
    if row and 'fileId' in row and row['fileId'] is not None:
        return int(row['fileId'])  # Numeric ID from row dictionary
    raise ValueError('Unable to derive fileId: no file.id or row.fileId')
def get_user_from_path(path):
    if path.startswith(ABS_UPLOAD_ROOT):
        return path.split(ABS_UPLOAD_ROOT)[1].split('/')[0]
    return filepath.split('/')[0]
def create_file_id(filename,
                   filepath,
                   uploader_id=None,
                   shareable=False,
                   download_count=0,
                   download_limit=None,
                   share_password=False,
                   password_str="",
                   req=None,
                   *args,
                   **kwargs):
    """
    Create a new file record in the uploads table and return its file ID.
    
    Args:
        filename (str): Name of the file (e.g., 'example.txt').
        filepath (str): File path (e.g., 'user1/example.txt').
        uploader_id (str): ID of the uploader (e.g., username).
        shareable (bool, optional): Whether the file is shareable. Defaults to False.
        share_password (str, optional): Password for sharing. Defaults to None.
        download_limit (int, optional): Maximum download limit. Defaults to None.
    
    Returns:
        int: The numeric file ID (id from uploads table).
    
    Raises:
            ValueError: If the file insertion fails or no ID is returned.
        """

    uploader_id= uploader_id or get_user_name(req=req,user_name=uploader_id) or get_user_from_path(filepath)
    shareable=shareable or False
    download_count=download_count or 0
    download_limit=download_limit or None
    share_password=share_password or False
    password_str=password_str or ""
    
    query = """
    INSERT INTO uploads (
        filename,
        filepath,
        uploader_id,
        shareable,
        download_count,
        download_limit,
        share_password,
        password_str,
        created_at
    ) VALUES (
        %s, %s, %s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP
    ) RETURNING id
"""
    params = (
        filename,
        filepath,
        uploader_id,
        shareable,
        download_count,  # Initial download_count
        download_limit,
        share_password,
        password_str
    )
    result = select_rows(query, *params)
    if result and 'id' in result:
        return result['id']
    raise ValueError('Failed to create fileId: no ID returned from database')
