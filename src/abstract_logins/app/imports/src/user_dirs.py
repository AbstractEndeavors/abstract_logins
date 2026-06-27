from .imports import *
from .auth_utils import *
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
def get_user_upload_dir(req=None, user_name=None, user_upload_dir=None):
    user_name = get_user_name(req=req, user_name=user_name)
    return os.path.join(USERS_DIR, user_name)

def get_user_from_path(path):
    if path.startswith(USERS_DIR):
        return path.split(USERS_DIR)[1].split('/')[0]
    return filepath.split('/')[0]
def get_glob_files(req=None,user_name=None,user_upload_dir=None):
    user_upload_dir = get_user_upload_dir(req=req,user_name=user_name,user_upload_dir=user_upload_dir)
    pattern = os.path.join(user_upload_dir, "**/*")  # include all files recursively
    glob_files = glob.glob(pattern, recursive=True)
    logger.info(f"glob_files == {glob_files}")
    return glob_files
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
def get_full_path(file_path: str, user: object = None,row: dict = None,req: object = None,data: object = None,user_name: object = None) -> Path:
    """
    Resolve a user's file path under /var/www/media/users/<uploader_id> safely.
    - file_path: user-supplied relative path (e.g., 'project/a.txt' or '../evil')
    - row: dict that may contain 'uploader_id'
    - user: object/str that may indicate the id via .id or itself
    """
    row = row or {}
    uploader_id = user or user_name or row.get("uploader_id") or get_uploader_id(req=req,data=data)
    if uploader_id is None:
       if user is not None:
           uploader_id = getattr(user, "id", user)
    if uploader_id is None:
       raise ValueError("uploader_id is required (provide via row['uploader_id'] or user)")

    user_dir = safe_join(USERS_DIR,str(uploader_id))
    # Ensure the user directory reference is real; create if you want:
    user_dir.mkdir(parents=True, exist_ok=True)

    # Return a safe, normalized absolute Path under the user_dir
    return safe_join(user_dir, file_path)
##def get_full_path(filepath: str, user_name: str) -> str:
##    user_dir = get_user_upload_dir(user_name=user_name)
##    return safe_join(user_dir, filepath)  # safe_join ensures no escape
##
