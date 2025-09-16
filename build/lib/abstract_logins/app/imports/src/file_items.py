from .imports import *
from .user_dirs import *
from .constants import *
from ..secure_utils import *
def prune_missing_files(user_name: str | None = None, req=None) -> list[dict]:
    removed = []
    items = get_upload_items(req=req, user_name=user_name, include_untracked=False)

    for file in items:
        fullpath = file.get("fullpath")

        # Skip if fullpath is missing or invalid
        if not fullpath or not isinstance(fullpath, (str, bytes, os.PathLike)):
            logger.warning(f"Skipping prune: invalid fullpath for {file.get('filepath')}")
            continue

        if not os.path.isfile(fullpath):
            msg, err_code = secure_remove(data=file, username=file["uploader_id"])
            if msg:
                removed.append(msg)

    return removed
from abstract_paths.file_handlers.path_handlers import PathOutsideBase

def get_upload_items(
    req=None,
    user_name=None,
    user_upload_dir=None,
    include_untracked: bool = False,
    prune_files: bool = False
):
    user_name = get_user_name(req=req, user_name=user_name)
    if prune_files:
        prune_missing_files(user_name=user_name, req=req)

    sql = """
        SELECT id, filename, filepath, uploader_id, shareable,
               download_count, download_limit, share_password, password_str, created_at
        FROM uploads
    """
    params = ()
    if user_name:
        sql += " WHERE uploader_id = %s"
        params = (user_name,)

    rows = select_distinct_rows(sql, *params)
    files = []
    user_upload_dir = get_user_upload_dir(req=req, user_name=user_name, user_upload_dir=user_upload_dir)

    for row in rows:
        file = dict(row)
        try:
            file['fullpath'] = get_full_path(file['filepath'], user_name)
        except PathOutsideBase as e:
            logger.warning(f"Invalid file skipped: {file['filepath']} ({e})")
            # optional: prune from DB
            execute_query("DELETE FROM uploads WHERE id = %s", file["id"])
            continue
        except Exception as e:
            logger.warning(f"Unexpected path error for {file['filepath']}: {e}")
            continue

        if prune_files and not os.path.isfile(file['fullpath']):
            execute_query("DELETE FROM uploads WHERE id = %s", file["id"])
            continue

        files.append(file)

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
