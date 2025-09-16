# /flask_app/login_app/endpoints/files/secure_files.py

import glob
from flask import send_file
from abstract_utilities import get_logFile
from abstract_ocr.functions import generate_file_id


import os, shutil, hashlib
from pathlib import Path
logger = get_logFile('secure_delete')
ABS_UPLOAD_ROOT = "/var/www/abstractendeavors/secure-files/uploads"
# ------------------------------------------------------------------
# tiny util: streaming SHA-256 (keeps memory low for big files)
# ------------------------------------------------------------------



row = {'id': 1149, 'filename': 'checkbox.tsx', 'uploader_id': 'admin', 'filepath': 'admin/checkbox.tsx', 'created_at': 'Thu, 03 Jul 2025 23:40:25 GMT', 'download_count': 0, 'download_limit': None, 'shareable': False, 'needsPassword': False, 'share_password': None}
input(delete_from_user_dir(row))
