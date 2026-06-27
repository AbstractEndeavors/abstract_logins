from __future__ import annotations
import glob, os, shutil, hashlib ,jwt,logging, glob, json,unicodedata,hashlib
from abstract_utilities import get_logFile,safe_join
from abstract_utilities.type_utils import get_mime_type
from abstract_utilities.time_utils import *
from abstract_security import *
from abstract_ai import get_json_call_response,is_number
from abstract_queries import *
from abstract_database import insert_any_combo,update_any_combo,fetch_any_combo,remove_any_combo
from pathlib import Path
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask import Response, render_template, Blueprint, Request,  request, jsonify, abort, send_file, has_request_context
from werkzeug.datastructures import MultiDict, FileStorage
from werkzeug.utils import secure_filename
from typing import *
from abstract_flask import *
from .nufunctions import *
from .paths import *
logger = get_logFile(__name__)
##(
##    get_request_info,
##    get_ip_addr,
##    get_user_name,
##    get_user_filename,
##    get_safe_subdir,
##    get_subdir,
##    get_request_safe_filename,
##    get_request_filename,
##    get_request_file,
##    get_request_files
##    )
# /flask_app/login_app/endpoints/files/secure_files.py
##row = {'id': 1149,
##       'filename': 'checkbox.tsx',
##       'uploader_id': 'admin',
##       'filepath': 'admin/checkbox.tsx',
##       'created_at': 'Thu, 03 Jul 2025 23:40:25 GMT',
##       'download_count': 0,
##       'download_limit': None,
##       'shareable': False,
##       'needsPassword': False,
##       'share_password': None
##       }
def generate_file_id(path: str, max_length: int = 50) -> str:
    base = os.path.splitext(os.path.basename(path))[0]
    base = unicodedata.normalize('NFKD', base).encode('ascii', 'ignore').decode('ascii')
    base = base.lower()
    base = re.sub(r'[^a-z0-9]+', '-', base).strip('-')
    base = re.sub(r'-{2,}', '-', base)
    if len(base) > max_length:
        h = hashlib.sha1(base.encode()).hexdigest()[:8]
        base = base[: max_length - len(h) - 1].rstrip('-') + '-' + h
    return base
