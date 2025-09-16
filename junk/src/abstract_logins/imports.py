from __future__ import annotations
from typing import *
from pathlib import Path
from dotenv import load_dotenv
from datetime import datetime
import os,jwt,logging,glob,shutil, hashlib, argparse, time, sys,secrets, string
from abstract_utilities.time_utils import *
from abstract_security import get_env_value
from functools import wraps
from flask import has_request_context,Request
from abstract_ai import get_json_call_response,is_number
from abstract_queries import *
from abstract_database import insert_any_combo,update_any_combo,fetch_any_combo,remove_any_combo
from abstract_paths.secure_paths import *
from abstract_flask import *
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
from abstract_utilities import get_logFile,SingletonMeta
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QComboBox, QCheckBox, QMessageBox
)
from PyQt5.QtCore import QTimer, Qt
from abstract_logins.functions import *
from abstract_logins.functions.routes import (
    verify_password,
    ensure_users_table_exists
)
from abstract_logins.functions.auth_utils.user_store.table_utils.users_utils import (
    get_existing_users,
    get_user,
    add_or_update_user
    )
from abstract_logins.functions.auth_utils.query_utils import *
from abstract_logins.functions import *
# abstract_logins/config.py
from pathlib import Path

HOMES_BASE = Path("/var/www/html/media/homes")
USERS_BASE = Path("/var/www/html/media/users")

def user_root(username: str) -> Path:
    return USERS_BASE / username

def user_home(username: str) -> Path:
    return user_root(username) / "Home"

def user_secure(username: str) -> Path:
    return user_root(username) / "secureFiles"

# Base used for DB relative paths so you can store "username/subdir/file.ext"
ABS_UPLOAD_DIR = USERS_BASE  # NOTE: DB paths will be relative to USERS_BASE


logger = get_logFile(__name__)





