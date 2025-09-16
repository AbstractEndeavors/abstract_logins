from .app import *
bp_list = [
    secure_env_bp,
    secure_login_bp,
    secure_files_bp,
    secure_users_bp,
    secure_views_bp,
    secure_upload_bp,
    secure_remove_bp,
    secure_logout_bp,
    secure_register_bp,
    secure_download_bp,
    secure_settings_bp,
    change_passwords_bp,
    secure_endpoints_bp,
    ]

import logging
from abstract_flask import *
from abstract_filepaths import *
from abstract_flask import main_flask_start
def login_app(allowed_origins=[],name="abstract_logins"):
    return get_Flask_app(name=name, bp_list=bp_list, allowed_origins=ALLOWED_ORIGINS)
