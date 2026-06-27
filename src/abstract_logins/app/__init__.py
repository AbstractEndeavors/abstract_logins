from .imports import *
from .endpoints import (
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
    )
from .templates import *
#from .chats import secure_chat_bp
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
