from .base_dir import *
USERS_DIR= get_media_dir('users')
def get_users_dir(path):
    return make_joined(USERS_DIR,path)
PUBLIC_USER_DIR = get_users_dir("public")
ADMIN_USER_DIR = get_users_dir("admin")
JOBEN_USER_DIR = get_users_dir("joben")
RNDM_USER_DIR = get_users_dir("joben")
##def make_public_user_dir(path):
##    return make_joined(PUBLIC_USER_DIR,path)
##def get_admin_user_dir(path):
##    return make_joined(ADMIN_USER_DIR,path)
##def get_joben_user_dir(path):
##    return make_joined(JOBEN_USER_DIR,path)
##def get_rndm_user_dir(path):
##    return make_joined(RNDM_USER_DIR,path)
##API_PREFIX = f"/api"
##UTILITIES_PREFIX = f"/utilities"
##MEDIA_PREFIX = f"/media"
##SECURE_FILES_PREFIX = "/api/secure-files"
##TEMPLATES_FOLDER = '/var/www/api/abstract_logins/app/src/templates'
##ABS_URL_PREFIX = SECURE_FILES_PREFIX
ABS_UPLOAD_DIR = "/mnt/24T/media/users"

