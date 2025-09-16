import os
def get_joined(*paths):
    joined_path = os.path.join(*paths)
    return joined_path
def make_joined(*paths):
    joined_path = get_joined(*paths)  # assumes returns a string path

    if not os.path.exists(joined_path):
        root, ext = os.path.splitext(joined_path)

        # Heuristic: if it ends with a separator, treat as dir regardless of ext
        if joined_path.endswith(os.sep):
            os.makedirs(joined_path, exist_ok=True)
        # If there is an extension, assume it's a file path: create parent dir
        elif ext:
            os.makedirs(os.path.dirname(joined_path) or ".", exist_ok=True)
        # Otherwise, treat as a directory path: create it directly
        else:
            os.makedirs(joined_path, exist_ok=True)

    return joined_path
ABS_BASE_DIR="/var/www/"
def get_base_dir(path):
    return get_joined(ABS_BASE_DIR, path)
MEDIA_DIR = get_base_dir('media')
def get_media_dir(path):
    return make_joined(MEDIA_DIR,path)
FUNCTIONS_DIR = get_base_dir('functions')
MODULES_DIR = get_base_dir('modules')
HTML_DIR = get_base_dir('html')
API_DIR = get_base_dir('api')
def get_functions_dir(path):
    return make_joined(FUNCTIONS_DIR,path)
def get_modules_dir(path):
    return make_joined(MODULES_DIR,path)
def get_html_dir(path):
    return make_joined(HTML_DIR,path)
def get_api_dir(path):
    return make_joined(API_DIR,path)



