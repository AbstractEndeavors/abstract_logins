from ..imports import *
secure_env_bp,logger = get_bp(
    "secure_env",
    __name__,
      # <-- everything in this Blueprint sits under /secure-files
)
@secure_env_bp.route("/api/secure-files/secure_env", methods=["POST"])
@secure_env_bp.route("/api/secure-files/secure_env/<path:path>/<path:key>", methods=["GET"])
def upload_file(path: str | None = None,key: str | None = None):
    initialize_call_log()
    request_data = extract_request_data(request)
    data = request_data.get('json')
    username = get_user_name(request)
    key = key or data.get('key')
    path = path or data.get('path')
    if path and os.path.splitext(path)[-1] == '.json' and os.path.isfile(path):
        content = safe_read_from_json(path)
        value = content.get(key)
        
    else:
        
        value = get_env_value(key=key,path=path)
    logger.info(data)
    logger.info(value)
    return jsonify(value), 200
