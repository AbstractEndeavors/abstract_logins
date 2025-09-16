# /flask_app/login_app/endpoints/files/secure_files.py
from ..imports import *
# Initialize Blueprint
secure_remove_bp,logger = get_bp(
    name="secure_remove",
    abs_path=__name__

)
@secure_remove_bp.route("/api/secure-files/remove", methods=["POST", "GET"])
@login_required
def remove_file():
    """
    Endpoint to remove a file securely.

    Expects JSON data with 'id', 'file_id', 'filepath', or 'rel_path'.
    Returns JSON response with status and message.
    """
    args, datas, username = get_args_jwargs_user_req(request)
    logger.info(f"username==={username}")
    results = []
    for data in make_list(datas):
        err = f"Remove file request: {data}"
        try:
            msg, err_code = secure_remove(data, username)
            logger.info()
        except Exception as e:
            err = f"Server error in remove_file: {e}"
            err_code =404
        #logger.error(err)
        #call_response = get_json_call_response(msg, err_code)
        #results.append(call_response)
    return get_json_call_response(True, 200)
@secure_remove_bp.route("/api/secure-files/remove_files", methods=["POST", "GET"])
@login_required
def removFile():
    """
    Endpoint to remove a file securely.

    Expects JSON data with 'id', 'file_id', 'filepath', or 'rel_path'.
    Returns JSON response with status and message.
    """
    result = extract_request_data(request)
    username = result.get('user')
    args = result.get('args', [])
    data = result.get('json',{})
    logger.info(f"username==={username}")
    args, datas, username = get_args_jwargs_user_req(request)
    logger.info(f"username==={username}")
    results = []
    for data in make_list(datas):
        logger.info(f"Remove file data: {data}")
        msg, err_code = secure_remove(data=data, username=username,req=request)
        logger.info(f"Remove file msg: {msg}")
        logger.info(f"Remove file err_code: {err_code}")
        call_response = get_json_call_response(msg, err_code)
        results.append(call_response)
    return get_json_call_response(True, 200)
