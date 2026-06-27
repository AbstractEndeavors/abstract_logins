from ..imports import *

secure_remove_bp, logger = get_bp(
    name="secure_remove",
    abs_path=__name__,
)


@secure_remove_bp.route("/secure-files/remove", methods=["POST", "GET"])
@login_required
def remove_file():
    """Remove one or more files. Expects JSON with 'id', 'filepath', or 'rel_path'."""
    args, datas, username = get_args_jwargs_user_req(request)
    logger.info(f"remove_file: username={username}")
    for data in make_list(datas):
        try:
            msg, err_code = secure_remove(data, username)
            logger.info(f"remove result: {msg} ({err_code})")
        except Exception as e:
            logger.error(f"remove_file error: {e}")
    return get_json_call_response(True, 200)


@secure_remove_bp.route("/secure-files/remove_files", methods=["POST", "GET"])
@login_required
def remove_files():
    """Bulk-remove files. Expects JSON with a list of file descriptors."""
    result = extract_request_data(request)
    username = result.get("user")
    data = result.get("json", {})
    for item in make_list(data):
        try:
            msg, err_code = secure_remove(data=item, username=username, req=request)
            logger.info(f"remove_files result: {msg} ({err_code})")
        except Exception as e:
            logger.error(f"remove_files error: {e}")
    return get_json_call_response(True, 200)
