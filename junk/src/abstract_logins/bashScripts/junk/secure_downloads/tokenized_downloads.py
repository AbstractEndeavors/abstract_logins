from flask import Response
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ....imports import *
from .secure_downloads import secure_download_bp


secure_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)
@secure_download_bp.route("/download/token/<token>")
@secure_limiter.limit("10 per minute")
@login_required
def download_with_token(token):
    try:
        data = decode_token(token)
    except jwt.ExpiredSignatureError:
        return get_json_call_response("Download link expired.", 410)
    except jwt.InvalidTokenError:
        return get_json_call_response("Invalid download link.", 400)
    # Check that the token’s user matches the logged-in user
    if data["sub"] != get_user_name(request):
        return get_json_call_response("Unauthorized.", 403)
    # Then serve exactly like before, using data["path"]
    return _serve_file(data["path"])

def _serve_file(rel_path: str):
    # after all your checks…
    internal_path = f"/protected/{rel_path}"
    resp = Response(status=200)
    resp.headers["X-Accel-Redirect"] = internal_path
    # optionally set download filename:
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{os.path.basename(rel_path)}"'
    )
    return resp





