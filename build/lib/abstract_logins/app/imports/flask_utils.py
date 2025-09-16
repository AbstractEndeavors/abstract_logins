from .src import *
from .secure_utils import *

def send_download(abs_path: str, filename: str | None = None):
    # Always include extension in the name we tell the browser
    download_name = filename or os.path.basename(abs_path)

    # Guess using the actual path (better than bare filename)
    mime_type = get_mime_type(abs_path) or 'application/octet-stream'
    
    # Let Werkzeug/Gunicorn stream efficiently and set Content-Length
    return send_file(
        abs_path,
        as_attachment=True,
        download_name=download_name,
        mimetype=mime_type,
        conditional=True,
        max_age=0,
        etag=True,
        last_modified=None,
    )
secure_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000 per day", "10000 per hour"]
)
def serve_file(rel_path: str):
    # after all your checks…
    internal_path = f"/protected/{rel_path}"
    resp = Response(status=200)
    resp.headers["X-Accel-Redirect"] = internal_path
    # optionally set download filename:
    resp.headers["Content-Disposition"] = (
        f'attachment; filename="{os.path.basename(rel_path)}"'
    )
    return resp
