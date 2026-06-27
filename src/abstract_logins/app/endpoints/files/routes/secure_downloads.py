from ..imports import *
from flask import Response
import io
import zipfile


def send_via_nginx(abs_path: str, filename: str):
    """Return a response telling Nginx to serve the file directly."""
    rel_path = str(abs_path).split("/24T/media/")[-1]
    resp = Response()
    resp.headers["Content-Type"] = "application/octet-stream"
    resp.headers["Content-Disposition"] = f'attachment; filename="{filename}"'
    resp.headers["X-Accel-Redirect"] = f"/protected/{rel_path}"
    return resp


secure_download_bp, logger = get_bp("secure_download", __name__)


@secure_download_bp.route("/secure-files/download", methods=["GET", "POST"])
@login_required
def downloadFile():
    """Authenticated download (single file or ZIP for multiple)."""
    args, datas, username = get_args_jwargs_user_req(request)
    logger.info(datas)

    valid_files = []
    errors = []
    for data in make_list(datas):
        data = dict(data)
        abs_path = None
        filename = None

        filepath = data.get("filepath")
        if filepath:
            abs_path, filename = get_path_and_filename(filepath)

        filename = data.get("filename") or filename

        if not filename or not abs_path:
            abs_path, filename, err = get_download(data=data, username=username)
            if err:
                errors.append((filename, err))
                continue

        if isinstance(filename, int):
            errors.append((filename, "Invalid filename"))
            continue

        valid_files.append((abs_path, filename))

    if not valid_files:
        return get_json_call_response({"error": "NO_FILE_FOUND"}, 404)

    if len(valid_files) > 1:
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
            seen: dict = {}
            for path, name in valid_files:
                base, ext = os.path.splitext(name)
                unique = name
                counter = 1
                while unique in seen:
                    unique = f"{base}_{counter}{ext}"
                    counter += 1
                seen[unique] = True
                zf.write(path, unique)
                logger.info(f"Added {name} as {unique} to ZIP")
        zip_buffer.seek(0)
        if errors:
            logger.warning("Partial ZIP: " + "; ".join(f"{n}: {e}" for n, e in errors))
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name="downloads.zip",
            mimetype="application/zip",
        )

    abs_path, filename = valid_files[0]
    return send_file(abs_path, as_attachment=True, download_name=filename)


@secure_download_bp.route("/secure-files/secure-download", methods=["POST"])
@secure_download_bp.route("/secure-files/secure-download/", methods=["POST"])
@secure_download_bp.route("/secure-files/secure-download/<int:id>", methods=["GET", "POST"])
@secure_download_bp.route("/secure-files/secure-download/<int:id>/<string:pwd>", methods=["GET", "POST"])
def download_file(id: int = None, pwd: str = None):
    """Public (shareable) download endpoint."""
    initialize_call_log()
    search_map, data, row = get_searchmap_data_row(req=request)

    abs_path, filename, err = get_download(
        req=request, data=data, search_map=search_map, row=row
    )
    is_user = is_user_uploader(req=request, data=data)

    if err == "NO_FILE_FOUND":
        return get_json_call_response("No file found.", 404)
    if not is_user and err == "NOT_SHAREABLE":
        return get_json_call_response("Not shareable.", 403)
    if not is_user and err == "DOWNLOAD_LIMIT":
        return get_json_call_response("Download limit reached.", 403)

    file_id = data.get("id")
    if not is_user and err in ("PASSWORD_REQUIRED", "PASSWORD_INCORRECT"):
        return render_template(
            "enter_password.html",
            file_id=file_id,
            error="Incorrect password." if err == "PASSWORD_INCORRECT" else None,
        ), 401

    if not is_user:
        add_to_download_count(search_map)

    return send_via_nginx(abs_path, filename)


@secure_download_bp.route("/secure-files/secure-download/token/<token>")
@login_required
def download_with_token(token):
    """Token-gated download (link shared via email, etc.)."""
    initialize_call_log()
    try:
        data = decode_token(token)
    except jwt.ExpiredSignatureError:
        return get_json_call_response("Download link expired.", 410)
    except jwt.InvalidTokenError:
        return get_json_call_response("Invalid download link.", 400)

    if data["sub"] != get_user_name(request):
        return get_json_call_response("Unauthorized.", 403)

    return _serve_file(data["path"])
