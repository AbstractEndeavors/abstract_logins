from flask import Response,render_template
import logging
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from ...imports import *
from ..secure_utils import *
from abstract_utilities.type_utils import get_mime_type
secure_download_bp, logger = get_bp(
    "secure_download",
    __name__,
    static_folder=STATIC_FOLDER,
    url_prefix=ABS_URL_PREFIX,
    template_folder='/var/www/api/abstract_logins/app/src/templates'
)
def get_args_jwargs_user_req(req,var_types={}):
   result = extract_request_data(req)
   data = result.get('json', {})
   args = result.get('args', [])
   username = get_user_id_from_request(req)

   return args,data,username
def _send_download(abs_path: str, filename: str | None = None):
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
@secure_download_bp.route("/download", methods=["GET", "POST"])
@login_required
def downloadFile():
    initialize_call_log()
    args, data, username = get_args_jwargs_user_req(request)
    items = make_list(data)

    valid = []
    errors = []

    for item in items:
        item = dict(item)
        # If caller gave direct filepath, try it; else go through get_download
        filepath = item.get("filepath")
        filename = item.get("filename")

        abs_path = None
        err = None

        if filepath:
            abs_path, _ = get_path_and_filename(filepath)
            if not abs_path:
                err = "NO_FILE_FOUND"
        if not abs_path:
            abs_path, filename, err = get_download(req=request, data=item)

        if err:
            errors.append({"item": item, "error": err})
            continue
        if not abs_path or not filename or isinstance(filename, int):
            errors.append({"item": item, "error": "INVALID_ENTRY"})
            continue

        valid.append((abs_path, filename))

    if not valid:
        return get_json_call_response({"error": "NO_FILE_FOUND", "errors": errors}, 404)

    if len(valid) == 1:
        abs_path, filename = valid[0]
        return _send_download(abs_path, filename)

    # Multi → ZIP
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        used = set()
        for abs_path, filename in valid:
            base, ext = os.path.splitext(filename)
            candidate = filename
            i = 1
            while candidate in used:
                candidate = f"{base}_{i}{ext}"
                i += 1
            used.add(candidate)
            zf.write(abs_path, candidate)
    zip_buffer.seek(0)
    return send_file(zip_buffer, as_attachment=True, download_name="downloads.zip", mimetype="application/zip")


@secure_download_bp.route('/secure-download', methods=['POST'])
@secure_download_bp.route('/secure-download/', methods=['POST'])
@secure_download_bp.route('/secure-download/<int:id>', methods=['GET','POST'])
@secure_download_bp.route('/secure-download/<int:id>/<string:pwd>', methods=['GET','POST'])
def download_file(id: int=None,pwd:str =None):
    initialize_call_log()
    search_map,data,row = get_searchmap_data_row(req=request)
 
    abs_path, filename, err = get_download(req=request,
                                           data=data,
                                           search_map=search_map,
                                           row=row
                                           )
    is_user = is_user_uploader(req=request, data=data)

    # handle missing file or other checks
    if err == 'NO_FILE_FOUND':
        return get_json_call_response('No file found.', 404)
    if not is_user and err == 'NOT_SHAREABLE':
        return get_json_call_response('Not shareable', 403)
    if not is_user and err == 'DOWNLOAD_LIMIT':
        return get_json_call_response('download limit reached', 403)

    # Password flow
    share_password = getRowValue(
        req=request,
        data=data,
        search_map=search_map,
        row=row,
        key='share_password'
        )
    file_id = data.get('id')
    if not is_user and err in ('PASSWORD_REQUIRED', 'PASSWORD_INCORRECT'):
          return render_template(
              'enter_password.html',
              file_id=file_id,
              error='Incorrect password.' if err == 'PASSWORD_INCORRECT' else None
          ), 401
    # increment count (non-owner)
    if not is_user:
        add_to_download_count(search_map)
        

    # owners or password-valid → send
    return _send_download(abs_path, filename)

    # Handle multiple file download (POST request)
    if request.method == 'POST':
        # Get file_ids from JSON payload or form data
        file_ids = data.get('file_ids', [])
        
        logger.info(f"abs_path, filename, err == {abs_path} {filename} {err}")

        
        if not file_ids:
           if 'file_ids' in request.form:
               file_ids = request.form['file_ids'].split(',')
           else:
               return get_json_call_response('No file_ids provided.', 400)

        if not file_ids:
            return get_json_call_response('No files specified.', 400)

        logger.info(f"Multiple file download requested: file_ids={file_ids}")

        # Validate and collect files
        valid_files = []
        errors = []
        for fid in file_ids:
            abs_path, filename, err = get_download(request)
            if err:
                errors.append((filename, err))
                continue
            if isinstance(filename, int):
                errors.append((filename, 'Invalid filename'))
                continue
            valid_files.append((abs_path, filename))

        # Handle errors
        if not valid_files and errors:
            error_msg = '; '.join([f"{fid}: {err}" for fid, err in errors])
            return get_json_call_response(f"Failed to download files: {error_msg}", 403)

        # Create ZIP archive in memory
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
            for abs_path, filename in valid_files:
                # Ensure unique filenames in ZIP (handle duplicates)
                base, ext = os.path.splitext(filename)
                counter = 1
                unique_filename = filename
                while unique_filename in [f[1] for f in valid_files[:len(valid_files)-1]]:
                    unique_filename = f"{base}_{counter}{ext}"
                    counter += 1
                zip_file.write(abs_path, unique_filename)
                logger.info(f"Added {filename} to ZIP as {unique_filename}")

        zip_buffer.seek(0)

        # Log partial errors if any
        if errors:
            error_msg = '; '.join([f"{filename}: {err}" for fid, err in errors])
            logger.warning(f"Partial success: {error_msg}")

        # Send ZIP file
        zip_buffer.seek(0)
        return send_file(
            zip_buffer,
            as_attachment=True,
            download_name='downloads.zip',
            mimetype='application/zip'
        )
secure_limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["10000 per day", "10000 per hour"]
)
@secure_download_bp.route("/secure-download/token/<token>")
@secure_limiter.limit("10000 per hour")
@login_required
def download_with_token(token):
    initialize_call_log()
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
