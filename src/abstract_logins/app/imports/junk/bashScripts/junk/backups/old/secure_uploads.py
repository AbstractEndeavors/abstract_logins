from ..routes import *
secure_uploads_bp, logger = get_bp('login_bp',
                          static_folder = ABS_PUBLIC_FOLDER)
@secure_uploads_bp.route("/secure-files/upload", methods=["POST"])
@login_required
def upload_file():
    """
    Expects a multipart/form-data POST with:
      - a file input named “file”
      - an optional form field “subdir”
    Saves the uploaded file under ABS_UPLOAD_FOLDER/<subdir>/
    Returns JSON { "message": "...", "path": "...relative path..." }
    """
    initialize_call_log()
    if "file" not in request.files:
        return jsonify({"message":"No file selected."}), 400

    f = request.files["file"]
    if f.filename == "":
        return jsonify({"message":"No file selected."}), 400

    # Let the user optionally specify a subdirectory (folder) under “uploads/”
    subdir = request.form.get("subdir", "").strip()
    # Sanitize subdir to avoid directory traversal:
    safe_subdir = secure_filename(subdir)  # if subdir="" this yields ""

    # Create the final directory: e.g. /var/.../uploads/safe_subdir
    target_folder = os.path.join(ABS_UPLOAD_FOLDER, safe_subdir)
    os.makedirs(target_folder, exist_ok=True)

    # Securely sanitize the filename
    filename = secure_filename(f.filename)
    if filename == "":
        return jsonify({"message":"Invalid filename."}), 400

    full_path = os.path.join(target_folder, filename)
    try:
        f.save(full_path)
    except Exception as e:
        return jsonify({"message":f"Error saving file: {e}"}), 500

    # Return the relative path so the client knows where it went
    rel_path = os.path.relpath(full_path, ABS_UPLOAD_FOLDER)
    return jsonify({
        "message": "File uploaded successfully.",
        "path": rel_path  # e.g. “myfolder/filename.png” or “filename.png”
    }), 200


# ──────────────────────────────────────────────────────────────────────────────
# 5) LIST FILES endpoint (NEW)
@secure_uploads_bp.route("/secure-files/list", methods=["GET"])
@login_required
def list_files():
    initialize_call_log()
    all_files = []
    for root, dirs, files in os.walk(ABS_UPLOAD_FOLDER):
        for fname in files:
            rel_path = os.path.relpath(os.path.join(root, fname), ABS_UPLOAD_FOLDER)
            all_files.append(rel_path)
    
    initialize_call_log()
    return get_json_call_response(all_files , 200,data=all_files)



# ──────────────────────────────────────────────────────────────────────────────
# 8) DOWNLOAD endpoint
#
#    Front-end constructs links like:
#      <a href="/secure-files/download/filename.ext">filename.ext</a>
#    or, if in a subdirectory:
#      <a href="/secure-files/download/subdir1/subdir2/picture.png">picture.png</a>
#
#    We use send_from_directory(...) to serve <ABS_UPLOAD_FOLDER>/<path:filename>,
#    forcing a file download.  If the file doesn’t exist, return 404.
#

@secure_uploads_bp.route("/secure-files/download/<path:rel_path>", methods=["GET"])
@login_required
def download_file(rel_path):
    initialize_call_log()
    

    # Build absolute path
    
    requested_path = os.path.join(ABS_UPLOAD_FOLDER, rel_path)

    # Prevent path-traversal
    requested_real = os.path.realpath(requested_path)
    allowed_base  = os.path.realpath(ABS_UPLOAD_FOLDER)
    if not (requested_real == allowed_base or requested_real.startswith(allowed_base + os.sep)):
        return abort(404)

    # Check existence
    if not os.path.isfile(requested_real):
        return abort(404)

    # Serve as attachment
    directory = os.path.dirname(requested_real)
    filename  = os.path.basename(requested_real)
    return send_from_directory(directory, filename, as_attachment=True)
