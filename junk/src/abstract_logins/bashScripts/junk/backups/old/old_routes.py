# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/routes.py
from ..imports import *
from .user_utils import *
# ──────────────────────────────────────────────────────────────────────────────
# 2) Hard‐code the absolute path to your “public/” folder, where index.html, login.html, main.js live:
# Make a folder named “uploads” parallel to “public”:


@login_bp.route("/secure-files/upload", methods=["POST"])
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
@login_bp.route("/secure-files/list", methods=["GET"])
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


# ──────────────────────────────────────────────────────────────────────────
# 6) Handle “/secure-files” (no trailing slash) → redirect to “/secure-files/”
@login_bp.route("/secure-files")
def secure_root_no_slash():
    initialize_call_log()
    # Permanent redirect or 302 is fine; we just want the trailing slash.
    return redirect("/secure-files/", code=302)

# ──────────────────────────────────────────────────────────────────────────
# 7) Handle “/secure-files/” exactly → serve index.html from static_folder
@login_bp.route("/secure-files/")
def secure_root_slash():
    initialize_call_log()
    # Flask’s send_static_file looks for "<static_folder>/index.html"
    # i.e. "/var/www/abstractendeavors/secure-files/public/index.html"
    return login_bp.send_static_file("index.html")

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

@login_bp.route("/secure-files/download/<path:rel_path>", methods=["GET"])
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
# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/routes.py

# … your existing imports …

@login_bp.route("/secure-files/settings/<path:rel_path>", methods=["POST"])
@login_required
def update_settings(rel_path):
    """
    Expects JSON body:
      {
        "is_shareable":   <bool>,
        "downloadPassword": "<string>" or "",
        "maxDownloads":   <int> or null
      }
    Updates the file metadata for <rel_path> (relative to ABS_UPLOAD_FOLDER).
    """
    data = request.get_json(force=True)
    initialize_call_log(data=data)
    # Validate existence of those keys:
    if data is None:
        return jsonify({"success": False, "message": "Missing JSON body."}), 400

    # Extract fields, providing defaults if not present:
    is_shareable = data.get("is_shareable", None)
    download_password = data.get("downloadPassword", None)
    max_downloads = data.get("maxDownloads", None)

    # You can choose to check types here if you like:
    if is_shareable is None or download_password is None or max_downloads is None:
        return (
            jsonify(
                {
                    "success": False,
                    "message": "Required fields: is_shareable, downloadPassword, maxDownloads.",
                }
            ),
            400,
        )

    # Now split rel_path into subdir / filename (to match how you store metadata)
    # e.g. if rel_path = "invoices/2025-01-01.pdf", then:
    import os

    subdir = ""
    filename = rel_path
    if "/" in rel_path:
        parts = rel_path.split("/")
        subdir = "/".join(parts[:-1])
        filename = parts[-1]

    username = request.user["username"]  # from @login_required

    # At this point, you need to call whatever database‐layer you have to update
    # the “files” table (or JSON, etc.). For example, if you have a function like:
    #   fileDb.updateFileSettings(owner, filename, subdir, { … })
    # then do something like:
    try:
        # Suppose you have a `fileDb.updateFileSettings` API (as in your Node example).
        # Here’s pseudocode—replace with your actual data‐store call:
        fileDb.updateFileSettings(
            owner=username,
            filename=filename,
            subdir=subdir,
            settings={
                "is_shareable": bool(is_shareable),
                # if downloadPassword is the empty string → clear the password;
                # otherwise hash & store it. (Implement as your DB/utility expects.)
                "downloadPassword": download_password.strip(),
                # If maxDownloads is None or 0 → interpret as unlimited, else store int.
                "max_downloads": None if (max_downloads is None or max_downloads == 0) else int(max_downloads),
            },
        )
    except Exception as e:
        # Log or inspect e as needed
        return jsonify({"success": False, "message": str(e)}), 500

    return jsonify({"success": True, "message": "Settings updated."})
