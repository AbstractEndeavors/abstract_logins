from ..imports import *
# Initialize Blueprint
secure_register_bp,logger = get_bp(
    name="secure_register",
    abs_path=__name__,

)
@secure_register_bp.route("/registers", methods=["POST"])
@login_required
def registers_file():
    initialize_call_log()

    # 1) Get and validate user
    user_name = request.user.get("username")
    if not user_name:
        abort(400, description="Missing user_name")

    # 2) Get JSON data from request
    data = request.get_json()
    if not data:
        abort(400, description="No data provided")

    original_file_path = data.get("file_path")
    if not original_file_path or not os.path.exists(original_file_path):
        abort(400, description="Invalid or missing file_path")

    subdir = data.get("subdir", "").strip()  # Optional subdirectory, e.g., 'videos'

    # 3) Determine where to save (secure user dir)
    basename = os.path.basename(original_file_path)
    safe_filename = secure_filename(basename)
    rel_path = os.path.join(subdir, safe_filename) if subdir else safe_filename

    user_dir = get_user_upload_dir(request, user_name)
    full_path = make_full_upload_path(user_dir, rel_path)
    logger.info(f"Moving file from {original_file_path} to {full_path}")

    # 4) Move the file to the secure directory
    try:
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        shutil.move(original_file_path, full_path)
    except Exception as e:
        logger.error(f"File move failed: {e}")
        abort(500, description=f"File move failed: {str(e)}")

    # 5) Record in DB
        # 4) record in DB
    db_path = os.path.relpath(full_path, user_dir)
    file_id = insert_any_combo(
        table_name="uploads",
        insert_map={
            "filename": safe_filename,
            "filepath": db_path,
            "uploader_id": user_name,
            "shareable": data.get("shareable", False),
            "download_count": data.get("download_count", 0),
            "download_limit": data.get("download_limit"),
            "share_password": data.get("share_password"),
        },
        returning="id",
    )

    # 6) Return consistent response
    return jsonify({
        "message": "File registered successfully.",
        "filename": safe_filename,
        "filepath": db_path,
        "file_id": file_id,
        "uploader_id": user_name,
    }), 200


@secure_register_bp.route("/register", methods=["POST"])
@login_required
def register_file():
    initialize_call_log()
    datas,args,  username = get_args_jwargs_user_req(request)
    user_name = get_user_name(req=request)
    user_dir = get_user_upload_dir(request, user_name)
    logger.info(f"datas == {datas}\nusername == {username}\nargs == {args}\nser_name == {user_name}\nser_dir == {user_dir}")
    
    
    if not username:
        abort(400, "Missing user_name")

    user_dir    = get_user_upload_dir(request, username)  # e.g. /var/www/uploads/{username}
    upload_root = ABS_UPLOAD_DIR                          # e.g. /var/www/uploads

    if not os.path.isdir(user_dir):
        abort(400, "User upload directory does not exist")

    results = []

    # 1) Grab every file under user_dir
    glob_pattern = os.path.join(user_dir, "**")
    all_paths    = glob.glob(glob_pattern, recursive=True)
    file_paths   = [p for p in all_paths if os.path.isfile(p)]

    for file_path in file_paths:
        # split into directory + name
        root  = os.path.dirname(file_path)
        fname = os.path.basename(file_path)

        # make a safe filename
        safe_name = secure_filename(fname)

        # compute the DB‐relative path (preserving subdirs)
        rel_dir = os.path.relpath(root, upload_root)  # e.g. "admin/689368584017637"
        # 4) record in DB
        db_path = os.path.relpath(full_path, user_dir)

        # 2) Only skip if exact filepath already registered
        existing = fetch_any_combo(
            column_names="*",
            table_name="uploads",
            search_map={"uploader_id": username, "filepath": db_path}
        )
        if existing:
            results.append({"status":"exists", "filepath":db_path})
            continue

        # 3) (Optional) rename on disk if unsafe
        if fname != safe_name:
            new_disk = os.path.join(root, safe_name)
            os.rename(file_path, new_disk)
            file_path = new_disk
        
        # 4) Insert record
        insert_map = {
            "filename":      safe_name,
            "filepath":      db_path,
            "uploader_id":   username,
            "shareable":     datas.get("shareable", False),
            "download_count":datas.get("download_count", 0),
            "download_limit":datas.get("download_limit"),
            "share_password":datas.get("share_password"),
        }
        file_id = insert_any_combo(
            table_name="uploads",
            insert_map=insert_map,
            returning="id"
        )
        results.append({"status":"registered","file_id":file_id,"filepath":db_path})

    return jsonify(results), 200
