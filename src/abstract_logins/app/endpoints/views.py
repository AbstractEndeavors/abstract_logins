from ..imports import *
secure_views_bp, logger = get_bp(
    "secure_views_bp",
    __name__,
    url_prefix=SECURE_FILES_PREFIX  # "/secure-files"
)
def _serve_index():
    initialize_call_log()
    
    return send_from_directory(ABS_HTML_INDEX_DIR, "index.html")
def register_index_routes(bp, prefix=""):
    variants = [
        ("/index.html",       True),
        ("/index",            True),
        ("/",                 False),
    ]

    def make_endpoint(path):
        # convert "/index.html" → "secure_index_index_html"
        ep = f"secure_index{path}"
        ep = ep.replace("/", "_").replace(".", "_")
        if not ep.isidentifier():
            # just in case, strip any left-over odd chars
            ep = "".join(ch for ch in ep if ch.isalnum() or ch == "_")
        return ep

    # register “root” variants
    for path, strict in variants:
        bp.add_url_rule(
            path,
            endpoint=make_endpoint(path),
            view_func=_serve_index,
            methods=["GET"],
            strict_slashes=strict
        )

    # register “prefixed” variants
    if prefix:
        for path, strict in variants:
            prefixed = f"{prefix}{path}"
            bp.add_url_rule(
                prefixed,
                endpoint=make_endpoint(prefixed),
                view_func=_serve_index,
                methods=["GET"],
                strict_slashes=strict
            )
# --- at module scope, so it runs on import ---
register_index_routes(secure_views_bp, prefix=SECURE_FILES_PREFIX)
# ─── 3) Serve static assets under /secure-files/js, /css, /ts ────────────
@secure_views_bp.route("/js/<path:filename>", methods=["GET"])
def serve_dist_js(filename):
    initialize_call_log()
    return send_from_directory(ABS_JS_DIR, filename)

@secure_views_bp.route("/css/<path:filename>", methods=["GET"])
def serve_dist_css(filename):
    initialize_call_log()
    return send_from_directory(ABS_CSS_DIR, filename)

@secure_views_bp.route("/ts/<path:filename>", methods=["GET"])
def serve_dist_ts(filename):
    initialize_call_log()
    return send_from_directory(ABS_TS_DIR, filename)
