# ---------- installers (kept small & composable) ----------
import uuid, urllib.parse, os, logging
from typing import Iterable, Optional
from flask import Flask, jsonify, request, g, send_file, Response, Blueprint
from werkzeug.datastructures import Range
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, jsonify, request, g, send_file, Response, Blueprint, redirect
# --- request ids ---
def install_request_ids(app: Flask):
    @app.before_request
    def _rid_start():
        g.request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    @app.after_request
    def _rid_hdr(resp):
        rid = getattr(g, "request_id", "")
        if rid:
            resp.headers["X-Request-ID"] = rid
        return resp

# --- security headers ---
def install_security_headers(app: Flask):
    @app.after_request
    def _sec(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
        resp.headers.setdefault("Referrer-Policy", "no-referrer-when-downgrade")
        return resp

# --- JSON errors ---
def install_json_errors(app: Flask):
    def _json_error(status, message, **kw):
        resp = jsonify({"error": message, "status": status, **kw})
        resp.status_code = status
        return resp
    @app.errorhandler(404)
    def _404(e): return _json_error(404, "Not Found", path=request.path)
    @app.errorhandler(405)
    def _405(e):
        resp = _json_error(405, "Method Not Allowed", path=request.path)
        allow = getattr(e, "valid_methods", None)
        if allow: resp.headers["Allow"] = ", ".join(allow)
        return resp
    @app.errorhandler(413)
    def _413(e): return _json_error(413, "Payload Too Large")
    @app.errorhandler(Exception)
    def _500(e):
        app.logger.exception("Unhandled exception")
        return _json_error(500, "Internal Server Error")

# --- slash normalizer ---
# replace your current install_trailing_slash_policy with this
# replace your installer with this upgraded version
def install_trailing_slash_policy(app, *, canonical="no-trailing",
                                  skip_prefixes=None,
                                  methods=("GET", "HEAD")):
    """
    canonical: "no-trailing" | "trailing" | None
    skip_prefixes: iterable of URL prefixes to ignore (no redirect)
    methods: which HTTP methods to canonicalize (default: only safe ones)
    """
    if canonical not in ("no-trailing", "trailing", None):
        raise ValueError("canonical must be 'no-trailing', 'trailing', or None")

    app.url_map.strict_slashes = False
    try:
        app.url_map.merge_slashes = True
    except Exception:
        pass

    if canonical is None:
        return

    skip_prefixes = tuple(skip_prefixes or ())

    @app.before_request
    def _normalize_slash():
        # **Do not** redirect non-safe methods to avoid POST/301→GET loops
        if request.method.upper() not in methods:
            return

        p = request.path
        if p == "/" or any(p.startswith(pref) for pref in skip_prefixes):
            return

        want_trailing = (canonical == "trailing")
        has_trailing  = p.endswith("/")

        if want_trailing and not has_trailing:
            target = p + "/"
        elif (not want_trailing) and has_trailing:
            target = p.rstrip("/")
        else:
            return

        qs = ("?" + request.query_string.decode()) if request.query_string else ""
        return redirect(target + qs, code=308)

    @app.after_request
    def _add_canonical_header(resp):
        resp.headers["X-Trailing-Slash-Policy"] = canonical
        return resp

def install_caching_headers(app: Flask, max_age_secs: int = 86400, extra_prefixes: Optional[Iterable[str]] = None):
    extras = tuple(extra_prefixes or ())
    @app.after_request
    def _cache(resp):
        if request.method in ("GET", "HEAD") and 200 <= resp.status_code < 300:
            p = request.path
            static_prefix = (app.static_url_path or "/static")
            if p.startswith(static_prefix) or p.startswith("/media") or any(p.startswith(x) for x in extras):
                resp.headers.setdefault("Cache-Control", f"public, max-age={max_age_secs}, immutable")
        return resp

# --- fast OPTIONS (lets flask_cors do its thing quickly) ---
def install_fast_options(app: Flask):
    @app.route("/", defaults={"path": ""}, methods=["OPTIONS"])
    @app.route("/<path:path>", methods=["OPTIONS"])
    def _opts(path):
        return app.make_default_options_response()

# --- method override ---
def install_method_override(app: Flask, allowed=("PATCH", "DELETE", "PUT")):
    @app.before_request
    def _method_override():
        if request.method == "POST":
            m = request.headers.get("X-HTTP-Method-Override", "").upper()
            if m in allowed:
                request.environ["REQUEST_METHOD"] = m

# --- openapi surfacing (lightweight) ---
def install_openapi(app: Flask, title="Media API", version="1.0.0"):
    @app.get("/openapi.json")
    def _openapi():
        servers = [{"url": request.url_root.rstrip("/")}]
        paths = {}
        for rule in app.url_map.iter_rules():
            if rule.endpoint == "static":
                continue
            methods = sorted(m for m in rule.methods if m not in {"HEAD", "OPTIONS"})
            paths[rule.rule] = {m.lower(): {"responses": {"200": {"description": "OK"}}} for m in methods}
        return jsonify({"openapi": "3.0.0", "info": {"title": title, "version": version}, "servers": servers, "paths": paths})

# --- healthz/readyz ---
def install_health(app: Flask):
    @app.get("/healthz")
    def _healthz(): return jsonify({"ok": True}), 200
    @app.get("/readyz")
    def _readyz():
        ok = os.path.isdir(app.config.get("UPLOAD_FOLDER", ""))
        return (jsonify({"ok": ok}), 200 if ok else 503)

# --- partial content helper for media (keep existing API) ---
def send_media_partial(path, mimetype=None, as_attachment=False, download_name=None):
    file_size = os.path.getsize(path)
    rng = request.range or Range(None)
    if rng and rng.ranges:
        start, end = rng.ranges[0]
        start = 0 if start is None else start
        end = file_size - 1 if end is None else end
        if start > end or end >= file_size:
            return Response(status=416, headers={"Content-Range": f"bytes */{file_size}"})
        with open(path, "rb") as f:
            f.seek(start)
            data = f.read(end - start + 1)
        resp = Response(data, status=206, mimetype=mimetype)
        resp.headers["Content-Range"]  = f"bytes {start}-{end}/{file_size}"
        resp.headers["Accept-Ranges"]  = "bytes"
        resp.headers["Content-Length"] = str(end - start + 1)
        if as_attachment and download_name:
            resp.headers["Content-Disposition"] = f'attachment; filename="{download_name}"'
        return resp
    return send_file(path, mimetype=mimetype, as_attachment=as_attachment,
                     download_name=download_name, conditional=True)

def content_disposition(name, attachment=True):
    safe = secure_filename(name) or "download"
    quoted = urllib.parse.quote(safe)
    disp = "attachment" if attachment else "inline"
    return f"{disp}; filename*=UTF-8''{quoted}"

# --- your audit handler (fixed undefined 'endpoint') ---
def get_static_url_ends(endpoint_suffix: str, app: Flask):
    s = (app.static_url_path or "").strip("/")
    e = (endpoint_suffix or "").strip("/")
    base = f"/{s}" if s else ""
    ep   = f"/{e}" if e else ""
    path = f"{base}{ep}" or "/"
    return path, path + "/"

def addHandler(app: Flask, *, name: Optional[str] = None, endpoints_suffix: str = "endpoints") -> Flask:
    if getattr(app, "_endpoints_registered", False):
        return app
    app._endpoints_registered = True
    name = name or os.path.splitext(os.path.basename(__file__))[0]
    # audit log
    audit_path = f"{name}.log"
    audit_fmt  = logging.Formatter("%(asctime)s %(message)s")
    audit_hdlr = logging.FileHandler(audit_path)
    audit_hdlr.setFormatter(audit_fmt)
    app.logger.addHandler(audit_hdlr)
    # endpoints browser under <static_url_path>/<endpoints_suffix>
    if "getEnds" not in app.view_functions:
        p0, p1 = get_static_url_ends(endpoints_suffix, app)
        @app.route(p1, methods=["GET", "POST"])
        @app.route(p0, methods=["GET", "POST"])
        def getEnds():
            endpoints = [
                (rule.rule, ", ".join(sorted(rule.methods - {"HEAD", "OPTIONS"})))
                for rule in app.url_map.iter_rules()
            ]
            return jsonify(sorted(endpoints)), 200
    return app


# ---------- ONE factory to rule them all ----------
def get_Flask_app(
    *args,
    bp_list=None,
    install_defaults=True,
    canonical_slash="no-trailing",   # "no-trailing" | "trailing" | None
    cache_max_age=86400,
    openapi=True,
    health=True,
    method_override=True,
    fast_options=True,
    proxy_fix=True,
    request_ids=True,
    json_errors=True,
    security_headers=True,
    extra_cache_prefixes: Optional[Iterable[str]] = None,
    handler_name: Optional[str] = None,
    **kwargs
) -> Flask:
    # resolve name + bp_list...
    name = None
    if args:
        for arg in args:
            if isinstance(arg, str):
                name = arg
            elif bp_list is None and isinstance(arg, (list, tuple)):
                bp_list = list(arg)
    if name is None:
        name = kwargs.pop("name", __name__)
    bp_list = bp_list or []

    app = Flask(name, **kwargs)

    # 1) Proxy headers first
    if install_defaults and proxy_fix:
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # 2) IDs / security / JSON errors
    if install_defaults and request_ids:      install_request_ids(app)
    if install_defaults and security_headers: install_security_headers(app)
    if install_defaults and json_errors:      install_json_errors(app)

    # 3) Slash policy ONCE, with skips to avoid ping-pong at /<static>/endpoints
    if install_defaults:
        static_prefix = (app.static_url_path or "/static").rstrip("/")
        skip = [f"{static_prefix}/endpoints", f"{static_prefix}/endpoints/"]
        install_trailing_slash_policy(app,
            canonical=canonical_slash,
            skip_prefixes=skip,
            methods=("GET","HEAD")   # <-- important
        )

    # 4) Cache / OPTIONS / method override / health / openapi
    if install_defaults and cache_max_age:    install_caching_headers(app, cache_max_age, extra_cache_prefixes)
    if install_defaults and fast_options:     install_fast_options(app)
    if install_defaults and method_override:  install_method_override(app)
    if install_defaults and health:           install_health(app)
    if install_defaults and openapi:          install_openapi(app)

    # 5) Your audit + endpoints browser
    addHandler(app, name=handler_name or 'download_audit', endpoints_suffix="endpoints")

    # 6) Blueprints last
    for bp in bp_list:
        app.register_blueprint(bp)

    return app
