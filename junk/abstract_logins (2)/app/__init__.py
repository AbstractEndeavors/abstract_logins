from .src.imports import *
from .src.endpoints import *
bp_list = [
    secure_logout_bp,
    secure_login_bp,
    change_passwords_bp,
    secure_users_bp,
    secure_settings_bp,
    secure_views_bp,
    secure_download_bp,
    secure_upload_bp,
    secure_files_bp,
    secure_remove_bp,
    secure_env_bp,
    secure_register_bp
    ]

class RequestFormatter(logging.Formatter):
    def format(self, record):
        if has_request_context():
            # `request` is the current flask.Request proxy
            ip_addr = get_ip_addr(req=request)
            user = USER_IP_MGR.get_user_by_ip(ip_addr)
            record.remote_addr = ip_addr
            record.user = user
        else:
            record.remote_addr = None
            record.user = None
        return super().format(record)
def addHandler(app,name=None):
    name = name or os.path.splitext(os.path.abspath(__file__))[0]
    audit_handler = logging.FileHandler("{name}.log")
    audit_fmt     = RequestFormatter(
        "%(asctime)s %(remote_addr)s %(user)s %(message)s"
    )
    audit_handler.setFormatter(audit_fmt)
    app.logger.addHandler(audit_handler)
    
    @app.before_request
    def record_ip_for_authenticated_user():
        if hasattr(request, 'user') and request.user:
            # your get_user_by_username gives you .id
            user = get_user_by_username(request.user["username"])
            if user:
                log_user_ip(user["id"], request.remote_addr)
    @app.route("/api/endpoints/", methods=["POST"])
    @app.route("/api/endpoints/", methods=["GET"])
    def get_endpoints():
        import sys, os, importlib
        endpoints=[]
        for rule in app.url_map.iter_rules():
            
            # skip dynamic parameters if desired, include all
            methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
            endpoints.append((rule.rule, ", ".join(methods)))
        rules = sorted(endpoints, key=lambda x: x[0])
        try:

            return jsonify(rules), 200
        finally:
            sys.path.pop(0)
    return app

def login_app():
    app = get_Flask_app(name=__name__,
                        bp_list=bp_list,
                        static_folder=None,  # Disable automatic static route
                        static_url_path=None)
    app.url_map.strict_slashes = False
    secure_limiter.init_app(app)
    app.config['DEBUG'] = True
    app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
    app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024 * 1024
    app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

    ALLOWED_ORIGINS = [
        "http://localhost:3000",
        "https://clownworld.biz",
        "https://www.clownworld.biz",
        "https://www.abstractendeavors.com"
    ]

    CORS(
        app,
        resources={r"/api/*": {"origins": ALLOWED_ORIGINS}},
        supports_credentials=True,
        methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS"],
        allow_headers=["Authorization", "Content-Type"]
    )
    @app.before_request
    def log_request():
        app.logger.debug(
            f"{request.method} {request.path} "
            f"form={dict(request.form)} files={list(request.files)}"
        )
    app.config.update({
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "None",
        "SESSION_COOKIE_SECURE": True
    })
    app = addHandler(app, name='download_audit')

    # Manually add static route AFTER blueprints for lower priority
    app.add_url_rule(
        "/api/<path:filename>",
        endpoint="static",
        view_func=lambda filename: send_from_directory(STATIC_FOLDER, filename),
        methods=["GET", "HEAD","POST", "PATCH","OPTIONS"]   # not "OPTION" and not "PULL"
    )

    return app
