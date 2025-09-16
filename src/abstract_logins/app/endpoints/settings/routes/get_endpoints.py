from ..imports import *
secure_endpoints_bp,logger = get_bp(
    "secure_endpoints",
    __name__,
    url_prefix=SECURE_FILES_PREFIX
      # <-- everything in this Blueprint sits under /secure-files
)
@secure_endpoints_bp.route("/api/secure-files/secure_endpoints", methods=["GET","POST"])
@secure_endpoints_bp.route("/api/secure-files/secure_endpoints/", methods=["GET","POST"])
def getEndpoints():
    import sys, os, importlib
    try:
        from ....__init__ import login_app
        app = login_app()
        endpoints=[]
        for rule in app.url_map.iter_rules():
            
            # skip dynamic parameters if desired, include all
            methods = sorted(rule.methods - {"HEAD", "OPTIONS"})
            endpoints.append((rule.rule, ", ".join(methods)))
        rules = sorted(endpoints, key=lambda x: x[0])
        return jsonify(rules), 200
    finally:
        sys.path.pop(0)
