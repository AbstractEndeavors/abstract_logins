"""
Auth routes. Each handler is small by design: parse the request into a
spec, call a service, shape a response. No domain logic here. No
direct DAL calls. No password hashing. If a route is doing more than
that, push it down a layer.

Errors from the service layer all derive from AuthError, so one
errorhandler in app.py maps them to HTTP responses uniformly.
"""
from flask import Blueprint, request, jsonify, make_response, current_app
from ..imports.schemas import LoginSpec, RegisterSpec, ChangePasswordSpec
from ..session import login_user, logout_user, current_user, login_required
from ..services import auth as auth_svc
from ..services import users as users_svc


from flask import Blueprint, request, jsonify, make_response

from ..imports.schemas import LoginSpec, RegisterSpec, ChangePasswordSpec
from ..session import login_user, logout_user, current_user, login_required
from ..services import auth as auth_svc
from ..services import users as users_svc


def make_blueprint(cfg, hasher):
    bp = Blueprint("auth", __name__)

    @bp.route("/login", methods=["POST"])
    def login():
        spec = LoginSpec.from_json(request.get_json(silent=True))
        user = auth_svc.authenticate(hasher, spec)

        resp = make_response(
            jsonify(
                {
                    "username": user["username"],
                    "is_admin": user["is_admin"],
                }
            )
        )
        login_user(cfg, resp, user["id"])
        return resp

    @bp.route("/logout", methods=["POST"])
    def logout():
        resp = make_response(jsonify({"ok": True}))
        logout_user(cfg, resp)
        return resp

    @bp.route("/me", methods=["GET"])
    @login_required(cfg)
    def me():
        user = current_user(cfg)
        return jsonify(
            {
                "username": user["username"],
                "email": user["email"],
                "is_admin": user["is_admin"],
                "status": user["status"],
            }
        )

    @bp.route("/register", methods=["POST"])
    def register():
        spec = RegisterSpec.from_json(request.get_json(silent=True))
        user_id = users_svc.register(cfg, hasher, spec)
        return jsonify({"id": user_id, "username": spec.username}), 201

    @bp.route("/change-password", methods=["POST"])
    @login_required(cfg)
    def change_password():
        spec = ChangePasswordSpec.from_json(request.get_json(silent=True))
        user = current_user(cfg)

        users_svc.change_password(cfg, hasher, user, spec)

        resp = make_response(jsonify({"ok": True}))
        login_user(cfg, resp, user["id"])
        return resp

    return bp
# services/auth.py
def authenticate(hasher, spec):
    user = users_dal.get_by_username(spec.username)
    if not user or not hasher.verify(spec.password, user["password_hash"]):
        raise AuthError("Invalid credentials", http_status=401)

    status = user["status"]
    if status == "pending":
        raise AuthError(
            "Your account is awaiting approval.",
            http_status=403,
        )
    if status == "rejected":
        raise AuthError(
            "Your account application was not approved.",
            http_status=403,
        )
    if status == "suspended":
        raise AuthError(
            "Your account has been suspended.",
            http_status=403,
        )
    if status != "approved":
        # defense in depth: unknown status = denied
        raise AuthError("Account is not active.", http_status=403)

    return user
