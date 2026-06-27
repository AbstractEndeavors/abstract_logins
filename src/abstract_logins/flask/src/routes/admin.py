"""
Admin-only routes. Gated by @admin_required, which itself enforces
authentication -- no need to stack @login_required.
Handlers stay thin: parse, delegate to a service, return shape.
All status transitions go through users_svc.set_status so audit
fields (actor, timestamp, reason) are written in one place.
"""
from flask import Blueprint, jsonify, request

from ..imports.schemas import RejectSpec
from ..session import admin_required, current_user
from ..services import users as users_svc
from ..dal import users as user_dal


def make_blueprint(cfg):
    bp = Blueprint("admin", __name__)

    @bp.get("/admin/users")
    @admin_required(cfg)
    def list_users():
        return jsonify({"usernames": user_dal.list_usernames()})

    @bp.get("/admin/users/pending")
    @admin_required(cfg)
    def list_pending():
        return jsonify({"users": users_svc.list_by_status(cfg, "pending")})

    @bp.post("/admin/users/<int:user_id>/approve")
    @admin_required(cfg)
    def approve(user_id):
        actor = current_user(cfg)
        users_svc.set_status(
            cfg,
            user_id,
            "approved",
            actor=actor,
            reason=None,
        )
        return jsonify({"ok": True})

    @bp.post("/admin/users/<int:user_id>/reject")
    @admin_required(cfg)
    def reject(user_id):
        spec = RejectSpec.from_json(request.get_json(silent=True))
        actor = current_user(cfg)
        users_svc.set_status(
            cfg,
            user_id,
            "rejected",
            actor=actor,
            reason=spec.reason,
        )
        return jsonify({"ok": True})

    @bp.post("/admin/users/<int:user_id>/suspend")
    @admin_required(cfg)
    def suspend(user_id):
        spec = RejectSpec.from_json(request.get_json(silent=True))
        actor = current_user(cfg)
        users_svc.set_status(
            cfg,
            user_id,
            "suspended",
            actor=actor,
            reason=spec.reason,
        )
        return jsonify({"ok": True})

    return bp
