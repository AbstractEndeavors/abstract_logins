"""
Application factory. Every other module is plain Python -- no Flask
globals, no decorators evaluated at import time. The factory is the
single place where everything gets wired together.

The wiring order matters and is explicit:
  1. load config
  2. init DB pool from config
  3. run migrations (creates tables if they don't exist)
  4. build the password hasher
  5. build blueprints (each receives cfg + hasher)
  6. register blueprints + error handlers
"""
import os
import warnings
import logging
from flask import Flask, jsonify, send_from_directory
from .imports.config import load_config
from .imports.errors import AuthError
from .imports.hashing import make_hasher
from . import db
from .db.migrations import run_migrations
from .routes import auth as auth_routes
from .routes import admin as admin_routes
from abstract_flask.abstract_flask import _add_endpoint_inspector
from flask import Blueprint, jsonify, request
from typing import Optional
from abstract_flask import get_bp

_logger = logging.getLogger(__name__)


def _init_db_with_warning(dsn: str) -> bool:
    """Init DB pool and run migrations. Returns True on success, warns and returns False on failure."""
    try:
        db.init_db(dsn)
    except Exception as exc:
        warnings.warn(
            f"abstract_logins: cannot connect to database: {exc}\n"
            "  Set the DATABASE_URL (or DB_DSN) environment variable to a valid "
            "PostgreSQL DSN, e.g. postgresql://user:pass@localhost/dbname\n"
            "  Auth and file endpoints will return 500 until the database is reachable.",
            RuntimeWarning,
            stacklevel=3,
        )
        _logger.error("abstract_logins: DB connection failed: %s", exc)
        return False

    try:
        run_migrations()
        _logger.info("abstract_logins: database schema is up to date")
    except Exception as exc:
        warnings.warn(
            f"abstract_logins: schema migration failed: {exc}\n"
            "  Tables may be missing. Check DB permissions and connectivity.",
            RuntimeWarning,
            stacklevel=3,
        )
        _logger.error("abstract_logins: migration failed: %s", exc)
        return False

    return True


def create_abstract_logins(cfg=None):
    cfg = cfg or load_config()

    _init_db_with_warning(cfg.db_dsn)
    hasher = make_hasher(cfg)

    abstract_logins_bp, logger = get_bp("abstract_logins_bp", __name__)

    abstract_logins_bp.register_blueprint(auth_routes.make_blueprint(cfg, hasher))
    abstract_logins_bp.register_blueprint(admin_routes.make_blueprint(cfg))

    @abstract_logins_bp.errorhandler(AuthError)
    def _on_auth_error(err):
        return jsonify({"error": str(err)}), err.http_status

    # Static frontend. Single page; no build step.
    static_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "static")

    @abstract_logins_bp.route("/")
    def _index():
        return send_from_directory(static_dir, "index.html")

    @abstract_logins_bp.route("/static/<path:path>")
    def _static(path):
        return send_from_directory(static_dir, path)

    _add_endpoint_inspector(abstract_logins_bp)
    return abstract_logins_bp
