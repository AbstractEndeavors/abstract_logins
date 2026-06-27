import logging
import warnings
from flask import Blueprint
from .endpoints.files import (
    secure_env_bp,
    secure_files_bp,
    secure_upload_bp,
    secure_remove_bp,
    secure_register_bp,
    secure_download_bp,
)
from .endpoints.settings import (
    secure_settings_bp,
    secure_endpoints_bp,
)
from .endpoints.views import secure_views_bp
from .endpoints.users import secure_users_bp

_logger = logging.getLogger(__name__)

_FILE_BLUEPRINTS = [
    secure_env_bp,
    secure_files_bp,
    secure_upload_bp,
    secure_remove_bp,
    secure_register_bp,
    secure_download_bp,
    secure_settings_bp,
    secure_endpoints_bp,
    secure_views_bp,
    secure_users_bp,
]


def _ensure_db(cfg=None):
    """
    Connect to the database and run migrations (which create any missing
    tables, including `uploads`, `users`, and `sessions`).
    Emits a RuntimeWarning -- and logs an error -- if the DB is unreachable
    rather than crashing hard, so the app still starts and surfaces a
    readable message.
    """
    try:
        from .flask.src.imports.config import load_config
        from .flask.src import db
        from .flask.src.db.migrations import run_migrations

        resolved_cfg = cfg or load_config()
        db.init_db(resolved_cfg.db_dsn)
        connectionManager(dbUrl=resolved_cfg.db_dsn)
        run_migrations()
        _logger.info("secure_files: database schema is up to date")
    except ImportError:
        # flask sub-package not installed alongside app/ -- skip silently.
        pass
    except Exception as exc:
        warnings.warn(
            f"secure_files: database setup failed: {exc}\n"
            "  Set DATABASE_URL (or DB_DSN) to a valid PostgreSQL DSN, e.g.\n"
            "  postgresql://user:pass@localhost/dbname\n"
            "  File endpoints will return errors until the database is reachable.",
            RuntimeWarning,
            stacklevel=3,
        )
        _logger.error("secure_files: DB setup failed: %s", exc)


def create_secure_files(cfg=None):
    """
    Returns a Blueprint that contains all secure-file endpoints.
    Connects to the database and runs schema migrations on startup so
    the required tables (uploads, users, sessions) are created
    automatically if they don't exist yet.

    Register this alongside login_app() in your main Flask app::

        from abstract_logins import login_app, create_secure_files
        app.register_blueprint(login_app())
        app.register_blueprint(create_secure_files())

    Authentication uses the dual-auth login_required decorator: the new
    session-cookie (auth_session) is checked first; a JWT Bearer token is
    accepted as a fallback for legacy clients.
    """
    _ensure_db(cfg)

    bp = Blueprint("secure_files", __name__)
    for child in _FILE_BLUEPRINTS:
        bp.register_blueprint(child)
    return bp
