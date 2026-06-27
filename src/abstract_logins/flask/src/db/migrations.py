"""
Schema migrations. DDL lives here, not scattered across data-access
modules. Run once at deploy time, not at module import.

For a project this size a real migration tool (alembic, yoyo) is
overkill. The pattern below -- a list of (version, sql) tuples and a
schema_version table -- is fine until you have a team. When you have a
team, switch to alembic.
"""
from . import db


_MIGRATIONS = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS users (
            id                  BIGSERIAL PRIMARY KEY,
            username            VARCHAR(32)  NOT NULL UNIQUE,
            email               VARCHAR(254) UNIQUE,
            password_hash       TEXT         NOT NULL,
            is_admin            BOOLEAN      NOT NULL DEFAULT FALSE,
            status              VARCHAR(24)  NOT NULL DEFAULT 'pending',
            status_reason       TEXT,
            status_changed_by   BIGINT,
            status_changed_at   TIMESTAMPTZ,
            created_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            updated_at          TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS sessions (
            session_id      TEXT         PRIMARY KEY,
            user_id         BIGINT       NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
            expires_at      TIMESTAMPTZ  NOT NULL,
            last_seen_at    TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS sessions_user_id_idx
            ON sessions(user_id);

        CREATE INDEX IF NOT EXISTS sessions_expires_at_idx
            ON sessions(expires_at);
        """,
    ),
    (
        3,
        """
        DO $$
        BEGIN
            IF NOT EXISTS (
                SELECT 1
                  FROM information_schema.columns
                 WHERE table_name = 'users'
                   AND column_name = 'status'
            ) THEN
                ALTER TABLE users
                    ADD COLUMN status VARCHAR(24) NOT NULL DEFAULT 'approved',
                    ADD COLUMN status_reason TEXT,
                    ADD COLUMN status_changed_by BIGINT,
                    ADD COLUMN status_changed_at TIMESTAMPTZ;
            END IF;
        END $$;
        """,
    ),
    (
        4,
        """
        CREATE TABLE IF NOT EXISTS uploads (
            id             BIGSERIAL    PRIMARY KEY,
            filename       TEXT         NOT NULL,
            filepath       TEXT         NOT NULL,
            uploader_id    TEXT         NOT NULL,
            shareable      BOOLEAN      NOT NULL DEFAULT FALSE,
            download_count INTEGER      NOT NULL DEFAULT 0,
            download_limit INTEGER,
            share_password TEXT,
            password_str   TEXT,
            "needsPassword" BOOLEAN     NOT NULL DEFAULT FALSE,
            created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW()
        );

        CREATE INDEX IF NOT EXISTS uploads_uploader_id_idx
            ON uploads(uploader_id);

        CREATE INDEX IF NOT EXISTS uploads_filepath_idx
            ON uploads(filepath);
        """,
    ),
]


def _ensure_schema_version_table():
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER PRIMARY KEY,
            applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        """
    )


def _applied_versions():
    rows = db.fetch_all("SELECT version FROM schema_version ORDER BY version ASC;")
    return {row["version"] for row in rows}


def run_migrations():
    _ensure_schema_version_table()
    applied = _applied_versions()

    for version, sql in _MIGRATIONS:
        if version in applied:
            continue

        with db.cursor() as cur:
            cur.execute(sql)
            cur.execute(
                "INSERT INTO schema_version (version) VALUES (%s);",
                (version,),
            )
