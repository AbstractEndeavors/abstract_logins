"""
CLI: bootstrap commands that don't go through the web app.

  python -m app.cli init-db
  python -m app.cli create-admin <username>
  python -m app.cli purge-sessions
"""
import sys
import getpass

from .db import db
from .db.migrations import migrations
from .dal import users as user_dal
from .dal import sessions as session_dal
from .imports.errors import UserExists
from .imports.config import load_config
from .imports.hashing import make_hasher, hash_password

def _setup():
    cfg = load_config()
    db.init_db(cfg.db_dsn)
    return cfg


def cmd_init_db(_args):
    _setup()
    migrations.run_migrations()
    print("schema migrations complete")


def cmd_create_admin(args):
    if len(args) != 1:
        print("usage: create-admin <username>", file=sys.stderr)
        sys.exit(2)
    cfg = _setup()
    migrations.run_migrations()
    username = args[0].strip().lower()

    pw1 = getpass.getpass("password: ")
    pw2 = getpass.getpass("repeat:   ")
    if pw1 != pw2:
        print("passwords do not match", file=sys.stderr)
        sys.exit(1)
    if len(pw1) < cfg.password_min_length:
        print("password too short", file=sys.stderr)
        sys.exit(1)

    hasher = make_hasher(cfg)
    pw_hash = hash_password(hasher, pw1)
    try:
        user_id = user_dal.create(username, None, pw_hash, is_admin=True)
    except UserExists:
        print("user already exists: " + username, file=sys.stderr)
        sys.exit(1)
    print("created admin id=" + str(user_id) + " username=" + username)


def cmd_purge_sessions(_args):
    _setup()
    session_dal.purge_expired()
    print("expired sessions purged")


_COMMANDS = {
    "init-db":         cmd_init_db,
    "create-admin":    cmd_create_admin,
    "purge-sessions":  cmd_purge_sessions,
}


def main(argv):
    if len(argv) < 2 or argv[1] not in _COMMANDS:
        print("commands: " + ", ".join(_COMMANDS), file=sys.stderr)
        sys.exit(2)
    _COMMANDS[argv[1]](argv[2:])


if __name__ == "__main__":
    main(sys.argv)
