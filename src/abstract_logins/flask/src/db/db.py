"""
Database access layer.

The connection pool is held in a module-private variable, set exactly
once by init_db(). Every other function in this module guards against
being called before init. No import has side effects: importing this
file does NOT connect to anything.

Four query primitives, named for what they do:
  fetch_one         -- SELECT, expect 0 or 1 rows
  fetch_all         -- SELECT, expect any number of rows
  execute           -- INSERT/UPDATE/DELETE/DDL, return rowcount
  insert_returning  -- INSERT ... RETURNING ..., return the row

Transactions: one transaction per `with cursor()` block. Commits on
clean exit, rolls back on any exception. If a service needs a
multi-statement transaction it grabs the cursor itself and runs all
statements inside one `with` block.
"""
from contextlib import contextmanager
from psycopg2 import pool as _pool
from psycopg2.extras import RealDictCursor


_pool_handle = None


class DBNotInitialized(RuntimeError):
    pass


def init_db(dsn, minconn=1, maxconn=8):
    """Create the connection pool. Idempotent. Called from the app factory."""
    global _pool_handle
    if _pool_handle is not None:
        return
    _pool_handle = _pool.ThreadedConnectionPool(minconn, maxconn, dsn=dsn)


def shutdown_db():
    """Release the pool. Useful in tests; harmless in production."""
    global _pool_handle
    if _pool_handle is None:
        return
    _pool_handle.closeall()
    _pool_handle = None


def _require_init():
    if _pool_handle is None:
        raise DBNotInitialized("init_db() must be called before any query")


@contextmanager
def cursor(dict_rows=True):
    """
    Borrow a connection from the pool, yield a cursor, commit on
    success, roll back on exception, return the connection to the pool.
    """
    _require_init()
    conn = _pool_handle.getconn()
    cur = conn.cursor(cursor_factory=RealDictCursor) if dict_rows else conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        _pool_handle.putconn(conn)


def fetch_one(query, params=()):
    """SELECT -> one row as dict, or None."""
    with cursor() as c:
        c.execute(query, params)
        return c.fetchone()


def fetch_all(query, params=()):
    """SELECT -> list of dicts (possibly empty)."""
    with cursor() as c:
        c.execute(query, params)
        return c.fetchall()


def execute(query, params=()):
    """INSERT/UPDATE/DELETE/DDL -> rowcount."""
    with cursor() as c:
        c.execute(query, params)
        return c.rowcount


def insert_returning(query, params=()):
    """INSERT ... RETURNING ... -> the returned row as dict."""
    with cursor() as c:
        c.execute(query, params)
        return c.fetchone()
