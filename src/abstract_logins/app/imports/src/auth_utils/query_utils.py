# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/functions/query_utils.py

from abstract_database import connectionManager
import psycopg2
from psycopg2.extras import RealDictCursor
from abstract_utilities import initialize_call_log

# Initialize connectionManager once (using your .env path if needed)
connectionManager(env_path="/home/solcatcher/.env",
                  dbType='database',
                  dbName='abstract')


def get_cur_conn(use_dict_cursor=True):
    """
    Get a database connection and a RealDictCursor.
    Returns:
        tuple: (cursor, connection)
    """
    conn = connectionManager().get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor) if use_dict_cursor else conn.cursor()
    return cur, conn


# -----------------------------
# SELECT helpers
# -----------------------------
def select_all(query: str, *args):
    """Run SELECT returning all rows."""
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args) if args else cur.execute(query)
        return cur.fetchall()
    finally:
        cur.close()
        conn.close()


def select_distinct_rows(query: str, *args):
    """Run SELECT returning all rows as list[dict]."""
    return select_all(query, *args)


def select_rows(query: str, *args):
    """Run SELECT returning one row (or None)."""
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args) if args else cur.execute(query)
        row = cur.fetchone()
        return row if row else None
    finally:
        cur.close()
        conn.close()


# -----------------------------
# Write helpers (INSERT/UPDATE/DELETE)
# -----------------------------
def insert_query(query: str, *args):
    """
    Run INSERT. If RETURNING clause exists, return the id (or None).
    """
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args)
        new_id = None
        try:
            res = cur.fetchone()
            if res and "id" in res:
                new_id = res["id"]
        except psycopg2.ProgrammingError:
            pass
        conn.commit()
        return new_id
    finally:
        cur.close()
        conn.close()


def execute_query(query: str, *args):
    """
    Run UPDATE/DELETE/INSERT (no fetch).
    Returns number of rows affected.
    """
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args)
        affected = cur.rowcount
        conn.commit()
        return affected
    finally:
        cur.close()
        conn.close()
