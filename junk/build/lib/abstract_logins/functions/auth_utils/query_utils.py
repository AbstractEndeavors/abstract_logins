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
def select_all(query: str, *args):
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args if args else None)
        return cur.fetchall()
    finally:
        cur.close(); conn.close()
def insert_query(query: str, *args):
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args if args else None)
        new_id = None
        try:
            rec = cur.fetchone()
            if isinstance(rec, dict) and 'id' in rec: new_id = rec['id']
            elif isinstance(rec, (list, tuple)) and rec: new_id = rec[0]
        except psycopg2.ProgrammingError:
            pass
        conn.commit()
        return new_id
    finally:
        cur.close(); conn.close()

def execute_query(query: str, *args):
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args if args else None)
        conn.commit()
    finally:
        cur.close(); conn.close()

def select_distinct_rows(query: str, *args):
    """
    Execute a SELECT query that returns zero or more rows.
    Returns:
        list[dict]: a list of RealDictCursor rows (dicts), empty if none.
    """
    cur, conn = get_cur_conn()
    try:
        if args:
            cur.execute(query, args)
        else:
            cur.execute(query)
        rows = cur.fetchall()
        return rows
    finally:
        cur.close()
        conn.close()

def select_rows(query: str, *args):
    cur, conn = get_cur_conn()
    try:
        cur.execute(query, args if args else None)
        row = cur.fetchone()
        return row  # None if not found
    finally:
        cur.close(); conn.close()

