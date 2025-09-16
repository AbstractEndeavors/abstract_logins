from ...query_utils import select_rows,initialize_call_log
def get_user_by_username(username: str) -> dict | None:
    """
    Returns a dict with keys: id, username, password_hash, is_admin,
    or None if no such user exists.
    """
    initialize_call_log()
    query = user_by_username_query()
    rows = select_rows(query,username)

    if not rows:
        return None
    # If select_rows returned a dict, use it; if it returned a list, grab the first item
    if isinstance(rows, dict):
        return rows
    else:
        return rows[0]

def user_by_username_query():
    query = """
              SELECT id,
                     username,
                     password_hash,
                     is_admin
                FROM users
               WHERE username = %s
            """
    return query
def user_query():
    query ="""SELECT
                username,
                password_hash,
                is_admin
              FROM users
              WHERE username = %s
            """
    return query
def add_or_update_user_query():
    query = """
      INSERT INTO users (username, password_hash, is_admin)
      VALUES (%s, %s, %s)
      ON CONFLICT (username) DO UPDATE
        SET password_hash = EXCLUDED.password_hash,
            is_admin      = EXCLUDED.is_admin;
    """
    return query
def existing_users_query():
    query = """SELECT
                username
               FROM users
               ORDER BY username ASC;
            """
    return query

def call_rows(query,*args):
    rows = select_rows(query,args)
    return rows
