from .imports import *
def get_conn_mgr():
    print('get_connection')
    return connectionManager(
                  dbType='abstract_base',
                  dbName='admin')
def get_cur_conn(use_dict_cursor=True):
    """
    Get a database connection and a RealDictCursor.
    Returns:
        tuple: (cursor, connection)
    """
    conn = connectionManager().get_db_connection()
    cur = conn.cursor(row_factory=dict_row) if use_dict_cursor else conn.cursor()
    return cur, conn

def get_connection(env=None,env_path=None):
    """Establish a PostgreSQL connection."""
    env = env or load_postgres_env(env_path)
    name_keys = ['dbname','dbName','database']
    for key in name_keys:
        dbname = env.get(key)
        if key in env:
            del env[key]
    env['dbname']=dbname
    del env['url']
    return psycopg.connect(**env)
