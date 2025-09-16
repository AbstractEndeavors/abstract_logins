from ...query_utils import insert_query, select_rows,initialize_call_log
def create_users_table():
    """
    Create the 'users' table (if not exists) and an updated_at trigger.
    Uses connectionManager via query_utils.
    """
    initialize_call_log()
    # 1) Create the users table if it does not exist
    query = """
    CREATE TABLE IF NOT EXISTS users (
      username      VARCHAR(255) PRIMARY KEY,
      password_hash TEXT           NOT NULL,
      is_admin      BOOLEAN        NOT NULL DEFAULT FALSE,
      created_at    TIMESTAMPTZ    DEFAULT NOW(),
      updated_at    TIMESTAMPTZ    DEFAULT NOW()
    );
    """
    
    insert_query(query)
def ensure_trigger_exists():
    initialize_call_log()
    # 2) Create (or replace) the trigger function to update updated_at
    query = """
    CREATE OR REPLACE FUNCTION update_users_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at := NOW();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
    """
    insert_query(query)
def create_trigger():
    initialize_call_log()
    # 3) Create the trigger if it doesn’t already exist
    query = """
    DO $$
    BEGIN
      IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'users_updated_at_trigger'
      ) THEN
        CREATE TRIGGER users_updated_at_trigger
        BEFORE UPDATE ON users
        FOR EACH ROW
        EXECUTE PROCEDURE update_users_updated_at();
      END IF;
    END;
    $$;
    """
    insert_query(query)
def ensure_users_table_exists():
    create_users_table()
    ensure_trigger_exists()
    create_trigger()
