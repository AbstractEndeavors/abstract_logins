
from ...query_utils import insert_query, select_rows,initialize_call_log
def ensure_blacklist_table_exists():
    """
    Create the 'blacklisted_tokens' table if it doesn’t already exist.
    Columns:
      - token (TEXT): the JWT string
      - blacklisted_on (TIMESTAMPTZ): timestamp when it was added
    """
    initialize_call_log()
    query = """
    CREATE TABLE IF NOT EXISTS blacklisted_tokens (
      token           TEXT PRIMARY KEY,
      blacklisted_on  TIMESTAMPTZ DEFAULT NOW()
    );
    """
    insert_query(query)

def is_token_blacklisted(token: str) -> bool:
    """
    Returns True if the given token is already in blacklisted_tokens.
    """
    query = "SELECT 1 FROM blacklisted_tokens WHERE token = %s;"
    row = select_rows(query, token)
    return row is not None

def blacklist_token(token: str) -> None:
    """
    Insert the given JWT into blacklisted_tokens.
    """
    initialize_call_log()
    query = "INSERT INTO blacklisted_tokens (token) VALUES (%s) ON CONFLICT DO NOTHING;"
    insert_query(query, token)
