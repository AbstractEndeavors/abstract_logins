# /var/www/abstractendeavors/secure-files/big_man/flask_app/login_app/functions/user_store.py

from pathlib import Path
import getpass,bcrypt
from datetime import datetime
from abstract_flask import initialize_call_log
from .query_utils import insert_query, select_rows
from abstract_flask import initialize_call_log
from abstract_utilities import get_logFile
from abstract_database import *






def get_connection():
    return connectionManager().get_db_connection()







