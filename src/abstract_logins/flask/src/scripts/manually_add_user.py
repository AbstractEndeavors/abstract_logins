from .config import load_config
from .hashing import make_hasher
from . import db
from .dal import users as user_dal

cfg = load_config()
db.init_db(cfg.db_dsn)
hasher = make_hasher(cfg)

from .hashing import hash_password
pw_hash = hash_password(hasher, 'sumdoodchillen')

user_id = user_dal.create(
    username='sumdood',
    email='aking@abstractendeavors.com',
    password_hash=pw_hash,
    is_admin=True,
)
print('created user id:', user_id)
