import os
from app import login_app
from abstract_flask import main_flask_start
from abstract_filepaths import *
        # directory that holds this wsgi file
                       # one level up
ENV_PATH   = os.path.join(ENV_DIR,".env")                     # ../.env

app = login_app()

if __name__ == "__main__":
    print(f"called from {caller_path}")

    # Use the env that lives in the parent folde
    main_flask_start(app, env_path=ENV_PATH)          # *args / **kwargs if you need them
