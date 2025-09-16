from login_app import login_app
app = login_app()
if __name__ == "__main__":
    from abstract_security import get_env_key
    debug=bool(get_env_key("DEBUG"))
    host=str(get_env_key("HOST"))
    port=int(get_env_key("PORT"))
    app.run(debug=debug, host=host, port=port)
