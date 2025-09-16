from abstract_utilities import initialize_call_log,SingletonMeta
class responseAggregator(metaclass=SingletonMeta):
    def __init__(self):
        if not hasattr(self, 'initialized') or self.initialized == False:
            self.initialized= True
            self.default_response = {
                "value": None,
                "message": None,
                "status_code": 200,
                "success": True
            }
            self.current_response = self.refresh_current_response()
    def refresh_current_response(self):
        self.current_response = self.default_response.copy()
        return self.current_response
    def update_response(self, *, value=None, message=None,
                        status_code=None, success=None,
                        refresh=True, send=False):
        # Only overwrite non-None fields
        if list(set(value,message,status,success)) == [None] and refresh == True:
            self.refresh_current_response()
        for key, v in {
            "value": value,
            "message": message,
            "status_code": status_code,
            "success": success
        }.items():
            if v is not None:
                self.current_response[key] = v

    def send_response(self,*, value=None, message=None,
                        status_code=None, success=None,
                        refresh=False):
        
        if send == True:
            out = self.current_response
        else:
            out = self.update_response(value=value, message=message,
                        status_code=status_code, success=success,
                        refresh=refresh, send=send)
        # Reset for next time
        self.current_response = self.default_response.copy()
        return out


response_mgr = responseAggregator()


def update_response(*, value=None, message=None,
                    status_code=None, success=None,
                    refresh=True):
    response = response_mgr.update_response(
        value=value,
        message=message,
        status_code=status_code,
        success=success,
        refresh=refresh,
        send=send
    )
    return response

def send_response():
    return response_mgr.send_response(
        value=value,
        message=message,
        status_code=status_code,
        success=success
        )


def get_output(*, value=None, message=None,
               status_code=None, success=None,
               refresh=True,send=False):
    """
    Builds a response based on status_code’s hundreds-bucket defaults,
    then merges in any overrides you passed (value, message, success).
    """
    # Default messages/success by hundreds-bucket
    status_ranges = {
        100: {"message": "Informational response", "success": True},
        200: {"message": "Success",               "success": True},
        300: {"message": "Redirection",           "success": False},
        400: {"message": "Client error",          "success": False},
        500: {"message": "Server error",          "success": False},
    }
    if refresh:
        status_code = status_code or 200
    # 1) Determine the bucket
    bucket = (status_code // 100) * 100 if isinstance(status_code, int) else None

    # 2) Look up defaults
    defaults = status_ranges.get(bucket, {})
    default_msg = defaults.get("message")
    default_success = defaults.get("success")

    # 3) Update aggregator
    update_response(
        value=value,
        # use the default message unless caller passed one explicitly
        message=(message if message is not None else default_msg),
        status_code=status_code,
        # use default success unless caller passed override
        success=(success if success is not None else default_success),
        refresh=refresh
    )
    if send:
        # 4) Return and reset
        return send_response()
