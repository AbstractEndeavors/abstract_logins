"""
Typed exceptions for the auth domain. Every layer below routes raises
these instead of returning sentinel values or None-on-error. Routes
have a single try/except that maps each exception to an HTTP status.

Why an exception hierarchy: it lets a route catch AuthError generically
to produce a uniform error response, while specific handlers (or tests)
can still catch BadCredentials specifically. None of these carry user
input in their string form -- the message is for logs, not for users.
"""


class AuthError(Exception):
    """Base for all auth-domain errors. Routes catch this."""
    http_status = 400


class ValidationError(AuthError):
    http_status = 400


class BadCredentials(AuthError):
    http_status = 401


class NotAuthenticated(AuthError):
    http_status = 401


class NotAuthorized(AuthError):
    http_status = 403


class UserNotFound(AuthError):
    http_status = 404


class UserExists(AuthError):
    http_status = 409


class RegistrationClosed(AuthError):
    http_status = 403
