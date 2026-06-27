"""
User-management services.
"""
from ..imports.errors import (
    RegistrationClosed,
    BadCredentials,
    ValidationError,
    UserExists,
)
from ..imports.hashing import hash_password, verify_password
from ..dal import users as user_dal
from ..session import logout_all_for_user


_VALID_STATUSES = {"pending", "approved", "rejected", "suspended"}


def register(cfg, hasher, spec):
    if not cfg.registration_open:
        raise RegistrationClosed("registration is disabled")

    if len(spec.password) < cfg.password_min_length:
        raise ValidationError(
            f"password must be at least {cfg.password_min_length} characters"
        )

    pw_hash = hash_password(hasher, spec.password)

    try:
        return user_dal.create(
            username=spec.username,
            email=spec.email,
            password_hash=pw_hash,
            is_admin=False,
            status="pending",
        )
    except UserExists:
        raise


def change_password(cfg, hasher, user, spec):
    if len(spec.new_password) < cfg.password_min_length:
        raise ValidationError(
            f"password must be at least {cfg.password_min_length} characters"
        )

    ok, _ = verify_password(hasher, spec.current_password, user["password_hash"])
    if not ok:
        raise BadCredentials("current password incorrect")

    new_hash = hash_password(hasher, spec.new_password)
    user_dal.update_password(user["id"], new_hash)

    logout_all_for_user(user["id"])


def list_by_status(cfg, status):
    if status not in _VALID_STATUSES:
        raise ValidationError(f"invalid status: {status}")
    return user_dal.list_by_status(status)


def set_status(cfg, user_id, status, actor=None, reason=None):
    if status not in _VALID_STATUSES:
        raise ValidationError(f"invalid status: {status}")

    actor_id = actor["id"] if actor else None
    user_dal.set_status(
        user_id=user_id,
        status=status,
        actor_id=actor_id,
        reason=reason,
    )
