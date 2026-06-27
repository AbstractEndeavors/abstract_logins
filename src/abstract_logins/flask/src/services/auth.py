"""
Authentication service. The single function authenticate() takes a
LoginSpec, returns a user row on success, raises BadCredentials on
failure. It also opportunistically rehashes legacy bcrypt passwords
to argon2 when verification succeeds.

Why a service layer at all in a project this small: it's where
multi-step logic lives. authenticate() touches users (lookup), hashing
(verify), and users again (rehash on success). Putting this in the
route would mix HTTP concerns with domain logic; putting it in the
DAL would force the DAL to know about hashing. Services are the
correct home.
"""
from ..imports.errors import BadCredentials, AuthError
from ..imports.hashing import verify_password, hash_password
from ..dal import users as user_dal


_DUMMY_ARGON2_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=1$"
    "AAAAAAAAAAAAAAAAAAAAAA$"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
)


def authenticate(hasher, spec):
    user = user_dal.get_by_username(spec.username)

    if user is None:
        verify_password(hasher, spec.password, _DUMMY_ARGON2_HASH)
        raise BadCredentials("invalid credentials")

    ok, needs_rehash = verify_password(
        hasher,
        spec.password,
        user["password_hash"],
    )

    if not ok:
        raise BadCredentials("invalid credentials")

    status = user.get("status", "approved")

    if status == "pending":
        raise AuthError("Your account is awaiting approval.")
    if status == "rejected":
        raise AuthError("Your account application was not approved.")
    if status == "suspended":
        raise AuthError("Your account has been suspended.")
    if status != "approved":
        raise AuthError("Account is not active.")

    if needs_rehash:
        try:
            new_hash = hash_password(hasher, spec.password)
            user_dal.update_password(user["id"], new_hash)
        except Exception:
            pass

    return user
