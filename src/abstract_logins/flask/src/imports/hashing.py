"""
Password hashing. Argon2id by default. A verify-and-migrate helper
upgrades legacy bcrypt hashes transparently on next successful login,
so you never need to send everyone a "reset your password" email when
you change algorithms.

The hasher is constructed from Config so timing parameters are
explicit and testable. Don't import argon2 anywhere except here.
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError


def make_hasher(cfg):
    """Build a PasswordHasher from Config. Called once at app start."""
    return PasswordHasher(
        time_cost=cfg.argon2_time_cost,
        memory_cost=cfg.argon2_memory_cost_kib,
        parallelism=cfg.argon2_parallelism,
    )


def hash_password(hasher, plaintext):
    """Hash a new password. Returns the encoded string for storage."""
    if not plaintext:
        raise ValueError("plaintext must be non-empty")
    return hasher.hash(plaintext)


def verify_password(hasher, plaintext, stored_hash):
    """
    Returns (ok, needs_rehash).
      ok           - True if the password matches.
      needs_rehash - True if the stored hash is valid but uses old params
                     (or a legacy algorithm). Caller should re-hash and
                     update the row when this is True.

    Never raises on a bad password. Only raises on truly malformed input
    (empty hash, wrong type) which indicates a bug, not a user error.
    """
    if not stored_hash:
        return False, False

    # Legacy bcrypt path. Recognize by prefix; verify with bcrypt; signal rehash.
    if stored_hash.startswith("$2a$") or stored_hash.startswith("$2b$") or stored_hash.startswith("$2y$"):
        try:
            import bcrypt
            ok = bcrypt.checkpw(plaintext.encode("utf-8"), stored_hash.encode("utf-8"))
            return ok, ok  # if it matched, rehash to argon2 next
        except (ValueError, TypeError):
            return False, False

    # Argon2 path.
    try:
        hasher.verify(stored_hash, plaintext)
    except VerifyMismatchError:
        return False, False
    except (InvalidHash, VerificationError):
        return False, False

    return True, hasher.check_needs_rehash(stored_hash)
