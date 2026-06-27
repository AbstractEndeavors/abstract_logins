"""
Request schemas. Every shape that crosses the network boundary is
defined here, exactly once. Routes call `Spec.from_request(request)`
and either get a validated object or a ValidationError. Services
take these typed objects, never raw dicts.

This file is the answer to "what does the API actually accept?"
If a field isn't here, the API doesn't accept it.
"""
"""
Request schemas.
"""
import re
from dataclasses import dataclass

from pydantic import BaseModel, Field, ValidationError as PydanticValidationError, field_validator

from .errors import ValidationError, AuthError


_USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,31}$")


class _Spec(BaseModel):
    model_config = {"extra": "forbid", "str_strip_whitespace": True}

    @classmethod
    def from_json(cls, data):
        if not isinstance(data, dict):
            raise ValidationError("request body must be a JSON object")

        try:
            return cls(**data)
        except PydanticValidationError as exc:
            errors = exc.errors()
            if errors:
                loc = ".".join(str(x) for x in errors[0]["loc"])
                raise ValidationError(f"{loc}: {errors[0]['msg']}")
            raise ValidationError("invalid request")


class LoginSpec(_Spec):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=1, max_length=256)

    @field_validator("username")
    @classmethod
    def _username_shape(cls, value):
        value = value.lower()
        if not _USERNAME_RE.match(value):
            raise ValueError(
                "must be 3-32 chars, lowercase letters/digits/_/-, "
                "starting with letter or digit"
            )
        return value


class RegisterSpec(_Spec):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=10, max_length=256)
    email: str | None = Field(default=None, max_length=254)

    @field_validator("username")
    @classmethod
    def _username_shape(cls, value):
        value = value.lower()
        if not _USERNAME_RE.match(value):
            raise ValueError(
                "must be 3-32 chars, lowercase letters/digits/_/-, "
                "starting with letter or digit"
            )
        return value

    @field_validator("email")
    @classmethod
    def _email_shape(cls, value):
        if value is None:
            return value
        if "@" not in value or "." not in value.split("@", 1)[-1]:
            raise ValueError("must look like an email address")
        return value.lower()


class ChangePasswordSpec(_Spec):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=10, max_length=256)

    @field_validator("new_password")
    @classmethod
    def _not_same_as_current(cls, value, info):
        current = info.data.get("current_password")
        if current is not None and value == current:
            raise ValueError("new password must differ from current")
        return value


@dataclass
class RejectSpec:
    reason: str

    @classmethod
    def from_json(cls, data):
        if not isinstance(data, dict):
            raise AuthError("Invalid request body")

        reason = (data.get("reason") or "").strip()
        if not reason:
            raise AuthError("Reason is required")

        return cls(reason=reason)
