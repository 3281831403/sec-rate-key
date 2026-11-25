"""Public interface for the rate-limit key builder."""

from .key import (
    build_key,
    check_dimensions,
    component,
    key_of,
    normalize_host,
    ratekey_batch,
    same_actor,
    validate_policy,
)

__all__ = [
    "normalize_host",
    "component",
    "build_key",
    "check_dimensions",
    "key_of",
    "same_actor",
    "validate_policy",
    "ratekey_batch",
]