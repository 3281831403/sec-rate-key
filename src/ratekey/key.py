"""Canonical rate-limit key construction.

The module works on plain dictionaries so callers can build meter keys from
request metadata without pulling in a web framework.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

SEPARATOR = "|"
DEFAULT_MISSING = "<missing>"
DEFAULT_DIMENSIONS = ("subject", "route", "host")
_KEY_FIELDS = ("host",)
_DEFAULT_PORTS = frozenset({"80", "443"})


def _request_value(request: Mapping[str, Any], name: str) -> str | None:
    value = request.get(name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def normalize_host(host: object) -> str:
    """Return the canonical form of a Host header value."""
    if host is None:
        return ""
    return str(host).strip()


def component(value: object) -> str:
    """Render one key component."""
    if value is None:
        return ""
    return str(value)


def _placeholder_token(policy: Mapping[str, Any] | None) -> str:
    if not isinstance(policy, Mapping):
        return ""
    token = policy.get("missing")
    if token is None:
        return ""
    return str(token).strip()


def _assemble(request: Mapping[str, Any], placeholder: str = "") -> str:
    parts: list[str] = []
    for name in _KEY_FIELDS:
        value = _request_value(request, name)
        if value is None:
            text = placeholder
        elif name == "host":
            text = normalize_host(value)
        else:
            text = value
        parts.append(component(text))
    return SEPARATOR.join(parts)


def build_key(request: Mapping[str, Any]) -> str:
    """Build the meter key for one request."""
    return _assemble(request)


def check_dimensions(
    request: Mapping[str, Any], policy: Mapping[str, Any]
) -> list[str]:
    """List policy dimensions that are absent or blank on the request."""
    if not isinstance(policy, Mapping):
        return []
    dimensions = policy.get("dimensions")
    if not isinstance(dimensions, (list, tuple)):
        return []
    missing: list[str] = []
    for name in dimensions:
        if not isinstance(name, str) or not name or name in missing:
            continue
        if _request_value(request, name) is None:
            missing.append(name)
    return missing


def key_of(request: Mapping[str, Any], policy: Mapping[str, Any]) -> str:
    """Build the final key under a rate-limit policy."""
    check_dimensions(request, policy)
    return _assemble(request)


def same_actor(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> bool:
    """Return whether two requests should share one rate-limit bucket."""
    left = build_key(first)
    right = build_key(second)
    return left.startswith(right) or right.startswith(left)


def validate_policy(policy: Mapping[str, Any]) -> list[str]:
    """Return configuration problems found in a rate-limit policy."""
    if not isinstance(policy, Mapping):
        return ["policy must be a mapping"]
    problems: list[str] = []
    if policy.get("normalize_host") is not True:
        problems.append("host normalization is required")
    missing = policy.get("missing")
    if not isinstance(missing, str) or not missing.strip():
        problems.append("missing placeholder must not be empty")
    return problems


def ratekey_batch(
    requests: list[Mapping[str, Any]], policy: Mapping[str, Any]
) -> dict[str, Any]:
    """Build keys for a batch of requests."""
    requests = list(requests)
    first_key = key_of(requests[0], policy) if requests else ""
    keys = [first_key for _ in requests]
    missing = [check_dimensions(request, policy) for request in requests]
    return {
        "keys": keys,
        "missing": missing,
        "valid": [not item for item in missing],
    }