"""Canonical rate-limit key construction.

The module works on plain dictionaries so callers can build meter keys from
request metadata without pulling in a web framework.

Key layout (fixed order, fixed width):

    subject|route|host

Invariants:

* The host is normalized before it enters the key: case is folded, trailing
  dots and default ports (80/443) do not change the result, so every spelling
  of one logical origin lands on one key.
* All three dimensions (subject, route, host) are always present. A missing
  dimension is rendered as a fixed placeholder token, never as an empty
  string. The placeholder is inserted raw while every request-supplied value
  is percent-escaped, so user input can never forge a placeholder or the
  field separator.
* Every request is keyed independently; equivalent requests share a key,
  different subjects never share a quota.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote

SEPARATOR = "|"
DEFAULT_MISSING = "<missing>"
DEFAULT_DIMENSIONS = ("subject", "route", "host")
_KEY_FIELDS = ("subject", "route", "host")
_DEFAULT_PORTS = frozenset({"80", "443"})


def _request_value(request: Mapping[str, Any], name: str) -> str | None:
    value = request.get(name)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _strip_default_port(lowered: str) -> str:
    """Drop a default :80/:443 port, keeping any other port intact."""
    if lowered.startswith("["):
        # Bracket-wrapped IPv6 literal, e.g. "[2001:db8::1]:443".
        end = lowered.find("]")
        if end == -1:
            return lowered
        hostname = lowered[: end + 1]
        tail = lowered[end + 1 :]
        if tail.startswith(":") and tail[1:].isdigit():
            return hostname if tail[1:] in _DEFAULT_PORTS else hostname + tail
        return hostname + tail

    hostname, sep, port = lowered.rpartition(":")
    if sep and port.isdigit():
        # Numeric port: drop only the scheme-default ones.
        return hostname if port in _DEFAULT_PORTS else lowered
    return lowered


def normalize_host(host: object) -> str:
    """Return the canonical form of a Host header value.

    Folds case, removes trailing DNS dots and strips default ports so that
    ``API.Example.COM.:443`` and ``api.example.com`` normalize identically.
    Non-default ports are preserved because they denote a different origin.
    """
    if host is None:
        return ""
    raw = str(host).strip().lower()
    if not raw:
        return ""
    return _strip_default_port(raw).rstrip(".")


def component(value: object) -> str:
    """Render one request-supplied key component.

    Percent-escaping removes every character that could be confused with the
    field separator or a placeholder token, including ``%`` itself, so a
    caller cannot smuggle structural characters into the key.
    """
    if value is None:
        return ""
    return quote(str(value), safe="")


def _placeholder_token(policy: Mapping[str, Any] | None) -> str:
    if not isinstance(policy, Mapping):
        return DEFAULT_MISSING
    token = policy.get("missing")
    if not isinstance(token, str) or not token.strip():
        return DEFAULT_MISSING
    return token.strip()


def _assemble(request: Mapping[str, Any], placeholder: str = DEFAULT_MISSING) -> str:
    parts: list[str] = []
    for name in _KEY_FIELDS:
        value = _request_value(request, name)
        if value is None:
            # Fixed token, inserted raw: request values are escaped below,
            # so user input can never produce this exact component.
            parts.append(placeholder)
        elif name == "host":
            normalized = normalize_host(value)
            parts.append(component(normalized) if normalized else placeholder)
        else:
            parts.append(component(value))
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
    placeholder = _placeholder_token(policy)
    return _assemble(request, placeholder)


def same_actor(
    first: Mapping[str, Any], second: Mapping[str, Any]
) -> bool:
    """Return whether two requests should share one rate-limit bucket."""
    # Full-key equality only: prefix matching merges distinct actors whose
    # keys happen to share a leading substring.
    return build_key(first) == build_key(second)


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
    dimensions = policy.get("dimensions")
    if not isinstance(dimensions, (list, tuple)):
        problems.append(
            "dimensions must be a list containing subject, route and host"
        )
    else:
        for name in DEFAULT_DIMENSIONS:
            if name not in dimensions:
                problems.append(f"policy dimensions must include {name}")
    return problems


def ratekey_batch(
    requests: list[Mapping[str, Any]], policy: Mapping[str, Any]
) -> dict[str, Any]:
    """Build keys for a batch of requests.

    Each request is keyed on its own; one request's key is never reused for
    another request in the same batch.
    """
    requests = list(requests)
    keys = [key_of(item, policy) for item in requests]
    missing = [check_dimensions(request, policy) for request in requests]
    return {
        "keys": keys,
        "missing": missing,
        "valid": [not item for item in missing],
    }
