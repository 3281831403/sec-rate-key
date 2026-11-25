from __future__ import annotations

from ratekey import (
    build_key,
    check_dimensions,
    key_of,
    normalize_host,
    ratekey_batch,
    validate_policy,
)


def policy() -> dict:
    return {
        "dimensions": ["subject", "route", "host"],
        "normalize_host": True,
        "missing": "<missing>",
    }


def request(subject: str = "alice", route: str = "/login", host: str = "api.example.com") -> dict:
    return {"subject": subject, "route": route, "host": host}


def test_host_normalization_collapses_case_dot_and_default_port() -> None:
    assert normalize_host("API.Example.COM.:443") == "api.example.com"
    assert normalize_host("api.example.com.") == "api.example.com"


def test_build_key_contains_subject_route_and_origin() -> None:
    assert build_key(request()) == "alice|%2Flogin|api.example.com"


def test_equivalent_host_spellings_produce_one_key() -> None:
    variants = [
        "api.example.com",
        "API.Example.COM",
        "api.example.com.",
        "api.example.com:443",
        "API.Example.COM.:443",
    ]

    keys = {key_of(request(host=host), policy()) for host in variants}

    assert len(keys) == 1


def test_dimension_validation_flags_a_missing_route() -> None:
    incomplete = request()
    del incomplete["route"]

    assert check_dimensions(incomplete, policy()) == ["route"]

    broken = policy()
    broken["dimensions"] = ["subject", "host"]
    problems = validate_policy(broken)

    assert any("route" in problem for problem in problems)


def test_ratekey_batch_keeps_requests_independent() -> None:
    requests = [
        request(subject="alice", host="one.example.com"),
        request(subject="bob", host="two.example.com"),
    ]

    result = ratekey_batch(requests, policy())

    assert result["keys"][0] != result["keys"][1]
    assert result["keys"] == [key_of(item, policy()) for item in requests]