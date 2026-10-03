from app.analyzers.csp import parse_policies, parse_policy


def test_parses_directives_and_lowercases_sources() -> None:
    policy = parse_policy("default-src 'self'; Script-Src 'SELF' https://cdn.example")
    assert policy.directives == {
        "default-src": ["'self'"],
        "script-src": ["'self'", "https://cdn.example"],
    }


def test_first_duplicate_directive_wins() -> None:
    policy = parse_policy("script-src 'self'; script-src *")
    assert policy.sources("script-src") == ["'self'"]


def test_script_sources_fall_back_to_default_src() -> None:
    assert parse_policy("default-src 'none'").script_sources() == ["'none'"]
    assert parse_policy("img-src *").script_sources() is None


def test_comma_joined_header_yields_multiple_policies() -> None:
    policies = parse_policies("default-src 'self', script-src 'none'")
    assert [p.raw for p in policies] == ["default-src 'self'", "script-src 'none'"]


def test_empty_and_blank_values_yield_no_policies() -> None:
    assert parse_policies(None) == []
    assert parse_policies("  ;  , ") == []
