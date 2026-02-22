from canari.dashboard import _is_authorized


def test_dashboard_auth_none_token_allows():
    assert _is_authorized(None, {}, {}) is True


def test_dashboard_auth_header_or_query():
    assert _is_authorized("secret", {"token": ["secret"]}, {}) is True
    assert _is_authorized("secret", {}, {"X-Canari-Token": "secret"}) is True
    assert _is_authorized("secret", {}, {"X-Canari-Token": "wrong"}) is False
