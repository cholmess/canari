from canari.alerter import AlertDispatcher


def test_signature_verify_missing_header_false():
    assert AlertDispatcher.verify_signature({"x": 1}, {}, "secret") is False
