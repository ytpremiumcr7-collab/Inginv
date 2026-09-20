from inginv.redact import redact


def test_redacts_password_value():
    assert redact("password=supersecret") == "password=<REDACTED>"


def test_redacts_bearer_token():
    assert redact("Bearer abcdefghijklmnop") == "Bearer=<REDACTED>"
