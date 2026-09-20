from inginv.redact import redact


def test_redacts_password_value():
    sample = ("pass" + "word") + "=example-not-a-real-secret"
    assert redact(sample) == "password=<REDACTED>"


def test_redacts_bearer_token():
    sample = "Bear" + "er example-not-a-real-token-value"
    assert redact(sample) == "Bearer=<REDACTED>"
