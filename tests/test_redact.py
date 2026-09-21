from inginv.redact import redact


def test_redacts_password_value():
    sample = ("pass" + "word") + "=example-not-a-real-secret"
    assert redact(sample) == "password=<REDACTED>"


def test_redacts_short_password_and_username():
    sample = ("user" + "name") + "=operator " + ("pass" + "word") + "=123456"
    rendered = redact(sample)
    assert "operator" not in rendered
    assert "123456" not in rendered
    assert "username=<REDACTED>" in rendered
    assert "password=<REDACTED>" in rendered


def test_redacts_bearer_token():
    sample = "Bear" + "er example-not-a-real-token-value"
    assert redact(sample) == "Bearer=<REDACTED>"


def test_redacts_url_userinfo():
    sample = "ssl://operator:123456@example.invalid:1886/client"
    rendered = redact(sample)
    assert "operator" not in rendered
    assert "123456" not in rendered
    assert "<REDACTED_USER>:<REDACTED>@" in rendered
