from __future__ import annotations

import re

# Values are redacted conservatively because Inginv reports are intended to be
# shareable. Usernames are included: paired with a password they can be part of
# a reusable remote-control credential even when the username is not secret by
# itself.
_SECRET_PATTERNS = [
    re.compile(
        r"(?i)(password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|"
        r"api[_-]?key|authorization|client[_-]?secret|username|user|session|cookie)"
        r"\s*[:=]\s*([^\s,;&]{1,})"
    ),
    re.compile(r"(?i)(bearer)\s+([A-Za-z0-9._~+/=-]{3,})"),
]

# URI user-info is especially easy to miss because it does not look like a
# conventional key=value assignment.
_URL_USERINFO_RE = re.compile(
    r"(?i)\b((?:https?|wss?|ssl|mqtts?)://)([^/@\s:]+):([^/@\s]+)@"
)


def redact(text: str) -> str:
    """Redact common credential forms without reproducing their values."""
    result = _URL_USERINFO_RE.sub(
        lambda m: f"{m.group(1)}<REDACTED_USER>:<REDACTED>@",
        text,
    )
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m: f"{m.group(1)}=<REDACTED>", result)
    return result
