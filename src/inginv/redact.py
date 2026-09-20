from __future__ import annotations

import re

_SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[:=]\s*([^\s,;]{3,})"),
    re.compile(r"(?i)(bearer)\s+([A-Za-z0-9._~+/=-]{8,})"),
]


def redact(text: str) -> str:
    """Redact common inline credential forms without hiding the key name."""
    result = text
    for pattern in _SECRET_PATTERNS:
        result = pattern.sub(lambda m: f"{m.group(1)}=<REDACTED>", result)
    return result
