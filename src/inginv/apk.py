from __future__ import annotations

from dataclasses import dataclass, asdict
from hashlib import sha256
from pathlib import Path, PurePosixPath
import json
import re
import zipfile
from urllib.parse import urlsplit, urlunsplit

from .redact import redact

URL_RE = re.compile(rb"(?:https?|wss?|ssl|mqtts?)://[^\x00-\x20\"'<>]{3,}", re.I)
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
CREDENTIAL_HINT_RE = re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|username)\b")
COMMAND_HINTS = {
    "installApp", "uninstallApp", "reboot", "factoryReset", "screenShot",
    "fileDelete", "logCapture", "location", "trackingDeviceLocation",
    "setPasscode", "clearPasscode", "clearAppCache", "lock", "unlock",
    "powerOff", "remoteCare", "sourceFile", "oemConfig", "TCPing",
}


def _safe_url(value: str) -> str:
    """Preserve endpoint structure while dropping credentials and volatile identifiers."""
    sanitized = redact(value)
    try:
        parsed = urlsplit(sanitized)
        host = parsed.hostname
        port = parsed.port
    except ValueError:
        return "<REDACTED_URL>"
    if not parsed.scheme or not host:
        return "<REDACTED_URL>"
    netloc = host if port is None else f"{host}:{port}"
    segments = [
        "<REDACTED_SEGMENT>" if len(segment) >= 48 else segment
        for segment in (parsed.path or "").split("/")
    ]
    return urlunsplit((parsed.scheme, netloc, "/".join(segments), "", ""))


@dataclass(frozen=True)
class Entry:
    name: str
    size: int
    compressed_size: int
    kind: str
    sha256: str


def file_sha256(path: Path) -> str:
    h = sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify(name: str) -> str:
    lower = name.lower()
    if re.fullmatch(r"classes\d*\.dex", PurePosixPath(name).name):
        return "dex"
    if lower.startswith("lib/") and lower.endswith(".so"):
        return "native-library"
    if lower == "androidmanifest.xml":
        return "manifest"
    if lower.endswith((".rsa", ".dsa", ".ec")) and lower.startswith("meta-inf/"):
        return "signature-block"
    if lower.endswith((".sf", ".mf")) and lower.startswith("meta-inf/"):
        return "signature-metadata"
    if lower.endswith((".bks", ".jks", ".keystore", ".p12", ".pfx")):
        return "keystore"
    if lower.endswith(".xml"):
        return "xml"
    if lower.startswith("assets/"):
        return "asset"
    if lower.startswith("res/"):
        return "resource"
    return "other"


def _entry_has_path_traversal(name: str) -> bool:
    p = PurePosixPath(name)
    return p.is_absolute() or ".." in p.parts


def summarize(path: str | Path) -> dict:
    apk = Path(path)
    if not apk.is_file():
        raise FileNotFoundError(apk)

    entries: list[Entry] = []
    traversal: list[str] = []
    with zipfile.ZipFile(apk) as zf:
        corrupt = zf.testzip()
        for zi in zf.infolist():
            if zi.is_dir():
                continue
            data = zf.read(zi)
            entries.append(Entry(
                name=zi.filename,
                size=zi.file_size,
                compressed_size=zi.compress_size,
                kind=classify(zi.filename),
                sha256=sha256(data).hexdigest(),
            ))
            if _entry_has_path_traversal(zi.filename):
                traversal.append(zi.filename)

    by_kind: dict[str, int] = {}
    for entry in entries:
        by_kind[entry.kind] = by_kind.get(entry.kind, 0) + 1

    native_abis = sorted({PurePosixPath(e.name).parts[1] for e in entries
                          if e.kind == "native-library" and len(PurePosixPath(e.name).parts) > 2})

    return {
        "path": apk.name,
        "size": apk.stat().st_size,
        "sha256": file_sha256(apk),
        "zip_integrity": "ok" if corrupt is None else f"corrupt:{corrupt}",
        "entry_count": len(entries),
        "counts": dict(sorted(by_kind.items())),
        "native_abis": native_abis,
        "path_traversal_entries": traversal,
        "entries": [asdict(e) for e in entries],
    }


def extract_strings(path: str | Path, *, max_per_entry: int = 10000) -> dict:
    apk = Path(path)
    urls: set[str] = set()
    command_hits: list[dict] = []
    credential_hints: list[dict] = []

    with zipfile.ZipFile(apk) as zf:
        for zi in zf.infolist():
            if zi.is_dir() or zi.file_size > 64 * 1024 * 1024:
                continue
            data = zf.read(zi)
            for raw in URL_RE.findall(data):
                urls.add(_safe_url(raw.decode("utf-8", "replace")))
            seen = 0
            for raw in ASCII_RE.findall(data):
                text = raw.decode("ascii", "replace")
                seen += 1
                if seen > max_per_entry:
                    break
                hits = sorted(h for h in COMMAND_HINTS if h.lower() in text.lower())
                if hits:
                    command_hits.append({
                        "entry": zi.filename,
                        "commands": hits,
                        "string_length": len(text),
                    })
                indicators = sorted({
                    match.group(1).lower()
                    for match in CREDENTIAL_HINT_RE.finditer(text)
                })
                if indicators:
                    credential_hints.append({
                        "entry": zi.filename,
                        "indicators": indicators,
                        "string_length": len(text),
                    })

    return {
        "apk_sha256": file_sha256(apk),
        "urls": sorted(urls),
        "command_hits": command_hits,
        "credential_hints": credential_hints,
    }


def dump_json(data: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
