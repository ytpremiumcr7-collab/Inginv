from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable

from .redact import redact

FORBIDDEN_SUFFIXES = {
    ".apk", ".aab", ".apks", ".xapk", ".dex", ".odex", ".vdex", ".oat",
    ".bks", ".jks", ".keystore", ".p12", ".pfx", ".pcap", ".pcapng", ".har",
}
FORBIDDEN_BASENAME_RE = re.compile(
    r"(?i)(?:_FULL_REPORT|_ACTIVE_REPORT|^logcat(?:_|\\.)|^getprop(?:_|\\.)|^tcp(?:_|\\.))"
)

TOKEN_RULES = (
    ("GH_TOKEN", "critical", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("AWS_ACCESS_KEY", "critical", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    ("GOOGLE_API_KEY", "critical", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("SLACK_TOKEN", "critical", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
    ("JWT", "high", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"""(?ix)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization|client[_-]?secret)\b
    \s*[:=]\s*["']?([^\s"'`,;]{8,})["']?"""
)
SERIAL_RE = re.compile(r"(?i)\bro\.serialno\b\s*[:=]\s*\S+")
SSID_RE = re.compile(r'(?i)\bSSID\s*[:=]\s*"[^"]+"')
BSSID_RE = re.compile(r"(?i)\bBSSID\s*[:=]\s*(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
SAFE_MARKERS = ("<redacted>", "redacted", "example", "dummy", "placeholder", "not-a-real", "changeme", "your_", "your-", "${", "{{")


@dataclass(frozen=True)
class GuardFinding:
    rule: str
    severity: str
    path: str
    line: int | None
    evidence: str


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_example(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SAFE_MARKERS)


def scan_text_high_confidence(path: str, text: str) -> list[GuardFinding]:
    """Patterns safe to apply to immutable history with a very low false-positive rate."""
    findings: list[GuardFinding] = []
    private_key_marker = "-----BEGIN " + "PRIVATE KEY-----"
    if private_key_marker in text:
        findings.append(GuardFinding(
            "PRIVATE_KEY", "critical", path,
            _line(text, text.index(private_key_marker)),
            private_key_marker,
        ))
    for rule, severity, pattern in TOKEN_RULES:
        for match in pattern.finditer(text):
            findings.append(GuardFinding(
                rule, severity, path, _line(text, match.start()), "<REDACTED_TOKEN>"
            ))
    return findings


def scan_text(path: str, text: str) -> list[GuardFinding]:
    findings = scan_text_high_confidence(path, text)

    for match in CREDENTIAL_ASSIGNMENT_RE.finditer(text):
        value = match.group(2)
        if _safe_example(value):
            continue
        findings.append(GuardFinding(
            "HARDCODED_CREDENTIAL", "high", path,
            _line(text, match.start()),
            f"{match.group(1)}=<REDACTED>",
        ))

    for rule, pattern in (("DEVICE_SERIAL", SERIAL_RE), ("WIFI_SSID", SSID_RE), ("WIFI_BSSID", BSSID_RE)):
        for match in pattern.finditer(text):
            findings.append(GuardFinding(
                rule, "high", path, _line(text, match.start()), f"{rule}=<REDACTED>"
            ))

    return findings


def _looks_binary(data: bytes) -> bool:
    if not data:
        return False
    sample = data[:4096]
    if b"\x00" in sample:
        return True
    printable = sum((32 <= b <= 126) or b in b"\n\r\t\f\b" for b in sample)
    return printable / len(sample) < 0.75


def scan_paths(root: Path, relative_paths: Iterable[str]) -> list[GuardFinding]:
    findings: list[GuardFinding] = []
    for rel in sorted(set(relative_paths)):
        path = root / rel
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_BASENAME_RE.search(path.name):
            findings.append(GuardFinding(
                "FORBIDDEN_EVIDENCE_ARTIFACT", "critical", rel, None,
                f"forbidden forensic artifact type: {path.name}",
            ))
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        if _looks_binary(data):
            continue
        findings.extend(scan_text(rel, data.decode("utf-8", "replace")))
    return findings


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True,
    ).stdout


def tracked_paths(root: Path) -> list[str]:
    return [p for p in _git(root, "ls-files").splitlines() if p]


def scan_history(root: Path, max_blob_bytes: int = 2 * 1024 * 1024) -> list[GuardFinding]:
    findings: list[GuardFinding] = []
    seen: set[str] = set()
    for line in _git(root, "rev-list", "--objects", "--all").splitlines():
        if not line:
            continue
        parts = line.split(" ", 1)
        oid = parts[0]
        path = parts[1] if len(parts) == 2 else f"<object:{oid[:12]}>"
        if oid in seen:
            continue
        seen.add(oid)
        if _git(root, "cat-file", "-t", oid).strip() != "blob":
            continue
        if int(_git(root, "cat-file", "-s", oid).strip()) > max_blob_bytes:
            continue
        raw = subprocess.run(
            ["git", "cat-file", "blob", oid], cwd=root,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
        ).stdout
        if _looks_binary(raw):
            continue
        findings.extend(scan_text_high_confidence(f"{path}@{oid[:12]}", raw.decode("utf-8", "replace")))
        if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_BASENAME_RE.search(Path(path).name):
            findings.append(GuardFinding(
                "FORBIDDEN_EVIDENCE_ARTIFACT_HISTORY", "critical",
                f"{path}@{oid[:12]}", None,
                "forensic artifact exists in reachable git history",
            ))
    return findings


def scan_repository(root: str | Path, history: bool = False) -> dict:
    root_path = Path(root).resolve()
    findings = scan_paths(root_path, tracked_paths(root_path))
    if history:
        findings.extend(scan_history(root_path))
    unique = {(f.rule, f.severity, f.path, f.line, f.evidence): f for f in findings}
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered = sorted(unique.values(), key=lambda f: (order.get(f.severity, 9), f.path, f.line or 0, f.rule))
    return {
        "root": str(root_path),
        "history_scanned": history,
        "finding_count": len(ordered),
        "findings": [asdict(f) for f in ordered],
    }


def dump_guard_json(report: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
