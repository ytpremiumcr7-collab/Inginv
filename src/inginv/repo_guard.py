from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from pathlib import Path
import json
import re
import subprocess
from typing import Iterable

FORBIDDEN_SUFFIXES = {
    ".apk", ".aab", ".apks", ".xapk", ".dex", ".odex", ".vdex", ".oat",
    ".bks", ".jks", ".keystore", ".p12", ".pfx", ".pem", ".key",
    ".pcap", ".pcapng", ".har", ".sqlite", ".db", ".log",
    ".png", ".jpg", ".jpeg", ".webp", ".gif", ".mp4", ".mov",
}
FORBIDDEN_BASENAME_RE = re.compile(
    r"(?i)(?:_FULL_REPORT|_ACTIVE_REPORT|^logcat(?:_|\\.)|^getprop(?:_|\\.)|^tcp(?:_|\\.))"
)

TOKEN_RULES = (
    ("GH_TOKEN", "critical", re.compile(r"\\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\\b")),
    ("AWS_ACCESS_KEY", "critical", re.compile(r"\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b")),
    ("GOOGLE_API_KEY", "critical", re.compile(r"\\bAIza[0-9A-Za-z_-]{35}\\b")),
    ("SLACK_TOKEN", "critical", re.compile(r"\\bxox[baprs]-[A-Za-z0-9-]{20,}\\b")),
    ("JWT", "high", re.compile(r"\\beyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\b")),
)
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r"""(?ix)\\b(password|passwd|pwd|secret|token|access[_-]?token|refresh[_-]?token|
    api[_-]?key|authorization|client[_-]?secret|username|user|session|cookie)\\b
    \\s*[:=]\\s*["']?([^\\s"'\`,;&]{3,})["']?"""
)
SERIAL_RE = re.compile(r"(?i)\\bro\\.serialno\\b\\s*[:=]\\s*\\S+")
SSID_RE = re.compile(r'(?i)\\bSSID\\s*[:=]\\s*"[^"]+"')
BSSID_RE = re.compile(r"(?i)\\bBSSID\\s*[:=]\\s*(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\\b")
SAFE_MARKERS = (
    "<redacted>", "redacted", "example", "dummy", "placeholder",
    "not-a-real", "changeme", "your_", "your-", "${", "{{",
    "os.environ", "getenv(", "environ[",
)
PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"
)
DEFAULT_BASELINE = ".inginv/guard-baseline.json"


@dataclass(frozen=True)
class GuardFinding:
    rule: str
    severity: str
    path: str
    line: int | None
    evidence: str
    blob: str | None = None


@dataclass(frozen=True)
class BaselineEntry:
    path: str
    blob: str
    rule: str
    line: int | None


def _line(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _safe_example(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in SAFE_MARKERS)


def scan_text_high_confidence(path: str, text: str) -> list[GuardFinding]:
    """Patterns safe to apply to source and immutable history."""
    findings: list[GuardFinding] = []
    for match in PRIVATE_KEY_RE.finditer(text):
        findings.append(GuardFinding(
            "PRIVATE_KEY", "critical", path,
            _line(text, match.start()),
            "<PRIVATE_KEY_MATERIAL_REDACTED>",
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

    for rule, pattern in (
        ("DEVICE_SERIAL", SERIAL_RE),
        ("WIFI_SSID", SSID_RE),
        ("WIFI_BSSID", BSSID_RE),
    ):
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


def _git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=root, text=True, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, check=True,
    ).stdout


def tracked_blobs(root: Path) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in _git(root, "ls-files", "-s").splitlines():
        if not line:
            continue
        meta, path = line.split("\t", 1)
        fields = meta.split()
        if len(fields) >= 2:
            result[path] = fields[1]
    return result


def scan_paths(
    root: Path,
    relative_paths: Iterable[str],
    *,
    blob_ids: dict[str, str] | None = None,
) -> list[GuardFinding]:
    findings: list[GuardFinding] = []
    for rel in sorted(set(relative_paths)):
        path = root / rel
        blob = (blob_ids or {}).get(rel)
        if path.suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_BASENAME_RE.search(path.name):
            findings.append(GuardFinding(
                "FORBIDDEN_EVIDENCE_ARTIFACT", "critical", rel, None,
                f"forbidden forensic artifact type: {path.name}", blob,
            ))
            continue
        if not path.is_file():
            continue
        data = path.read_bytes()
        if _looks_binary(data):
            continue
        findings.extend(
            replace(finding, blob=blob)
            for finding in scan_text(rel, data.decode("utf-8", "replace"))
        )
    return findings


def scan_history(root: Path, max_blob_bytes: int = 8 * 1024 * 1024) -> list[GuardFinding]:
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

        if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES or FORBIDDEN_BASENAME_RE.search(Path(path).name):
            findings.append(GuardFinding(
                "FORBIDDEN_EVIDENCE_ARTIFACT_HISTORY", "critical",
                path, None, "forensic artifact exists in reachable git history", oid,
            ))
            continue
        if _looks_binary(raw):
            continue
        findings.extend(
            replace(finding, blob=oid)
            for finding in scan_text(path, raw.decode("utf-8", "replace"))
        )
    return findings


def _load_baseline(root: Path, relative_path: str | None) -> list[BaselineEntry]:
    if not relative_path:
        return []
    path = root / relative_path
    if not path.exists():
        return []
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid guard baseline: {relative_path}") from exc
    if payload.get("version") != 1 or not isinstance(payload.get("entries"), list):
        raise ValueError(f"unsupported guard baseline: {relative_path}")

    result: list[BaselineEntry] = []
    for item in payload["entries"]:
        if not isinstance(item, dict):
            raise ValueError("guard baseline entries must be objects")
        entry = BaselineEntry(
            path=str(item.get("path", "")),
            blob=str(item.get("blob", "")),
            rule=str(item.get("rule", "")),
            line=item.get("line"),
        )
        if not entry.path or len(entry.blob) < 12 or not entry.rule:
            raise ValueError("guard baseline entry is incomplete")
        result.append(entry)
    return result


def _is_baselined(finding: GuardFinding, baseline: list[BaselineEntry]) -> bool:
    if not finding.blob:
        return False
    return any(
        finding.path == entry.path
        and finding.blob.startswith(entry.blob)
        and finding.rule == entry.rule
        and finding.line == entry.line
        for entry in baseline
    )


def scan_repository(
    root: str | Path,
    history: bool = False,
    *,
    baseline_file: str | None = DEFAULT_BASELINE,
) -> dict:
    root_path = Path(root).resolve()
    blobs = tracked_blobs(root_path)
    findings = scan_paths(root_path, blobs, blob_ids=blobs)
    if history:
        findings.extend(scan_history(root_path))

    unique = {
        (f.rule, f.severity, f.path, f.line, f.evidence, f.blob): f
        for f in findings
    }
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ordered = sorted(
        unique.values(),
        key=lambda f: (
            order.get(f.severity, 9), f.path, f.line or 0, f.rule, f.blob or ""
        ),
    )
    baseline = _load_baseline(root_path, baseline_file)

    rendered: list[dict] = []
    blocking_count = 0
    baselined_count = 0
    for finding in ordered:
        baselined = _is_baselined(finding, baseline)
        if baselined:
            baselined_count += 1
        else:
            blocking_count += 1
        rendered.append({**asdict(finding), "baselined": baselined})

    return {
        "root": root_path.name,
        "history_scanned": history,
        "baseline_file": baseline_file,
        "finding_count": len(rendered),
        "blocking_count": blocking_count,
        "baselined_count": baselined_count,
        "findings": rendered,
    }


def dump_guard_json(report: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
