from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import ipaddress
import json
import re
import subprocess
import time
import uuid
from typing import Callable, Sequence

from .redact import redact

PACKAGE_RE = re.compile(r"^[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)+$")
IPV4_RE = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
IPV6_CANDIDATE_RE = re.compile(r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}[0-9A-Fa-f:]{0,4}(?![0-9A-Fa-f:])")
MAC_RE = re.compile(r"(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b")
SSID_RE = re.compile(r'(?i)(SSID\s*[:=]\s*)(?:"[^"]*"|[^\s,}]+)')
SERIAL_VALUE_RE = re.compile(r"(?i)(ro\.serialno\s*[:=]\s*)[^\s]+")
TOKEN_CONTEXT_RE = re.compile(
    r"(?i)\b(token|authorization|auth|fcm|registration[_-]?id|api[_-]?key|secret)\b"
)
LONG_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_./+=-])[A-Za-z0-9_./+=-]{36,}(?![A-Za-z0-9_./+=-])")

MAX_CAPTURE_BYTES = 2 * 1024 * 1024


class RuntimeCollectionError(RuntimeError):
    pass


@dataclass(frozen=True)
class CommandResult:
    name: str
    argv: list[str]
    started_at: str
    duration_ms: int
    exit_code: int
    stdout: str
    stderr: str
    truncated: bool = False


@dataclass
class RuntimeBundle:
    schema: str
    capture_id: str
    captured_at: str
    package: str
    device: dict[str, str | None]
    records: list[CommandResult] = field(default_factory=list)
    privacy: dict[str, object] = field(default_factory=dict)


@dataclass(frozen=True)
class RuntimeFact:
    fact_id: str
    evidence_state: str
    value: bool | str | int | None
    evidence_records: tuple[str, ...]
    does_not_prove: str


Runner = Callable[[Sequence[str], float], tuple[int, bytes, bytes]]


def _default_runner(argv: Sequence[str], timeout: float) -> tuple[int, bytes, bytes]:
    completed = subprocess.run(
        list(argv),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


def _sanitize_ipv6(text: str) -> str:
    def replace(match: re.Match[str]) -> str:
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            return candidate
        return "<IPV6_REDACTED>"
    return IPV6_CANDIDATE_RE.sub(replace, text)


def sanitize_runtime_text(text: str) -> str:
    """Remove credentials and device/network identifiers before serialization."""
    text = redact(text)
    text = SERIAL_VALUE_RE.sub(r"\1<REDACTED>", text)
    text = SSID_RE.sub(r"\1<REDACTED>", text)
    text = MAC_RE.sub("<MAC_REDACTED>", text)
    text = IPV4_RE.sub("<IPV4_REDACTED>", text)
    text = _sanitize_ipv6(text)

    lines: list[str] = []
    for line in text.splitlines():
        if TOKEN_CONTEXT_RE.search(line):
            line = LONG_TOKEN_RE.sub("<TOKEN_REDACTED>", line)
        lines.append(line)
    return "\n".join(lines)


def _bounded_decode(data: bytes) -> tuple[str, bool]:
    truncated = len(data) > MAX_CAPTURE_BYTES
    data = data[:MAX_CAPTURE_BYTES]
    return sanitize_runtime_text(data.decode("utf-8", "replace")), truncated


class AdbCollector:
    def __init__(
        self,
        *,
        adb_path: str = "adb",
        serial: str | None = None,
        timeout: float = 15.0,
        runner: Runner | None = None,
    ):
        self.adb_path = adb_path
        self.serial = serial
        self.timeout = timeout
        self.runner = runner or _default_runner

    def _base(self) -> list[str]:
        argv = [self.adb_path]
        if self.serial:
            argv += ["-s", self.serial]
        return argv

    def run(self, name: str, logical_argv: Sequence[str]) -> CommandResult:
        # logical_argv is deliberately stored without the ADB device selector so
        # a device serial never leaks into a report through the command field.
        full = [*self._base(), *logical_argv]
        started = datetime.now(timezone.utc)
        monotonic = time.monotonic()
        try:
            exit_code, stdout_raw, stderr_raw = self.runner(full, self.timeout)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or b""
            stderr = exc.stderr or b""
            out_text, out_truncated = _bounded_decode(stdout)
            err_text, err_truncated = _bounded_decode(stderr)
            return CommandResult(
                name=name,
                argv=list(logical_argv),
                started_at=started.isoformat(),
                duration_ms=int((time.monotonic() - monotonic) * 1000),
                exit_code=124,
                stdout=out_text,
                stderr=(err_text + "\n<TIMEOUT>").strip(),
                truncated=out_truncated or err_truncated,
            )

        stdout, out_truncated = _bounded_decode(stdout_raw)
        stderr, err_truncated = _bounded_decode(stderr_raw)
        return CommandResult(
            name=name,
            argv=list(logical_argv),
            started_at=started.isoformat(),
            duration_ms=int((time.monotonic() - monotonic) * 1000),
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            truncated=out_truncated or err_truncated,
        )


def _first_nonempty(result: CommandResult) -> str | None:
    for line in result.stdout.splitlines():
        value = line.strip()
        if value:
            return value
    return None


def _safe_package(package: str) -> str:
    if not PACKAGE_RE.fullmatch(package):
        raise ValueError("package must be a dotted Android package identifier")
    return package


def collect_runtime(
    package: str,
    *,
    adb_path: str = "adb",
    serial: str | None = None,
    include_network: bool = False,
    logcat_lines: int = 0,
    runner: Runner | None = None,
) -> dict:
    """Collect bounded, read-only ADB evidence and sanitize it before returning."""
    package = _safe_package(package)
    if logcat_lines < 0 or logcat_lines > 5000:
        raise ValueError("logcat_lines must be between 0 and 5000")

    collector = AdbCollector(
        adb_path=adb_path,
        serial=serial,
        runner=runner,
    )
    captured_at = datetime.now(timezone.utc).isoformat()
    records: list[CommandResult] = []

    identity_commands = (
        ("model", ["shell", "getprop", "ro.product.model"]),
        ("device", ["shell", "getprop", "ro.product.device"]),
        ("build", ["shell", "getprop", "ro.build.display.id"]),
        ("sdk", ["shell", "getprop", "ro.build.version.sdk"]),
    )
    device: dict[str, str | None] = {}
    for name, argv in identity_commands:
        result = collector.run(f"identity.{name}", argv)
        records.append(result)
        device[name] = _first_nonempty(result)

    core_commands = (
        ("device_policy", ["shell", "dumpsys", "device_policy"]),
        ("package", ["shell", "dumpsys", "package", package]),
        ("processes", ["shell", "ps", "-A"]),
        ("services", ["shell", "dumpsys", "activity", "services", package]),
        ("jobs", ["shell", "dumpsys", "jobscheduler", package]),
        ("alarms", ["shell", "dumpsys", "alarm"]),
        ("appops", ["shell", "appops", "get", package]),
    )
    for name, argv in core_commands:
        records.append(collector.run(name, argv))

    if include_network:
        records.append(collector.run("connectivity", ["shell", "dumpsys", "connectivity"]))

    if logcat_lines:
        pid_result = collector.run("pidof", ["shell", "pidof", package])
        records.append(pid_result)
        pid = _first_nonempty(pid_result)
        if pid and re.fullmatch(r"[0-9]+", pid):
            records.append(collector.run(
                "logcat",
                ["shell", "logcat", f"--pid={pid}", "-d", "-t", str(logcat_lines)],
            ))

    bundle = RuntimeBundle(
        schema="inginv.runtime.v1",
        capture_id=str(uuid.uuid4()),
        captured_at=captured_at,
        package=package,
        device=device,
        records=records,
        privacy={
            "adb_serial_stored": False,
            "raw_secrets_stored": False,
            "network_identifiers_redacted": True,
            "unrelated_full_logcat_collected": False,
            "include_network": include_network,
            "requested_logcat_lines": logcat_lines,
        },
    )
    return {
        **asdict(bundle),
        "records": [asdict(record) for record in records],
    }


def _record_map(bundle: dict) -> dict[str, dict]:
    return {record.get("name", ""): record for record in bundle.get("records", [])}


def derive_runtime_facts(bundle: dict) -> list[dict]:
    package = bundle.get("package")
    records = _record_map(bundle)

    policy = records.get("device_policy", {}).get("stdout", "")
    processes = records.get("processes", {}).get("stdout", "")
    services = records.get("services", {}).get("stdout", "")
    jobs = records.get("jobs", {}).get("stdout", "")

    owner_patterns = (
        f"package={package}",
        f"ComponentInfo{{{package}/",
        f"admin=ComponentInfo{{{package}/",
    )
    owner = bool(package and "Device Owner" in policy and any(p in policy for p in owner_patterns))
    active = bool(package and re.search(rf"(?m)^.*\b{re.escape(str(package))}\b.*$", processes))
    service_active = bool(package and package in services and "ServiceRecord" in services)
    job_registered = bool(package and package in jobs and ("JOB #" in jobs or "SystemJobService" in jobs))

    facts = [
        RuntimeFact(
            "runtime.device_owner",
            "RUNTIME_CONFIRMED" if owner else "UNVERIFIED",
            owner,
            ("device_policy",),
            "Device Owner state does not prove that any destructive policy command was issued.",
        ),
        RuntimeFact(
            "runtime.process_active",
            "RUNTIME_CONFIRMED" if active else "UNVERIFIED",
            active,
            ("processes",),
            "A running process does not prove remote control traffic or command execution.",
        ),
        RuntimeFact(
            "runtime.service_active",
            "RUNTIME_CONFIRMED" if service_active else "UNVERIFIED",
            service_active,
            ("services",),
            "A running service proves persistence/activity, not a particular remote action.",
        ),
        RuntimeFact(
            "runtime.job_registered",
            "RUNTIME_CONFIRMED" if job_registered else "UNVERIFIED",
            job_registered,
            ("jobs",),
            "A registered job proves scheduling infrastructure, not that a remote command ran.",
        ),
    ]
    return [asdict(fact) for fact in facts]


def correlate_static_runtime(
    *,
    runtime_bundle: dict,
    manifest_model: dict | None = None,
    dex_trace: dict | None = None,
) -> dict:
    """Correlate authority/capability without promoting them to observed execution."""
    runtime_facts = derive_runtime_facts(runtime_bundle)
    by_id = {fact["fact_id"]: fact for fact in runtime_facts}
    package = runtime_bundle.get("package")

    correlations: list[dict] = []
    if manifest_model:
        static_package = manifest_model.get("package")
        if static_package and package and static_package == package:
            correlations.append({
                "correlation_id": "package.identity",
                "evidence_state": "CORRELATED",
                "static": {"package": static_package},
                "runtime": {"package": package},
                "does_not_prove": "Package identity correlation does not prove any command was executed.",
            })

    owner = bool(by_id.get("runtime.device_owner", {}).get("value"))
    if owner and dex_trace:
        privileged = sorted({
            path["sink"]
            for item in dex_trace.get("task_execute_paths", [])
            for path in item.get("sink_paths", [])
            if path.get("sink") in {
                "DEVICE_WIPE", "DEVICE_REBOOT", "PACKAGE_INSTALL_COMMIT",
                "RUNTIME_EXEC", "FILE_DELETE",
            }
        })
        if privileged:
            correlations.append({
                "correlation_id": "privileged.capability_and_authority",
                "evidence_state": "CORRELATED",
                "static_privileged_sinks": privileged,
                "runtime_authority": "device_owner",
                "does_not_prove": (
                    "Static privileged code plus live Device Owner authority proves capability and authority, "
                    "not that the server sent or the device executed a specific command."
                ),
            })

    return {
        "schema": "inginv.correlation.v1",
        "package": package,
        "runtime_facts": runtime_facts,
        "correlations": correlations,
        "observed_remote_command_execution": {
            "evidence_state": "UNVERIFIED",
            "value": False,
            "reason": (
                "Inginv requires direct runtime evidence of a specific command execution; "
                "capability, authority, process state and scheduling are insufficient."
            ),
        },
    }


def dump_runtime_json(data: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
