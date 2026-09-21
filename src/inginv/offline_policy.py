from __future__ import annotations

import ast
from dataclasses import asdict, dataclass
from pathlib import Path
import re
from typing import Iterable


# Inginv analysis code is intentionally offline. URL parsing is allowed, but
# transports, resolvers and remote-service SDKs are not part of product runtime.
FORBIDDEN_NETWORK_IMPORTS = {
    "socket",
    "http.client",
    "urllib.request",
    "urllib3",
    "ftplib",
    "telnetlib",
    "requests",
    "httpx",
    "httpcore",
    "aiohttp",
    "websocket",
    "websockets",
    "paho",
    "firebase_admin",
    "grpc",
    "dns",
    "paramiko",
}

FORBIDDEN_NETWORK_EXECUTABLES = {
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "telnet",
    "ping",
    "dig",
    "nslookup",
    "host",
    "ssh",
    "scp",
    "sftp",
    "mosquitto_pub",
    "mosquitto_sub",
}

_SUBPROCESS_CALLS = {"run", "Popen", "check_call", "check_output", "call"}


@dataclass(frozen=True)
class OfflinePolicyFinding:
    path: str
    line: int
    rule: str
    detail: str


def _module_name(module: str) -> str:
    if module.startswith("http.client"):
        return "http.client"
    if module.startswith("urllib.request"):
        return "urllib.request"
    return module.split(".", 1)[0]


def _literal_command_parts(node: ast.AST) -> list[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return re.findall(r"[A-Za-z0-9_.-]+", node.value)
    if isinstance(node, (ast.List, ast.Tuple)):
        result: list[str] = []
        for item in node.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                result.extend(re.findall(r"[A-Za-z0-9_.-]+", item.value))
        return result
    return []


def scan_python_source(path: str, source: str) -> list[OfflinePolicyFinding]:
    tree = ast.parse(source, filename=path)
    findings: list[OfflinePolicyFinding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = _module_name(alias.name)
                if module in FORBIDDEN_NETWORK_IMPORTS:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "NETWORK_IMPORT", module
                    ))
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = _module_name(node.module)
            if module in FORBIDDEN_NETWORK_IMPORTS:
                findings.append(OfflinePolicyFinding(
                    path, node.lineno, "NETWORK_IMPORT", module
                ))
        elif isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr in _SUBPROCESS_CALLS
                and node.args
            ):
                parts = _literal_command_parts(node.args[0])
                lowered = {Path(part).name.lower() for part in parts}
                blocked = sorted(lowered & FORBIDDEN_NETWORK_EXECUTABLES)
                for executable in blocked:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "NETWORK_SUBPROCESS", executable
                    ))

    return findings


def scan_python_tree(
    root: str | Path,
    relative_paths: Iterable[str] | None = None,
) -> list[OfflinePolicyFinding]:
    base = Path(root)
    paths = (
        [base / path for path in relative_paths]
        if relative_paths is not None
        else sorted(base.rglob("*.py"))
    )
    findings: list[OfflinePolicyFinding] = []
    for path in paths:
        if not path.is_file() or path.suffix != ".py":
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_python_source(str(path.relative_to(base)), source))
    return findings


def scan_repository_source(root: str | Path) -> dict:
    repo = Path(root).resolve()
    source_root = repo / "src"
    if not source_root.is_dir():
        raise FileNotFoundError(f"source directory not found: {source_root}")
    findings = scan_python_tree(source_root)
    return {
        "root": repo.name,
        "policy": "offline-only-analysis",
        "finding_count": len(findings),
        "findings": [asdict(finding) for finding in findings],
    }
