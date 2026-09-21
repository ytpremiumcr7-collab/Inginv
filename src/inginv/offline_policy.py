from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

# Analysis code is intentionally offline. Parsing URL syntax is allowed, but
# transports/resolvers/remote SDKs are not part of the product runtime.
FORBIDDEN_NETWORK_IMPORTS = {
    "socket",
    "http.client",
    "urllib.request",
    "ftplib",
    "telnetlib",
    "requests",
    "httpx",
    "aiohttp",
    "websocket",
    "websockets",
    "paho",
    "firebase_admin",
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
    "mosquitto_pub",
    "mosquitto_sub",
}


@dataclass(frozen=True)
class OfflinePolicyFinding:
    path: str
    line: int
    rule: str
    detail: str


def _root_name(module: str) -> str:
    if module.startswith("http.client"):
        return "http.client"
    if module.startswith("urllib.request"):
        return "urllib.request"
    return module.split(".", 1)[0]


def _literal_command(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value.strip().split()[0] if node.value.strip() else None
    if isinstance(node, (ast.List, ast.Tuple)) and node.elts:
        first = node.elts[0]
        if isinstance(first, ast.Constant) and isinstance(first.value, str):
            return first.value.strip()
    return None


def scan_python_source(path: str, source: str) -> list[OfflinePolicyFinding]:
    tree = ast.parse(source, filename=path)
    findings: list[OfflinePolicyFinding] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = _root_name(alias.name)
                if module in FORBIDDEN_NETWORK_IMPORTS:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "NETWORK_IMPORT", module
                    ))
        elif isinstance(node, ast.ImportFrom) and node.module:
            module = _root_name(node.module)
            if module in FORBIDDEN_NETWORK_IMPORTS:
                findings.append(OfflinePolicyFinding(
                    path, node.lineno, "NETWORK_IMPORT", module
                ))
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {
                "run", "Popen", "check_call", "check_output", "call"
            } and node.args:
                command = _literal_command(node.args[0])
                if command and Path(command).name in FORBIDDEN_NETWORK_EXECUTABLES:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "NETWORK_SUBPROCESS", Path(command).name
                    ))
    return findings


def scan_python_tree(root: str | Path, relative_paths: Iterable[str] | None = None) -> list[OfflinePolicyFinding]:
    base = Path(root)
    paths = [base / p for p in relative_paths] if relative_paths is not None else sorted(base.rglob("*.py"))
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
