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
_OS_SHELL_CALLS = {"system", "popen"}
_ASYNCIO_SUBPROCESS_CALLS = {"create_subprocess_exec", "create_subprocess_shell"}
_DYNAMIC_IMPORT_CALLS = {"import_module"}


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

    module_aliases: dict[str, str] = {}
    imported_call_aliases: dict[str, tuple[str, str]] = {}

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                module = _module_name(alias.name)
                local_name = alias.asname or alias.name.split(".", 1)[0]
                module_aliases[local_name] = module
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
            for alias in node.names:
                imported_call_aliases[alias.asname or alias.name] = (module, alias.name)

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func

        # Catch constant-string dynamic imports of network transports/resolvers.
        if isinstance(func, ast.Name) and func.id == "__import__" and node.args:
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                module = _module_name(arg.value)
                if module in FORBIDDEN_NETWORK_IMPORTS:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "DYNAMIC_NETWORK_IMPORT", module
                    ))
        elif (
            isinstance(func, ast.Attribute)
            and func.attr in _DYNAMIC_IMPORT_CALLS
            and isinstance(func.value, ast.Name)
            and module_aliases.get(func.value.id) == "importlib"
            and node.args
        ):
            arg = node.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                module = _module_name(arg.value)
                if module in FORBIDDEN_NETWORK_IMPORTS:
                    findings.append(OfflinePolicyFinding(
                        path, node.lineno, "DYNAMIC_NETWORK_IMPORT", module
                    ))

        if not node.args:
            continue

        command_node: ast.AST | None = None
        if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
            module = module_aliases.get(func.value.id)
            if module == "subprocess" and func.attr in _SUBPROCESS_CALLS:
                command_node = node.args[0]
            elif module == "os" and func.attr in _OS_SHELL_CALLS:
                command_node = node.args[0]
            elif module == "asyncio" and func.attr in _ASYNCIO_SUBPROCESS_CALLS:
                command_node = node.args[0]
        elif isinstance(func, ast.Name):
            imported = imported_call_aliases.get(func.id)
            if imported:
                module, name = imported
                if (
                    (module == "subprocess" and name in _SUBPROCESS_CALLS)
                    or (module == "os" and name in _OS_SHELL_CALLS)
                    or (module == "asyncio" and name in _ASYNCIO_SUBPROCESS_CALLS)
                ):
                    command_node = node.args[0]

        if command_node is None:
            continue

        parts = _literal_command_parts(command_node)
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
