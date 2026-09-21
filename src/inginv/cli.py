from __future__ import annotations

import argparse
import json
from pathlib import Path

from .apk import dump_json, extract_strings, summarize
from .axml import manifest_matrix, write_component_csv
from .dex import trace_apk
from .evidence import build_report, dump_report_json, dump_report_markdown, findings_from_analysis
from .offline_policy import scan_repository_source
from .repo_guard import dump_guard_json, scan_repository
from .runtime import collect_runtime, correlate_static_runtime, dump_runtime_json

REPORT_INPUT_MAX_BYTES = 64 * 1024 * 1024


def _read_json_object(path: Path, *, max_bytes: int = REPORT_INPUT_MAX_BYTES) -> dict:
    if max_bytes < 1:
        raise ValueError("max_bytes must be positive")
    size = path.stat().st_size
    if size > max_bytes:
        raise ValueError(f"analysis JSON exceeds size budget: {size} > {max_bytes}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"analysis JSON must contain an object: {path.name}")
    return value


def _write_or_print(data: dict, output: str | None) -> None:
    if output:
        dump_json(data, output)
        print(f"wrote {output}")
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def _descriptor_prefix(value: str) -> str:
    if value.startswith("L"):
        return value
    return "L" + value.replace(".", "/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inginv")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("apk-summary", help="Inventory an APK and verify ZIP integrity")
    summary.add_argument("apk", type=Path)
    summary.add_argument("--json", dest="output")

    strings = sub.add_parser("apk-strings", help="Extract sanitized endpoints and high-value string indicators")
    strings.add_argument("apk", type=Path)
    strings.add_argument("--json", dest="output")

    manifest = sub.add_parser("manifest-matrix", help="Decode AndroidManifest.xml and emit component/permission model")
    manifest.add_argument("apk", type=Path)
    manifest.add_argument("--json", dest="output")
    manifest.add_argument("--csv", dest="csv_output")

    dex = sub.add_parser("dex-trace", help="Trace command const-strings through DEX invoke edges to privileged sinks")
    dex.add_argument("apk", type=Path)
    dex.add_argument("--first-party-prefix", action="append", default=[])
    dex.add_argument("--max-depth", type=int, default=12)
    dex.add_argument("--json", dest="output")

    runtime = sub.add_parser("runtime-collect", help="Collect bounded read-only ADB evidence with privacy redaction")
    runtime.add_argument("package")
    runtime.add_argument("--adb", default="adb")
    runtime.add_argument("--serial")
    runtime.add_argument("--include-network", action="store_true")
    runtime.add_argument("--logcat-lines", type=int, default=0)
    runtime.add_argument("--json", dest="output")

    correlate = sub.add_parser("correlate", help="Correlate sanitized runtime evidence with static manifest/DEX reports")
    correlate.add_argument("runtime_json", type=Path)
    correlate.add_argument("--manifest-json", type=Path)
    correlate.add_argument("--dex-json", type=Path)
    correlate.add_argument("--json", dest="output")

    report = sub.add_parser("report", help="Generate provenance-aware sanitized findings from analysis JSON")
    report.add_argument("--manifest-json", type=Path)
    report.add_argument("--dex-json", type=Path)
    report.add_argument("--correlation-json", type=Path)
    report.add_argument("--json", dest="output")
    report.add_argument("--markdown", dest="markdown_output")

    offline = sub.add_parser(
        "offline-guard",
        help="Fail if production source can initiate direct network/provider access",
    )
    offline.add_argument("root", nargs="?", default=".", type=Path)

    guard = sub.add_parser("repo-guard", help="Scan tracked files and optional Git history for secrets/private evidence")
    guard.add_argument("root", nargs="?", default=".", type=Path)
    guard.add_argument("--history", action="store_true")
    guard.add_argument("--json", dest="output")

    args = parser.parse_args(argv)
    if args.command == "apk-summary":
        _write_or_print(summarize(args.apk), args.output)
        return 0
    if args.command == "apk-strings":
        _write_or_print(extract_strings(args.apk), args.output)
        return 0
    if args.command == "manifest-matrix":
        model = manifest_matrix(args.apk)
        _write_or_print(model, args.output)
        if args.csv_output:
            write_component_csv(model, args.csv_output)
            print(f"wrote {args.csv_output}")
        return 0
    if args.command == "dex-trace":
        prefixes = tuple(_descriptor_prefix(p) for p in args.first_party_prefix)
        _write_or_print(
            trace_apk(args.apk, first_party_prefixes=prefixes, max_depth=args.max_depth),
            args.output,
        )
        return 0
    if args.command == "runtime-collect":
        bundle = collect_runtime(
            args.package,
            adb_path=args.adb,
            serial=args.serial,
            include_network=args.include_network,
            logcat_lines=args.logcat_lines,
        )
        if args.output:
            dump_runtime_json(bundle, args.output)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(bundle, indent=2, sort_keys=True))
        return 0
    if args.command == "correlate":
        runtime_bundle = _read_json_object(args.runtime_json)
        manifest_model = (
            _read_json_object(args.manifest_json)
            if args.manifest_json else None
        )
        dex_trace = (
            _read_json_object(args.dex_json)
            if args.dex_json else None
        )
        report = correlate_static_runtime(
            runtime_bundle=runtime_bundle,
            manifest_model=manifest_model,
            dex_trace=dex_trace,
        )
        if args.output:
            dump_runtime_json(report, args.output)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 0
    if args.command == "report":
        if not any((args.manifest_json, args.dex_json, args.correlation_json)):
            parser.error("report requires at least one analysis JSON input")
        manifest_model = (
            _read_json_object(args.manifest_json)
            if args.manifest_json else None
        )
        dex_trace = (
            _read_json_object(args.dex_json)
            if args.dex_json else None
        )
        correlation = (
            _read_json_object(args.correlation_json)
            if args.correlation_json else None
        )
        findings = findings_from_analysis(
            manifest_model=manifest_model,
            dex_trace=dex_trace,
            correlation=correlation,
        )
        report_data = build_report(
            findings,
            metadata={
                "inputs": {
                    "manifest": bool(args.manifest_json),
                    "dex": bool(args.dex_json),
                    "correlation": bool(args.correlation_json),
                }
            },
        )
        if args.output:
            dump_report_json(report_data, args.output)
            print(f"wrote {args.output}")
        if args.markdown_output:
            dump_report_markdown(report_data, args.markdown_output)
            print(f"wrote {args.markdown_output}")
        if not args.output and not args.markdown_output:
            print(json.dumps(report_data, indent=2, sort_keys=True))
        return 0
    if args.command == "offline-guard":
        report = scan_repository_source(args.root)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["finding_count"] else 0
    if args.command == "repo-guard":
        report = scan_repository(args.root, history=args.history)
        if args.output:
            dump_guard_json(report, args.output)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report.get("blocking_count", report["finding_count"]) else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
