from __future__ import annotations

import argparse
import json
from pathlib import Path

from .apk import dump_json, extract_strings, summarize
from .axml import manifest_matrix, write_component_csv
from .dex import trace_apk
from .repo_guard import dump_guard_json, scan_repository
from .runtime import collect_runtime, correlate_static_runtime, dump_runtime_json


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
        runtime_bundle = json.loads(args.runtime_json.read_text(encoding="utf-8"))
        manifest_model = (
            json.loads(args.manifest_json.read_text(encoding="utf-8"))
            if args.manifest_json else None
        )
        dex_trace = (
            json.loads(args.dex_json.read_text(encoding="utf-8"))
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
    if args.command == "repo-guard":
        report = scan_repository(args.root, history=args.history)
        if args.output:
            dump_guard_json(report, args.output)
            print(f"wrote {args.output}")
        else:
            print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["finding_count"] else 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
