from __future__ import annotations

import argparse
import json
from pathlib import Path

from .apk import dump_json, extract_strings, summarize
from .repo_guard import dump_guard_json, scan_repository


def _write_or_print(data: dict, output: str | None) -> None:
    if output:
        dump_json(data, output)
        print(f"wrote {output}")
    else:
        print(json.dumps(data, indent=2, sort_keys=True))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="inginv")
    sub = parser.add_subparsers(dest="command", required=True)

    summary = sub.add_parser("apk-summary", help="Inventory an APK and verify ZIP integrity")
    summary.add_argument("apk", type=Path)
    summary.add_argument("--json", dest="output")

    strings = sub.add_parser("apk-strings", help="Extract sanitized endpoints and high-value string indicators")
    strings.add_argument("apk", type=Path)
    strings.add_argument("--json", dest="output")

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
