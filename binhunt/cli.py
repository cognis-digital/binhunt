"""BINHUNT command-line interface.

Subcommands:
  scan      Fingerprint a binary, detect packers, report entropy/sections.
  baseline  Build a known-good baseline JSON from one or more binaries.
  diff      Compare a binary against a baseline to detect tampering.

Exit codes (for CI gates):
  0  clean / informational only
  2  suspicious or mismatched findings (medium/high/critical)
  1  usage / runtime error
"""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    scan_file,
    build_baseline,
    load_baseline,
    diff_baseline,
    SEVERITY_ORDER,
)

_EXAMPLES = """
examples:
  # Fingerprint + packer/entropy report
  binhunt scan ./client.exe

  # Machine-readable output for CI / piping
  binhunt scan ./client.exe --format json | jq .max_severity

  # Record a known-good baseline, then verify a downloaded copy
  binhunt baseline ./good/client.exe -o baseline.json
  binhunt diff ./downloaded/client.exe --baseline baseline.json
"""


def _print_scan_table(r) -> None:
    print(f"file      : {r.path}")
    print(f"format    : {r.fmt}  ({r.arch})")
    print(f"size      : {r.size} bytes")
    print(f"sha256    : {r.sha256}")
    print(f"md5       : {r.md5}")
    print(f"entropy   : {r.overall_entropy} bits/byte")
    if r.sections:
        print("sections  :")
        print(f"    {'name':<16}{'offset':>10}{'size':>12}{'entropy':>10}")
        for s in r.sections:
            print(f"    {(s['name'] or '<unnamed>'):<16}{s['offset']:>10}"
                  f"{s['size']:>12}{s['entropy']:>10}")
    if r.findings:
        print("findings  :")
        for f in r.findings:
            print(f"    [{f.severity.upper():<8}] {f.id}: {f.title}")
            print(f"             {f.detail}")
    else:
        print("findings  : none")
    print(f"verdict   : {r.max_severity().upper()}")


def _findings_exit(findings) -> int:
    worst = 0
    for f in findings:
        worst = max(worst, SEVERITY_ORDER.get(f.severity, 0))
    return 2 if worst >= SEVERITY_ORDER["medium"] else 0


def _cmd_scan(args) -> int:
    try:
        r = scan_file(args.file)
    except OSError as e:
        print(f"error: cannot read {args.file}: {e}", file=sys.stderr)
        return 1
    if args.format == "json":
        print(json.dumps(r.to_dict(), indent=2))
    else:
        _print_scan_table(r)
    return _findings_exit(r.findings)


def _cmd_baseline(args) -> int:
    try:
        base = build_baseline(args.files)
    except (OSError, ValueError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    text = json.dumps(base, indent=2)
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as e:
            print(f"error: cannot write baseline to {args.output!r}: {e}",
                  file=sys.stderr)
            return 1
        print(f"wrote baseline with {len(base['entries'])} entr"
              f"{'y' if len(base['entries']) == 1 else 'ies'} to {args.output}")
    else:
        print(text)
    return 0


def _cmd_diff(args) -> int:
    try:
        r = scan_file(args.file)
        base = load_baseline(args.baseline)
    except OSError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    except json.JSONDecodeError as e:
        print(f"error: invalid baseline JSON: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    findings = diff_baseline(r, base, key=args.key)
    if args.format == "json":
        print(json.dumps({
            "file": r.path,
            "sha256": r.sha256,
            "findings": [f.to_dict() for f in findings],
            "max_severity": max(
                (f.severity for f in findings),
                key=lambda s: SEVERITY_ORDER.get(s, 0), default="info"),
        }, indent=2))
    else:
        print(f"file   : {r.path}")
        print(f"sha256 : {r.sha256}")
        for f in findings:
            print(f"[{f.severity.upper():<8}] {f.id}: {f.title}")
            print(f"         {f.detail}")
    return _findings_exit(findings)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Binary integrity scanner: fingerprint executables, "
                    "detect packers, diff vs a known-good baseline.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")
    sub = p.add_subparsers(dest="cmd", metavar="<command>")

    sp = sub.add_parser("scan", help="fingerprint + analyze a binary")
    sp.add_argument("file", help="path to the executable")
    sp.set_defaults(func=_cmd_scan)

    bp = sub.add_parser("baseline", help="build a known-good baseline JSON")
    bp.add_argument("files", nargs="+", help="one or more known-good binaries")
    bp.add_argument("-o", "--output", help="write baseline to this file")
    bp.set_defaults(func=_cmd_baseline)

    dp = sub.add_parser("diff", help="compare a binary against a baseline")
    dp.add_argument("file", help="path to the executable under test")
    dp.add_argument("--baseline", required=True, help="baseline JSON file")
    dp.add_argument("--key", default=None,
                    help="baseline entry name (default: basename of file)")
    dp.set_defaults(func=_cmd_diff)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return 1
    except Exception as e:  # pragma: no cover
        print(f"error: unexpected failure: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
