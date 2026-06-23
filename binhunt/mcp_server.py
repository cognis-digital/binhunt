"""BINHUNT MCP server — exposes the scanner as MCP tools for Cognis.Studio.

Passive/offline only: every tool reads local files. No network calls.
Requires the optional 'mcp' extra:  pip install "cognis-binhunt[mcp]"
"""
from __future__ import annotations

import json

from binhunt.core import (
    scan_file,
    build_baseline,
    load_baseline,
    diff_baseline,
    to_json,
)


def serve() -> int:
    """Start an MCP stdio server exposing scan / baseline / diff."""
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-binhunt[mcp]'")
        return 1
    app = FastMCP("binhunt")

    @app.tool()
    def binhunt_scan(path: str) -> str:
        """Fingerprint a local executable (format/arch/hashes/entropy/sections),
        detect packers/obfuscators, and return findings as JSON."""
        return to_json(scan_file(path))

    @app.tool()
    def binhunt_baseline(paths: list[str]) -> str:
        """Build a known-good baseline JSON from one or more local binaries."""
        return json.dumps(build_baseline(paths), indent=2)

    @app.tool()
    def binhunt_diff(path: str, baseline_path: str) -> str:
        """Diff a local binary against a baseline JSON file; return tamper
        findings as JSON."""
        r = scan_file(path)
        base = load_baseline(baseline_path)
        findings = diff_baseline(r, base)
        return json.dumps({
            "file": r.path,
            "sha256": r.sha256,
            "findings": [f.to_dict() for f in findings],
        }, indent=2)

    app.run()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(serve())
