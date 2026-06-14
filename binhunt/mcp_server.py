"""BINHUNT MCP server — exposes scan_file() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
import json
import sys

from binhunt.core import scan_file


def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-binhunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-binhunt[mcp]'",
              file=sys.stderr)
        return 1
    app = FastMCP("binhunt")

    @app.tool()
    def binhunt_scan(target: str) -> str:
        """Binary integrity scanner: fingerprint executables, detect packers/
        obfuscators, and diff against a known-good baseline to catch tampering.
        Returns JSON findings.
        """
        try:
            result = scan_file(target)
        except (OSError, ValueError) as exc:
            return json.dumps({"error": str(exc)})
        return json.dumps(result.to_dict())

    app.run()
    return 0
