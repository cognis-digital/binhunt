"""BINHUNT MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from binhunt.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-binhunt[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-binhunt[mcp]'")
        return 1
    app = FastMCP("binhunt")

    @app.tool()
    def binhunt_scan(target: str) -> str:
        """Game/desktop binary integrity scanner that fingerprints executables, detects common packers/obfuscators, and diffs against a known-good baseline to catch tampering.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
