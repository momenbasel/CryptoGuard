"""Minimal MCP (Model Context Protocol) server for CryptoGuard.

Exposes CryptoGuard analysis as an MCP tool that any compatible
AI agent or IDE can call.

Tools exposed:
  - cryptoguard_check: Analyze a token contract for security risks
"""

from __future__ import annotations

import json
import sys

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent
    HAS_MCP = True
except ImportError:
    HAS_MCP = False

from .analyzer import analyze


def _build_check_tool() -> dict:
    """Build the MCP tool definition for contract checking."""
    return {
        "name": "cryptoguard_check",
        "description": (
            "Analyze a smart contract/token for security risks before interacting with it. "
            "Checks for honeypots, blacklists, rug pull indicators, dangerous tax rates, "
            "and other scam patterns. Queries GoPlus, Honeypot.is, TokenSniffer, De.Fi, "
            "and performs bytecode analysis. Returns risk score (0-100) and detailed findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "address": {
                    "type": "string",
                    "description": "Contract address to analyze (0x...)",
                },
                "chain": {
                    "type": "string",
                    "description": "Blockchain name (ethereum, bsc, polygon, arbitrum, base, optimism, avalanche, fantom, zksync, linea, scroll)",
                    "default": "ethereum",
                },
            },
            "required": ["address"],
        },
    }


async def _handle_check(arguments: dict) -> str:
    """Handle cryptoguard_check tool call."""
    address = arguments.get("address", "")
    chain = arguments.get("chain", "ethereum")

    if not address:
        return json.dumps({"error": "address is required"})

    try:
        result = analyze(address, chain)
        output = result.to_dict()

        # Add human-readable summary
        level = result.risk_level.value
        summary_lines = [
            f"Risk Level: {level} (Score: {result.risk_score}/100)",
            f"Token: {result.token_info.name} ({result.token_info.symbol})",
            "",
        ]

        if result.should_block:
            summary_lines.append("WARNING: This token is DANGEROUS. Do NOT proceed with the transaction.")
            summary_lines.append("")

        if result.critical_findings:
            summary_lines.append("CRITICAL FINDINGS:")
            for f in result.critical_findings:
                summary_lines.append(f"  - {f.title}: {f.description}")
            summary_lines.append("")

        if result.high_findings:
            summary_lines.append("HIGH RISK FINDINGS:")
            for f in result.high_findings:
                summary_lines.append(f"  - {f.title}: {f.description}")

        output["summary"] = "\n".join(summary_lines)
        return json.dumps(output, indent=2)

    except Exception as exc:
        return json.dumps({"error": str(exc)})


def start_server(host: str = "127.0.0.1", port: int = 3847) -> None:
    """Start the MCP server."""
    if not HAS_MCP:
        print(
            "MCP SDK not installed. Install with: pip install mcp",
            file=sys.stderr,
        )
        sys.exit(1)

    import asyncio

    server = Server("cryptoguard")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        tool_def = _build_check_tool()
        return [Tool(**tool_def)]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        if name == "cryptoguard_check":
            result_text = await _handle_check(arguments)
            return [TextContent(type="text", text=result_text)]
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    async def run():
        async with stdio_server() as (read, write):
            await server.run(read, write, server.create_initialization_options())

    asyncio.run(run())


# --- Fallback: simple JSON-RPC over stdio for agents without MCP ---

def start_simple_server() -> None:
    """Minimal JSON-RPC stdio server for environments without MCP SDK.

    Reads JSON-RPC requests from stdin, writes responses to stdout.
    This allows any agent to use CryptoGuard without the MCP dependency.
    """
    import sys

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            method = req.get("method", "")
            params = req.get("params", {})
            req_id = req.get("id", 1)

            if method == "check":
                address = params.get("address", "")
                chain = params.get("chain", "ethereum")
                result = analyze(address, chain)
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": result.to_dict(),
                }
            elif method == "ping":
                response = {"jsonrpc": "2.0", "id": req_id, "result": "pong"}
            else:
                response = {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Unknown method: {method}"},
                }

            print(json.dumps(response), flush=True)

        except Exception as exc:
            err_resp = {
                "jsonrpc": "2.0",
                "id": 0,
                "error": {"code": -32000, "message": str(exc)},
            }
            print(json.dumps(err_resp), flush=True)
