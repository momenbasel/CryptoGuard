"""AI Agent pre-transaction hook.

This module intercepts bash commands from AI agents (Claude Code, Codex, etc.)
before execution. If a crypto transaction is detected, it runs a full security
analysis and blocks dangerous transactions.

Hook protocol (Claude Code):
  - stdin:  JSON with {"tool_name": "...", "tool_input": {"command": "..."}}
  - exit 0: Allow the command to proceed
  - exit 2: Block the command (stderr message shown to user/agent)

Usage in Claude Code settings.json:
  {
    "hooks": {
      "PreToolUse": [{
        "matcher": "Bash",
        "hook": "python -m cryptoguard.hook"
      }]
    }
  }
"""

from __future__ import annotations

import json
import os
import re
import sys

from .analyzer import analyze
from .constants import READONLY_KEYWORDS, TX_KEYWORDS
from .report import format_hook_message

# Ethereum address pattern: 0x followed by 40 hex chars
ETH_ADDRESS_RE = re.compile(r"0x[a-fA-F0-9]{40}")

# Environment variable to disable the hook temporarily
DISABLE_ENV = "CRYPTOGUARD_DISABLE"

# Environment variable to set default chain
CHAIN_ENV = "CRYPTOGUARD_CHAIN"

# Environment variable to set risk threshold for blocking
# Values: CRITICAL, HIGH, MEDIUM (default: HIGH)
THRESHOLD_ENV = "CRYPTOGUARD_THRESHOLD"


def extract_addresses(text: str) -> list[str]:
    """Extract all Ethereum-style addresses from text.

    Deduplicates and validates basic format (0x + 40 hex chars).
    Excludes common false positives like zero address and known system addresses.
    """
    matches = ETH_ADDRESS_RE.findall(text)
    # Deduplicate while preserving order
    seen = set()
    unique = []
    for addr in matches:
        lower = addr.lower()
        if lower not in seen:
            seen.add(lower)
            unique.append(addr)

    # Filter out known non-token addresses
    EXCLUDED = {
        "0x0000000000000000000000000000000000000000",  # zero address
        "0x0000000000000000000000000000000000000001",  # ecrecover precompile
        "0x0000000000000000000000000000000000000002",
        "0x0000000000000000000000000000000000000003",
        "0x0000000000000000000000000000000000000004",
        "0x0000000000000000000000000000000000000005",
        "0x0000000000000000000000000000000000000006",
        "0x0000000000000000000000000000000000000007",
        "0x0000000000000000000000000000000000000008",
        "0x0000000000000000000000000000000000000009",
        "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",  # native token placeholder
        "0xffffffffffffffffffffffffffffffffffffffff",
        "0x000000000000000000000000000000000000dead",  # burn address
    }

    return [a for a in unique if a.lower() not in EXCLUDED]


def is_transaction_command(command: str) -> bool:
    """Determine if a bash command appears to be a crypto transaction.

    Returns True if the command contains transaction-related keywords
    AND is not purely a read-only call.
    """
    cmd_lower = command.lower()

    # Check for read-only patterns first (these are safe)
    for kw in READONLY_KEYWORDS:
        if kw.lower() in cmd_lower:
            # If it's ONLY a read, skip
            has_tx_kw = any(tk.lower() in cmd_lower for tk in TX_KEYWORDS)
            if not has_tx_kw:
                return False

    # Check for transaction keywords
    for kw in TX_KEYWORDS:
        if kw.lower() in cmd_lower:
            return True

    return False


def detect_chain(command: str) -> str:
    """Attempt to detect the target chain from the command.

    Looks for chain flags, RPC URLs, and chain-specific tool invocations.
    Falls back to CRYPTOGUARD_CHAIN env var, then 'ethereum'.
    """
    cmd_lower = command.lower()

    # Foundry --rpc-url patterns
    chain_patterns = {
        "bsc": ["bsc", "binance", "bnb", "56"],
        "polygon": ["polygon", "matic", "137"],
        "arbitrum": ["arbitrum", "arb", "42161"],
        "base": ["base-mainnet", "base.org", "8453"],
        "optimism": ["optimism", "op-mainnet", "10"],
        "avalanche": ["avalanche", "avax", "43114"],
        "fantom": ["fantom", "ftm", "250"],
        "ethereum": ["ethereum", "eth-mainnet", "mainnet"],
    }

    for chain_name, patterns in chain_patterns.items():
        for pattern in patterns:
            if pattern in cmd_lower:
                return chain_name

    # Environment variable fallback
    return os.environ.get(CHAIN_ENV, "ethereum")


def get_block_threshold() -> str:
    """Get the risk level threshold for blocking transactions.

    Transactions at or above this level will be blocked.
    Default: HIGH (blocks HIGH and CRITICAL).
    """
    threshold = os.environ.get(THRESHOLD_ENV, "HIGH").upper()
    if threshold not in ("CRITICAL", "HIGH", "MEDIUM"):
        return "HIGH"
    return threshold


def run_hook() -> None:
    """Main hook entry point. Read stdin, analyze, decide.

    Exit codes:
      0 - Allow (no crypto transaction detected, or risk is acceptable)
      2 - Block (dangerous transaction detected)
    """
    # Check if disabled
    if os.environ.get(DISABLE_ENV, "").lower() in ("1", "true", "yes"):
        sys.exit(0)

    # Read tool input from stdin
    try:
        raw = sys.stdin.read()
        if not raw.strip():
            sys.exit(0)
        data = json.loads(raw)
    except (json.JSONDecodeError, IOError):
        # Can't parse input - don't block
        sys.exit(0)

    # Extract the command
    tool_name = data.get("tool_name", "")
    tool_input = data.get("tool_input", {})

    # Only analyze Bash commands
    if tool_name != "Bash":
        sys.exit(0)

    command = tool_input.get("command", "")
    if not command:
        sys.exit(0)

    # Check if this looks like a crypto transaction
    if not is_transaction_command(command):
        sys.exit(0)

    # Extract target addresses
    addresses = extract_addresses(command)
    if not addresses:
        sys.exit(0)

    # Detect target chain
    chain = detect_chain(command)

    # Analyze each address (usually there's 1-2 contract addresses)
    threshold = get_block_threshold()
    threshold_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1}
    threshold_val = threshold_order.get(threshold, 2)

    should_block = False
    messages = []

    for addr in addresses[:3]:  # Limit to 3 addresses to avoid excessive API calls
        try:
            result = analyze(addr, chain)
        except Exception as exc:
            # Analysis failed - warn but don't block
            msg = f"CryptoGuard: Analysis failed for {addr}: {exc}"
            print(msg, file=sys.stderr)
            continue

        level_order = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0, "SAFE": 0}
        result_level = level_order.get(result.risk_level.value, 0)

        if result_level >= threshold_val:
            should_block = True

        # Always show the report for non-SAFE results
        if result.risk_level.value != "SAFE":
            messages.append(format_hook_message(result))

    # Output and exit
    if messages:
        print("\n".join(messages), file=sys.stderr)

    if should_block:
        sys.exit(2)  # Block the transaction
    else:
        sys.exit(0)  # Allow


if __name__ == "__main__":
    run_hook()
