"""Bytecode scanner for dangerous contract patterns.

Performs on-chain bytecode analysis independent of GoPlus to detect:
  - Blacklist / freeze functions
  - Self-destruct capability
  - Proxy / delegatecall patterns
  - Dangerous admin selectors
  - Known scam bytecode signatures
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any

import requests

from .constants import (
    CHAINS,
    CHAIN_ALIASES,
    DANGEROUS_OPCODES,
    DANGEROUS_SELECTORS,
)

logger = logging.getLogger(__name__)

_TIMEOUT = 10


@dataclass
class BytecodeFinding:
    """A single finding from bytecode analysis."""

    title: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # blacklist, pause, ownership, mint, etc.
    selector: str = ""  # hex selector if applicable


@dataclass
class ScanResult:
    """Aggregated bytecode scan results."""

    address: str
    chain: str
    bytecode_length: int = 0
    is_contract: bool = False
    has_bytecode: bool = False
    findings: list[BytecodeFinding] = field(default_factory=list)
    matched_selectors: list[dict] = field(default_factory=list)
    raw_bytecode: str = ""

    @property
    def has_blacklist(self) -> bool:
        return any(f.category == "blacklist" for f in self.findings)

    @property
    def has_selfdestruct(self) -> bool:
        return any(f.category == "selfdestruct" for f in self.findings)

    @property
    def has_pause(self) -> bool:
        return any(f.category == "pause" for f in self.findings)

    @property
    def max_severity(self) -> str:
        order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        if not self.findings:
            return "INFO"
        return max(self.findings, key=lambda f: order.get(f.severity, 0)).severity


def _resolve_rpc(chain: str) -> str:
    """Resolve chain name to RPC URL."""
    chain = chain.lower().strip()
    if chain in CHAIN_ALIASES:
        chain = CHAIN_ALIASES[chain]
    if chain not in CHAINS:
        raise ValueError(f"Unsupported chain: {chain!r}")
    return CHAINS[chain]["rpc"]


def fetch_bytecode(address: str, chain: str) -> str:
    """Fetch contract bytecode via JSON-RPC eth_getCode."""
    rpc_url = _resolve_rpc(chain)
    address = address.strip()

    # Ensure proper checksum format
    if not address.startswith("0x"):
        address = f"0x{address}"

    payload = {
        "jsonrpc": "2.0",
        "method": "eth_getCode",
        "params": [address, "latest"],
        "id": 1,
    }

    try:
        resp = requests.post(rpc_url, json=payload, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("RPC eth_getCode failed for %s: %s", address, exc)
        return "0x"

    result = data.get("result", "0x")
    return result if result else "0x"


def scan_bytecode(address: str, chain: str) -> ScanResult:
    """Perform comprehensive bytecode analysis on a contract.

    Steps:
      1. Fetch bytecode from on-chain RPC
      2. Check if address is a contract (has bytecode)
      3. Scan for dangerous function selectors
      4. Scan for dangerous opcodes (SELFDESTRUCT, DELEGATECALL)
      5. Check for common scam patterns
    """
    result = ScanResult(address=address, chain=chain)

    bytecode = fetch_bytecode(address, chain)
    result.raw_bytecode = bytecode

    # Strip 0x prefix for analysis
    code = bytecode[2:] if bytecode.startswith("0x") else bytecode
    result.bytecode_length = len(code) // 2  # bytes
    result.is_contract = len(code) > 2
    result.has_bytecode = len(code) > 2

    if not result.is_contract:
        result.findings.append(BytecodeFinding(
            title="Not a contract",
            description="Address has no bytecode - this is an EOA (wallet), not a contract",
            severity="INFO",
            category="general",
        ))
        return result

    # --- Scan for dangerous function selectors ---
    _scan_selectors(code, result)

    # --- Scan for dangerous opcodes ---
    _scan_opcodes(code, result)

    # --- Check for suspiciously small bytecode (potential proxy/minimal) ---
    if result.bytecode_length < 100:
        result.findings.append(BytecodeFinding(
            title="Minimal bytecode",
            description=(
                f"Contract has only {result.bytecode_length} bytes of code. "
                "This may be a minimal proxy or a suspiciously simple contract."
            ),
            severity="MEDIUM",
            category="proxy",
        ))

    # --- Check for known scam patterns ---
    _scan_scam_patterns(code, result)

    return result


def _scan_selectors(code: str, result: ScanResult) -> None:
    """Search bytecode for known dangerous function selectors.

    Function selectors appear in bytecode as PUSH4 instructions followed
    by the 4-byte selector for comparison in the function dispatcher.
    The PUSH4 opcode is 0x63.
    """
    code_lower = code.lower()

    for selector_hex, info in DANGEROUS_SELECTORS.items():
        # Look for the selector in bytecode (it appears as-is for PUSH4 matching)
        if selector_hex.lower() in code_lower:
            # Skip standard/info-level selectors from detailed findings
            if info["severity"] == "INFO":
                continue

            finding = BytecodeFinding(
                title=f"Dangerous function detected: {info['name']}",
                description=(
                    f"Bytecode contains selector 0x{selector_hex} "
                    f"matching {info['name']}. "
                    f"Risk category: {info['risk']}"
                ),
                severity=info["severity"],
                category=info["risk"],
                selector=selector_hex,
            )
            result.findings.append(finding)
            result.matched_selectors.append({
                "selector": selector_hex,
                "name": info["name"],
                "risk": info["risk"],
                "severity": info["severity"],
            })


def _scan_opcodes(code: str, result: ScanResult) -> None:
    """Scan for dangerous EVM opcodes in bytecode.

    Note: We check for the opcode bytes, but must be careful about false
    positives since these bytes can appear as data/arguments too.
    SELFDESTRUCT (0xff) is particularly significant when found.
    """
    code_lower = code.lower()
    code_bytes = bytes.fromhex(code_lower) if len(code_lower) % 2 == 0 else b""

    if not code_bytes:
        return

    # SELFDESTRUCT (0xff) - scan through opcodes properly
    # We do a simplified check: if 0xff appears in the bytecode,
    # it COULD be SELFDESTRUCT but also could be PUSH data.
    # We flag it as a potential risk.
    if b"\xff" in code_bytes:
        # Count occurrences - multiple hits increase confidence
        count = code_bytes.count(b"\xff")
        # SELFDESTRUCT is typically near the end of a code path
        # Check if any 0xff is NOT preceded by a PUSH instruction
        # This is a heuristic - proper disassembly would be more accurate
        if count <= 5:  # Low count = more likely to be actual opcode
            result.findings.append(BytecodeFinding(
                title="Potential SELFDESTRUCT opcode",
                description=(
                    "Bytecode may contain SELFDESTRUCT (0xff). If confirmed, "
                    "the contract owner could destroy the contract and drain "
                    "all native tokens. Found in bytecode analysis."
                ),
                severity="HIGH",
                category="selfdestruct",
            ))

    # DELEGATECALL (0xf4) - common in proxy patterns
    if b"\xf4" in code_bytes:
        result.findings.append(BytecodeFinding(
            title="DELEGATECALL detected",
            description=(
                "Contract uses DELEGATECALL, indicating a proxy pattern. "
                "The implementation contract could be upgraded to include "
                "malicious logic without changing the proxy address."
            ),
            severity="MEDIUM",
            category="proxy",
        ))


def _scan_scam_patterns(code: str, result: ScanResult) -> None:
    """Detect known scam contract bytecode patterns.

    These are patterns commonly found in rug pull / honeypot contracts.
    """
    code_lower = code.lower()

    # Pattern: Extremely large number of external calls (code contains
    # many CALL opcodes) - can indicate a contract that calls out to
    # attacker-controlled contracts
    call_count = code_lower.count("f1")  # CALL opcode
    if call_count > 50:
        result.findings.append(BytecodeFinding(
            title="Excessive external calls",
            description=(
                f"Contract has ~{call_count} potential CALL opcodes. "
                "Excessive external calls may indicate complex interaction "
                "patterns that could be used to manipulate token behavior."
            ),
            severity="LOW",
            category="complexity",
        ))

    # Pattern: Contract stores to many different storage slots
    # (SSTORE = 0x55) - extremely high count could indicate
    # hidden state manipulation
    sstore_count = code_lower.count("55")
    if sstore_count > 100:
        result.findings.append(BytecodeFinding(
            title="High storage write complexity",
            description=(
                f"Contract has ~{sstore_count} potential SSTORE operations. "
                "This level of storage complexity is unusual for standard tokens."
            ),
            severity="LOW",
            category="complexity",
        ))
