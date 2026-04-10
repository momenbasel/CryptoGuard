"""Core analysis engine - orchestrates all checks and computes risk scores.

The analyzer is the brain of CryptoGuard. It:
  1. Fetches GoPlus security data
  2. Runs bytecode scanning
  3. Queries reputation sources (honeypot.is, TokenSniffer, De.Fi, QuickIntel)
  4. Analyzes holder distribution
  5. Evaluates liquidity safety
  6. Computes an aggregate risk score with weighted findings
  7. Returns a structured AnalysisResult
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .constants import RISK_THRESHOLDS, RISK_WEIGHTS
from .goplus import get_token_security, parse_goplus_flags
from .reputation import check_reputation, ReputationReport
from .scanner import scan_bytecode, ScanResult

logger = logging.getLogger(__name__)


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def weight(self) -> int:
        return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}[self.value]


class RiskLevel(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"


@dataclass
class Finding:
    """A single security finding."""

    severity: Severity
    title: str
    description: str
    category: str  # blacklist, honeypot, tax, ownership, liquidity, holder, source, reputation

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "category": self.category,
        }


@dataclass
class TokenInfo:
    """Basic token metadata."""

    name: str = ""
    symbol: str = ""
    total_supply: str = ""
    holder_count: int = 0
    is_open_source: bool = False
    is_verified: bool = False
    owner: str = ""
    creator: str = ""
    is_in_dex: bool = False


@dataclass
class AnalysisResult:
    """Complete analysis result for a token contract."""

    address: str
    chain: str
    risk_score: int = 0
    risk_level: RiskLevel = RiskLevel.SAFE
    findings: list[Finding] = field(default_factory=list)
    token_info: TokenInfo = field(default_factory=TokenInfo)
    scan_result: ScanResult | None = None
    reputation: ReputationReport | None = None
    goplus_data: dict[str, Any] = field(default_factory=dict)
    error: str = ""

    @property
    def is_safe(self) -> bool:
        return self.risk_level == RiskLevel.SAFE

    @property
    def should_block(self) -> bool:
        return self.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "chain": self.chain,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level.value,
            "token": {
                "name": self.token_info.name,
                "symbol": self.token_info.symbol,
                "holder_count": self.token_info.holder_count,
                "is_open_source": self.token_info.is_open_source,
                "owner": self.token_info.owner,
            },
            "findings": [f.to_dict() for f in self.findings],
            "findings_summary": {
                "critical": len(self.critical_findings),
                "high": len(self.high_findings),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
            },
        }


def analyze(address: str, chain: str = "ethereum") -> AnalysisResult:
    """Run full security analysis on a token contract.

    This is the main entry point. It:
      1. Runs GoPlus, bytecode scan, and reputation checks in parallel
      2. Analyzes all results
      3. Computes weighted risk score
      4. Returns structured result

    Args:
        address: Contract address (0x...)
        chain: Chain name (ethereum, bsc, polygon, etc.)

    Returns:
        AnalysisResult with risk score, findings, and recommendation
    """
    address = address.strip()
    if not address.startswith("0x"):
        address = f"0x{address}"

    result = AnalysisResult(address=address, chain=chain)

    # --- Phase 1: Parallel data collection ---
    goplus_data = {}
    scan_data = None
    reputation_data = None

    with ThreadPoolExecutor(max_workers=3) as pool:
        futures = {
            pool.submit(get_token_security, address, chain): "goplus",
            pool.submit(scan_bytecode, address, chain): "scanner",
            pool.submit(check_reputation, address, chain): "reputation",
        }

        for future in as_completed(futures):
            label = futures[future]
            try:
                res = future.result(timeout=30)
                if label == "goplus":
                    goplus_data = res
                elif label == "scanner":
                    scan_data = res
                elif label == "reputation":
                    reputation_data = res
            except Exception as exc:
                logger.warning("Data collection (%s) failed: %s", label, exc)

    # Parse GoPlus flags
    gp = parse_goplus_flags(goplus_data)
    result.goplus_data = gp
    result.scan_result = scan_data
    result.reputation = reputation_data

    # --- Phase 2: Extract token info ---
    result.token_info = TokenInfo(
        name=gp.get("token_name", ""),
        symbol=gp.get("token_symbol", ""),
        total_supply=gp.get("total_supply", ""),
        holder_count=gp.get("holder_count", 0),
        is_open_source=gp.get("is_open_source", False),
        is_verified=gp.get("is_open_source", False),
        owner=gp.get("owner_address", ""),
        creator=gp.get("creator_address", ""),
        is_in_dex=gp.get("is_in_dex", False),
    )

    # --- Phase 3: Generate findings ---
    if not gp.get("available"):
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No GoPlus data available",
            description=(
                "GoPlus Security API returned no data for this token. "
                "This could mean the token is very new, on an unsupported chain, "
                "or not yet indexed. Exercise extreme caution."
            ),
            category="data",
        ))

    _analyze_honeypot(gp, result)
    _analyze_blacklist(gp, scan_data, result)
    _analyze_ownership(gp, result)
    _analyze_tax(gp, result)
    _analyze_holders(gp, result)
    _analyze_liquidity(gp, result)
    _analyze_source_code(gp, result)
    _analyze_bytecode(scan_data, result)
    _analyze_reputation(reputation_data, result)
    _analyze_misc(gp, result)

    # --- Phase 4: Compute risk score ---
    result.risk_score = _compute_risk_score(result)
    result.risk_level = _score_to_level(result.risk_score)

    return result


# ---------------------------------------------------------------------------
# Finding generators - each analyzes a specific risk category
# ---------------------------------------------------------------------------

def _analyze_honeypot(gp: dict, result: AnalysisResult) -> None:
    """Check for honeypot indicators."""
    if gp.get("is_honeypot"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="HONEYPOT DETECTED",
            description=(
                "GoPlus confirms this token is a honeypot. "
                "You WILL NOT be able to sell this token after buying. "
                "DO NOT interact with this contract."
            ),
            category="honeypot",
        ))

    if gp.get("cannot_sell_all"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Cannot sell all tokens",
            description=(
                "The contract prevents selling your entire token balance. "
                "This is a honeypot variant that traps a portion of your funds."
            ),
            category="honeypot",
        ))

    if gp.get("cannot_buy"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Cannot buy token",
            description="The token currently cannot be purchased. Trading may be disabled.",
            category="honeypot",
        ))

    if gp.get("honeypot_with_same_creator"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Creator has deployed honeypots before",
            description=(
                "The creator of this contract has previously deployed confirmed "
                "honeypot tokens. This is a strong indicator of malicious intent."
            ),
            category="honeypot",
        ))

    if gp.get("is_airdrop_scam"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Airdrop scam detected",
            description=(
                "This token is flagged as an airdrop scam. It was likely "
                "sent to your wallet unsolicited to lure you into interacting "
                "with a malicious contract. DO NOT approve or swap this token."
            ),
            category="honeypot",
        ))


def _analyze_blacklist(
    gp: dict, scan: ScanResult | None, result: AnalysisResult
) -> None:
    """Check for blacklist capabilities - the core mission of CryptoGuard."""
    blacklist_found = False

    if gp.get("is_blacklisted"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Token has active blacklist",
            description=(
                "GoPlus confirms this token has an active blacklist mechanism. "
                "The contract owner can blacklist ANY address, preventing you "
                "from transferring or selling your tokens. After buying, you "
                "could be permanently locked out of your funds."
            ),
            category="blacklist",
        ))
        blacklist_found = True

    if gp.get("is_whitelisted"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Token uses whitelist (inverse blacklist)",
            description=(
                "This token uses a whitelist mechanism. Only whitelisted "
                "addresses can transact. If you are removed from the whitelist "
                "after buying, you cannot sell."
            ),
            category="blacklist",
        ))
        blacklist_found = True

    if gp.get("transfer_pausable"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Transfers can be paused",
            description=(
                "The contract owner can pause all token transfers. "
                "This effectively freezes all holder funds at the owner's discretion."
            ),
            category="blacklist",
        ))

    # Cross-reference with bytecode scan
    if scan and scan.has_blacklist and not blacklist_found:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Blacklist function detected in bytecode",
            description=(
                "Bytecode analysis found blacklist-related function selectors "
                "in the contract code. This means the contract likely has the "
                "ability to blacklist addresses even though GoPlus may not have "
                "flagged it yet. Functions found: "
                + ", ".join(s["name"] for s in scan.matched_selectors if s["risk"] == "blacklist")
            ),
            category="blacklist",
        ))

    if scan and scan.has_pause and not gp.get("transfer_pausable"):
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Pause function detected in bytecode",
            description=(
                "Bytecode contains pause-related selectors. The contract "
                "may be able to halt all transfers."
            ),
            category="blacklist",
        ))


def _analyze_ownership(gp: dict, result: AnalysisResult) -> None:
    """Analyze ownership risks."""
    if gp.get("hidden_owner"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Hidden owner detected",
            description=(
                "The contract has a hidden ownership mechanism. The real owner "
                "may not be visible through standard owner() calls, allowing "
                "concealed admin operations."
            ),
            category="ownership",
        ))

    if gp.get("can_take_back_ownership"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Ownership can be reclaimed",
            description=(
                "Even if ownership appears renounced, it can be reclaimed. "
                "The deployer can regain full admin control at any time."
            ),
            category="ownership",
        ))

    if gp.get("owner_change_balance"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Owner can modify balances",
            description=(
                "The contract owner has the ability to arbitrarily change "
                "token balances. They can drain your wallet or inflate their "
                "own balance to dump on the market."
            ),
            category="ownership",
        ))

    owner = gp.get("owner_address", "")
    if owner and owner != "0x0000000000000000000000000000000000000000":
        # Owner exists - not necessarily bad, but worth noting
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Contract has active owner",
            description=f"Owner address: {owner}",
            category="ownership",
        ))
    elif owner == "0x0000000000000000000000000000000000000000":
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Ownership renounced",
            description="Contract ownership has been renounced (owner = 0x0).",
            category="ownership",
        ))


def _analyze_tax(gp: dict, result: AnalysisResult) -> None:
    """Analyze buy/sell taxes."""
    buy_tax = gp.get("buy_tax", 0.0)
    sell_tax = gp.get("sell_tax", 0.0)

    if sell_tax > 0.50:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title=f"Extreme sell tax: {sell_tax*100:.1f}%",
            description=(
                f"Sell tax is {sell_tax*100:.1f}%. You will lose more than half "
                "your value when selling. This is functionally a honeypot."
            ),
            category="tax",
        ))
    elif sell_tax > 0.20:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Very high sell tax: {sell_tax*100:.1f}%",
            description=f"Sell tax is {sell_tax*100:.1f}%. Significant loss on every sale.",
            category="tax",
        ))
    elif sell_tax > 0.10:
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"High sell tax: {sell_tax*100:.1f}%",
            description=f"Sell tax is {sell_tax*100:.1f}%.",
            category="tax",
        ))
    elif sell_tax > 0.05:
        result.findings.append(Finding(
            severity=Severity.LOW,
            title=f"Moderate sell tax: {sell_tax*100:.1f}%",
            description=f"Sell tax is {sell_tax*100:.1f}%.",
            category="tax",
        ))

    if buy_tax > 0.20:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Very high buy tax: {buy_tax*100:.1f}%",
            description=f"Buy tax is {buy_tax*100:.1f}%.",
            category="tax",
        ))
    elif buy_tax > 0.10:
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"High buy tax: {buy_tax*100:.1f}%",
            description=f"Buy tax is {buy_tax*100:.1f}%.",
            category="tax",
        ))

    if gp.get("slippage_modifiable"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Tax/slippage can be modified",
            description=(
                "The contract owner can change buy/sell tax at any time. "
                "They could set 100% tax after you buy, trapping your funds."
            ),
            category="tax",
        ))

    if gp.get("personal_slippage_modifiable"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Per-address tax can be modified",
            description=(
                "The owner can set different tax rates per address. "
                "They could target YOUR specific address with 100% sell tax."
            ),
            category="tax",
        ))


def _analyze_holders(gp: dict, result: AnalysisResult) -> None:
    """Analyze holder distribution for concentration risks."""
    holder_count = gp.get("holder_count", 0)
    holders = gp.get("holders", [])

    if holder_count < 10:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Very few holders: {holder_count}",
            description="Token has very few holders. Extremely vulnerable to manipulation.",
            category="holder",
        ))
    elif holder_count < 50:
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Low holder count: {holder_count}",
            description="Token has relatively few holders.",
            category="holder",
        ))

    # Check for whale concentration
    for h in holders[:5]:
        pct = h.get("percent", 0)
        addr = h.get("address", "")
        is_contract = h.get("is_contract", False)
        is_locked = h.get("is_locked", False)

        if pct > 0.5 and not is_locked and not is_contract:
            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                title=f"Single wallet holds {pct*100:.1f}% of supply",
                description=(
                    f"Address {addr} holds over 50% of the token supply "
                    "and is NOT locked. They can dump the entire market at any time."
                ),
                category="holder",
            ))
        elif pct > 0.2 and not is_locked and not is_contract:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title=f"Whale holds {pct*100:.1f}% of supply",
                description=f"Address {addr} holds a large portion of supply (unlocked).",
                category="holder",
            ))


def _analyze_liquidity(gp: dict, result: AnalysisResult) -> None:
    """Analyze DEX liquidity safety."""
    dex_info = gp.get("dex", [])
    lp_holders = gp.get("lp_holders", [])

    if not dex_info and gp.get("is_in_dex"):
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="No DEX pair info available",
            description="Token claims to be on a DEX but no pair data was returned.",
            category="liquidity",
        ))
    elif not dex_info:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Token not listed on any DEX",
            description="No DEX trading pairs found. You may not be able to sell.",
            category="liquidity",
        ))
        return

    # Check total liquidity
    total_liquidity = sum(d.get("liquidity", 0) for d in dex_info)
    if total_liquidity < 1000:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title=f"Extremely low liquidity: ${total_liquidity:,.0f}",
            description="Liquidity is dangerously low. Large slippage or inability to sell.",
            category="liquidity",
        ))
    elif total_liquidity < 10000:
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title=f"Low liquidity: ${total_liquidity:,.0f}",
            description="Limited liquidity may cause high slippage.",
            category="liquidity",
        ))

    # Check if LP is locked
    lp_locked = any(lp.get("is_locked") for lp in lp_holders)
    if not lp_locked and lp_holders:
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Liquidity NOT locked",
            description=(
                "Liquidity pool tokens are not locked. The liquidity provider "
                "can remove all liquidity at any time (rug pull)."
            ),
            category="liquidity",
        ))
    elif lp_locked:
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Liquidity is locked",
            description="At least one LP position is locked.",
            category="liquidity",
        ))


def _analyze_source_code(gp: dict, result: AnalysisResult) -> None:
    """Analyze source code availability."""
    if not gp.get("is_open_source"):
        result.findings.append(Finding(
            severity=Severity.HIGH,
            title="Contract source code NOT verified",
            description=(
                "The contract source code is not published/verified on the "
                "block explorer. This means the code cannot be publicly audited. "
                "Unverified contracts have a much higher chance of being malicious."
            ),
            category="source",
        ))

    if gp.get("is_proxy"):
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Contract is a proxy",
            description=(
                "This is a proxy contract. The actual logic lives in a separate "
                "implementation contract that can potentially be upgraded to "
                "include malicious code."
            ),
            category="source",
        ))

    if gp.get("external_call"):
        result.findings.append(Finding(
            severity=Severity.LOW,
            title="Contract makes external calls",
            description="The contract calls external contracts, which adds execution risk.",
            category="source",
        ))


def _analyze_bytecode(scan: ScanResult | None, result: AnalysisResult) -> None:
    """Incorporate bytecode scan findings."""
    if not scan or not scan.has_bytecode:
        return

    if scan.has_selfdestruct:
        # Check if GoPlus also flagged it to avoid double-counting
        goplus_selfdestruct = result.goplus_data.get("selfdestruct", False)
        if not goplus_selfdestruct:
            result.findings.append(Finding(
                severity=Severity.HIGH,
                title="SELFDESTRUCT capability in bytecode",
                description=(
                    "Bytecode analysis detected potential SELFDESTRUCT opcode. "
                    "The contract could be destroyed, draining all native tokens."
                ),
                category="selfdestruct",
            ))

    # Add unique bytecode findings not covered by GoPlus
    goplus_blacklist = result.goplus_data.get("is_blacklisted", False)
    for bf in scan.findings:
        if bf.category == "blacklist" and not goplus_blacklist:
            # Already handled in _analyze_blacklist
            pass
        elif bf.category in ("complexity", "proxy") and bf.severity != "INFO":
            result.findings.append(Finding(
                severity=Severity(bf.severity),
                title=f"[Bytecode] {bf.title}",
                description=bf.description,
                category=bf.category,
            ))


def _analyze_reputation(rep: ReputationReport | None, result: AnalysisResult) -> None:
    """Incorporate multi-source reputation data."""
    if not rep:
        return

    # Check consensus
    if rep.consensus_flagged:
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Multiple reputation sources flag this token",
            description=(
                "A majority of independent security oracles have flagged this "
                "token as dangerous. Sources: "
                + "; ".join(rep.flags)
            ),
            category="reputation",
        ))

    # Check individual sources for specific insights
    for src in rep.sources:
        if not src.available:
            continue

        # Honeypot.is specific findings
        if src.source == "honeypot.is" and src.is_flagged:
            reason = src.details.get("honeypot_reason", "")
            result.findings.append(Finding(
                severity=Severity.CRITICAL,
                title="Honeypot.is confirms honeypot",
                description=(
                    f"Honeypot.is buy/sell simulation confirms this is a honeypot. "
                    f"Reason: {reason}" if reason else
                    "Honeypot.is buy/sell simulation confirms this is a honeypot."
                ),
                category="reputation",
            ))

        # Honeypot.is tax cross-validation
        if src.source == "honeypot.is" and src.available:
            hp_sell_tax = src.details.get("sell_tax", 0)
            hp_buy_tax = src.details.get("buy_tax", 0)
            if hp_sell_tax and hp_sell_tax > 50:
                result.findings.append(Finding(
                    severity=Severity.CRITICAL,
                    title=f"Honeypot.is: simulated sell tax {hp_sell_tax:.1f}%",
                    description="Buy/sell simulation shows extreme sell tax.",
                    category="reputation",
                ))

        # TokenSniffer similar scams
        if src.source == "tokensniffer.com" and src.available:
            similar_scams = src.details.get("similar_scams", 0)
            if similar_scams:
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"TokenSniffer: {similar_scams} similar known scams",
                    description=(
                        f"TokenSniffer found {similar_scams} tokens with similar "
                        "code that are confirmed scams."
                    ),
                    category="reputation",
                ))
            score = src.details.get("score", -1)
            if 0 <= score < 30:
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"TokenSniffer audit score: {score}/100",
                    description="Very low automated audit score.",
                    category="reputation",
                ))

        # De.Fi critical issues
        if src.source == "de.fi" and src.available:
            critical_count = src.details.get("critical_issues", 0)
            if critical_count:
                result.findings.append(Finding(
                    severity=Severity.HIGH,
                    title=f"De.Fi Scanner: {critical_count} critical issues",
                    description=f"De.Fi found {critical_count} critical security issues.",
                    category="reputation",
                ))


def _analyze_misc(gp: dict, result: AnalysisResult) -> None:
    """Additional miscellaneous checks."""
    if gp.get("is_mintable"):
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Token is mintable",
            description="New tokens can be minted, potentially diluting your holdings.",
            category="supply",
        ))

    if gp.get("selfdestruct"):
        result.findings.append(Finding(
            severity=Severity.CRITICAL,
            title="Contract has SELFDESTRUCT",
            description=(
                "GoPlus confirms the contract can self-destruct. "
                "All tokens would become worthless if triggered."
            ),
            category="selfdestruct",
        ))

    if gp.get("trading_cooldown"):
        result.findings.append(Finding(
            severity=Severity.LOW,
            title="Trading cooldown enabled",
            description="There is a cooldown period between trades.",
            category="trading",
        ))

    if gp.get("anti_whale_modifiable"):
        result.findings.append(Finding(
            severity=Severity.LOW,
            title="Anti-whale limits are modifiable",
            description="The owner can change max transaction/wallet limits.",
            category="trading",
        ))

    # Trust list check
    if gp.get("on_trust_list"):
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="Token is on GoPlus trust list",
            description="This token is recognized as legitimate by GoPlus.",
            category="trust",
        ))

    # Additional risk notes from GoPlus
    notes = gp.get("other_potential_risks", "")
    if notes and notes.strip():
        result.findings.append(Finding(
            severity=Severity.MEDIUM,
            title="Additional risk notes from GoPlus",
            description=notes.strip(),
            category="misc",
        ))

    note = gp.get("note", "")
    if note and note.strip():
        result.findings.append(Finding(
            severity=Severity.INFO,
            title="GoPlus note",
            description=note.strip(),
            category="misc",
        ))


# ---------------------------------------------------------------------------
# Risk score computation
# ---------------------------------------------------------------------------

def _compute_risk_score(result: AnalysisResult) -> int:
    """Compute aggregate risk score (0-100) from all findings.

    Uses weighted scoring where:
      - CRITICAL findings have highest weight
      - Multiple findings in the same category don't stack linearly
      - Reputation consensus adds multiplicative penalty
      - Trust list provides a small bonus
    """
    score = 0.0
    category_scores: dict[str, float] = {}

    for finding in result.findings:
        # Base score by severity
        severity_base = {
            Severity.CRITICAL: 30,
            Severity.HIGH: 18,
            Severity.MEDIUM: 8,
            Severity.LOW: 3,
            Severity.INFO: 0,
        }
        base = severity_base.get(finding.severity, 0)

        # Category-specific weight from constants
        category_weight = 1.0
        category_key = _finding_to_weight_key(finding)
        if category_key and category_key in RISK_WEIGHTS:
            # Use the predefined weight instead of base
            base = RISK_WEIGHTS[category_key] * 0.4

        cat = finding.category
        if cat not in category_scores:
            category_scores[cat] = 0
        # Diminishing returns within same category
        existing = category_scores[cat]
        contribution = base * (0.6 ** (existing / 20))
        category_scores[cat] += contribution

    score = sum(category_scores.values())

    # Reputation consensus multiplier
    if result.reputation and result.reputation.consensus_flagged:
        score *= 1.3

    # Trust list bonus (reduces score slightly)
    if result.goplus_data.get("on_trust_list"):
        score *= 0.6

    return min(100, max(0, int(score)))


def _finding_to_weight_key(finding: Finding) -> str:
    """Map a finding to its RISK_WEIGHTS key."""
    title_lower = finding.title.lower()
    cat = finding.category

    if "honeypot" in title_lower:
        return "is_honeypot"
    if cat == "blacklist":
        if "bytecode" in title_lower:
            return "blacklist_function"
        return "is_blacklisted"
    if "sell tax" in title_lower:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            return "high_sell_tax"
        return "moderate_sell_tax"
    if "buy tax" in title_lower:
        if finding.severity in (Severity.CRITICAL, Severity.HIGH):
            return "high_buy_tax"
        return "moderate_buy_tax"
    if "liquidity" in title_lower and "lock" in title_lower:
        return "unlocked_liquidity"
    if "liquidity" in title_lower and "low" in title_lower:
        return "low_liquidity"
    if "holder" in title_lower:
        if "few" in title_lower or "low" in title_lower:
            return "low_holder_count"
        return "whale_concentration"
    if "source" in cat or "verified" in title_lower:
        return "not_open_source"
    if "selfdestruct" in title_lower or cat == "selfdestruct":
        return "selfdestruct"
    if "balance" in title_lower:
        return "owner_change_balance"
    if "pause" in title_lower:
        return "transfer_pausable"
    if "hidden owner" in title_lower:
        return "hidden_owner"
    if "mintable" in title_lower or "mint" in title_lower:
        return "is_mintable"
    if "proxy" in title_lower:
        return "is_proxy"

    return ""


def _score_to_level(score: int) -> RiskLevel:
    """Convert numeric risk score to risk level."""
    if score >= RISK_THRESHOLDS["CRITICAL"]:
        return RiskLevel.CRITICAL
    if score >= RISK_THRESHOLDS["HIGH"]:
        return RiskLevel.HIGH
    if score >= RISK_THRESHOLDS["MEDIUM"]:
        return RiskLevel.MEDIUM
    if score >= RISK_THRESHOLDS["LOW"]:
        return RiskLevel.LOW
    return RiskLevel.SAFE
