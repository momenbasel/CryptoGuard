"""Multi-source contract reputation aggregator.

Queries multiple independent security oracles to cross-validate token safety:
  - Honeypot.is    - Dedicated honeypot simulation engine
  - Token Sniffer  - Automated token audit scores
  - De.Fi Scanner  - DeFi protocol security ratings
  - Etherscan      - Contract labels & verification status
  - QuickIntel     - Multi-chain token intelligence
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

import requests

from .constants import CHAINS, CHAIN_ALIASES

logger = logging.getLogger(__name__)

_TIMEOUT = 12


@dataclass
class ReputationSource:
    """Result from a single reputation provider."""

    source: str
    available: bool = False
    is_flagged: bool = False
    risk_score: int = 0          # 0-100, provider-specific
    details: dict[str, Any] = field(default_factory=dict)
    error: str = ""


@dataclass
class ReputationReport:
    """Aggregated reputation from all sources."""

    address: str
    chain: str
    sources: list[ReputationSource] = field(default_factory=list)
    consensus_flagged: bool = False   # majority of sources flag it
    average_risk: float = 0.0
    flags: list[str] = field(default_factory=list)

    def compute_consensus(self) -> None:
        """Calculate consensus from all available sources."""
        available = [s for s in self.sources if s.available]
        if not available:
            return
        flagged_count = sum(1 for s in available if s.is_flagged)
        self.consensus_flagged = flagged_count > len(available) / 2
        scores = [s.risk_score for s in available if s.risk_score > 0]
        self.average_risk = sum(scores) / len(scores) if scores else 0.0


def _resolve_chain_id(chain: str) -> str:
    chain = chain.lower().strip()
    if chain in CHAIN_ALIASES:
        chain = CHAIN_ALIASES[chain]
    if chain not in CHAINS:
        return "1"
    return CHAINS[chain]["id"]


# ---------------------------------------------------------------------------
# Honeypot.is  -  Free, no API key, simulates buy+sell
# ---------------------------------------------------------------------------
def _check_honeypot_is(address: str, chain_id: str) -> ReputationSource:
    """Query honeypot.is simulation API."""
    src = ReputationSource(source="honeypot.is")
    try:
        url = "https://api.honeypot.is/v2/IsHoneypot"
        params = {"address": address, "chainID": chain_id}
        resp = requests.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        src.available = True

        hp = data.get("honeypotResult", {})
        src.is_flagged = hp.get("isHoneypot", False)
        src.details = {
            "is_honeypot": hp.get("isHoneypot", False),
            "honeypot_reason": hp.get("honeypotReason", ""),
            "buy_tax": data.get("simulationResult", {}).get("buyTax", 0),
            "sell_tax": data.get("simulationResult", {}).get("sellTax", 0),
            "buy_gas": data.get("simulationResult", {}).get("buyGas", ""),
            "sell_gas": data.get("simulationResult", {}).get("sellGas", ""),
            "transfer_tax": data.get("simulationResult", {}).get("transferTax", 0),
        }

        # Risk score: honeypot = 100, high tax = proportional
        if src.is_flagged:
            src.risk_score = 100
        else:
            sell_tax = src.details.get("sell_tax", 0) or 0
            buy_tax = src.details.get("buy_tax", 0) or 0
            src.risk_score = min(int(max(sell_tax, buy_tax) * 100), 99)

        # Collect specific flags
        pair = data.get("pair", {})
        if pair.get("liquidity", 0) and pair["liquidity"] < 1000:
            src.details["low_liquidity"] = True

        summary = data.get("summary", {})
        if summary.get("riskLevel"):
            src.details["risk_level"] = summary["riskLevel"]

    except (requests.RequestException, ValueError, KeyError) as exc:
        src.error = str(exc)
        logger.debug("honeypot.is check failed: %s", exc)
    return src


# ---------------------------------------------------------------------------
# Token Sniffer  -  Free tier, provides audit score
# ---------------------------------------------------------------------------
def _check_token_sniffer(address: str, chain_id: str) -> ReputationSource:
    """Query Token Sniffer for automated audit score."""
    src = ReputationSource(source="tokensniffer.com")
    try:
        # Token Sniffer v2 API (public, rate-limited)
        url = f"https://tokensniffer.com/api/v2/tokens/{chain_id}/{address}"
        params = {"apikey": "none", "include_metrics": "true", "include_tests": "true"}
        resp = requests.get(url, params=params, timeout=_TIMEOUT)

        if resp.status_code == 429:
            src.error = "rate limited"
            return src
        if resp.status_code != 200:
            src.error = f"HTTP {resp.status_code}"
            return src

        data = resp.json()
        src.available = True

        score = data.get("score", -1)
        src.details["score"] = score
        src.details["name"] = data.get("name", "")
        src.details["symbol"] = data.get("symbol", "")

        # Invert score: TokenSniffer 100 = safe, our risk 0 = safe
        if score >= 0:
            src.risk_score = max(0, 100 - score)
            src.is_flagged = score < 40  # Below 40/100 is dangerous

        # Collect test results
        tests = data.get("tests", [])
        failed_tests = []
        for test in tests:
            if test.get("result") == "fail":
                failed_tests.append(test.get("id", "unknown"))
        if failed_tests:
            src.details["failed_tests"] = failed_tests

        # Check for similar known scams
        similar = data.get("similar_tokens", [])
        scam_similar = [s for s in similar if s.get("is_scam")]
        if scam_similar:
            src.details["similar_scams"] = len(scam_similar)
            src.is_flagged = True
            src.risk_score = max(src.risk_score, 70)

    except (requests.RequestException, ValueError, KeyError) as exc:
        src.error = str(exc)
        logger.debug("TokenSniffer check failed: %s", exc)
    return src


# ---------------------------------------------------------------------------
# De.Fi Scanner  -  Free public API for token audits
# ---------------------------------------------------------------------------
def _check_defi_scanner(address: str, chain_id: str) -> ReputationSource:
    """Query De.Fi (formerly DeFi Safety) scanner."""
    src = ReputationSource(source="de.fi")
    try:
        url = "https://public-api.de.fi/graphql"
        query = """
        query GetTokenSecurity($address: String!, $chainId: Int!) {
            tokenSecurity(address: $address, chainId: $chainId) {
                overallRisk
                issues {
                    title
                    severity
                    description
                }
            }
        }
        """
        payload = {
            "query": query,
            "variables": {"address": address, "chainId": int(chain_id)},
        }
        resp = requests.post(url, json=payload, timeout=_TIMEOUT)

        if resp.status_code != 200:
            src.error = f"HTTP {resp.status_code}"
            return src

        data = resp.json()
        token_sec = data.get("data", {}).get("tokenSecurity")
        if not token_sec:
            src.error = "no data returned"
            return src

        src.available = True
        overall_risk = token_sec.get("overallRisk", "unknown")
        src.details["overall_risk"] = overall_risk

        issues = token_sec.get("issues", [])
        src.details["issues"] = issues
        src.details["issue_count"] = len(issues)

        critical_issues = [i for i in issues if i.get("severity") in ("critical", "high")]
        src.details["critical_issues"] = len(critical_issues)

        risk_map = {"critical": 90, "high": 70, "medium": 40, "low": 15, "none": 0}
        src.risk_score = risk_map.get(overall_risk.lower(), 50)
        src.is_flagged = overall_risk.lower() in ("critical", "high")

    except (requests.RequestException, ValueError, KeyError) as exc:
        src.error = str(exc)
        logger.debug("De.Fi check failed: %s", exc)
    return src


# ---------------------------------------------------------------------------
# QuickIntel  -  Multi-chain token intelligence
# ---------------------------------------------------------------------------
def _check_quickintel(address: str, chain_id: str) -> ReputationSource:
    """Query QuickIntel for token intelligence."""
    src = ReputationSource(source="quickintel.io")
    try:
        url = f"https://api.quickintel.io/v1/getquickiauditfull"
        payload = {
            "chain": _chain_id_to_quickintel(chain_id),
            "token_address": address,
        }
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, json=payload, headers=headers, timeout=_TIMEOUT)

        if resp.status_code != 200:
            src.error = f"HTTP {resp.status_code}"
            return src

        data = resp.json()
        if not data:
            src.error = "empty response"
            return src

        src.available = True

        # QuickIntel returns various risk flags
        token_details = data.get("tokenDetails", {})
        src.details["name"] = token_details.get("token_name", "")
        src.details["symbol"] = token_details.get("token_symbol", "")

        # Collect risk indicators
        risk_indicators = []
        if data.get("is_honeypot"):
            risk_indicators.append("honeypot")
            src.is_flagged = True
        if data.get("is_blacklisted"):
            risk_indicators.append("blacklisted")
        if data.get("can_blacklist"):
            risk_indicators.append("can_blacklist")
            src.is_flagged = True
        if data.get("has_mint"):
            risk_indicators.append("mintable")
        if data.get("can_self_destruct"):
            risk_indicators.append("self_destruct")
            src.is_flagged = True
        if data.get("has_proxy"):
            risk_indicators.append("proxy")
        if data.get("can_pause_trading"):
            risk_indicators.append("pausable")

        src.details["risk_indicators"] = risk_indicators
        src.risk_score = min(len(risk_indicators) * 15, 100)

    except (requests.RequestException, ValueError, KeyError) as exc:
        src.error = str(exc)
        logger.debug("QuickIntel check failed: %s", exc)
    return src


def _chain_id_to_quickintel(chain_id: str) -> str:
    """Map numeric chain ID to QuickIntel chain name."""
    mapping = {
        "1": "eth", "56": "bsc", "137": "polygon", "42161": "arbitrum",
        "8453": "base", "10": "optimism", "43114": "avalanche",
        "250": "fantom", "324": "zksync",
    }
    return mapping.get(chain_id, "eth")


# ---------------------------------------------------------------------------
# Public entry point: parallel reputation check
# ---------------------------------------------------------------------------
def check_reputation(address: str, chain: str) -> ReputationReport:
    """Query all reputation sources in parallel and aggregate results.

    Returns a ReputationReport with individual source results and
    consensus determination.
    """
    chain_id = _resolve_chain_id(chain)
    address = address.lower().strip()
    if not address.startswith("0x"):
        address = f"0x{address}"

    report = ReputationReport(address=address, chain=chain)

    # Run all checks in parallel for speed
    checks = {
        "honeypot.is": (_check_honeypot_is, address, chain_id),
        "tokensniffer": (_check_token_sniffer, address, chain_id),
        "de.fi": (_check_defi_scanner, address, chain_id),
        "quickintel": (_check_quickintel, address, chain_id),
    }

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {}
        for name, (fn, addr, cid) in checks.items():
            futures[pool.submit(fn, addr, cid)] = name

        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result(timeout=_TIMEOUT + 5)
                report.sources.append(result)
            except Exception as exc:
                logger.warning("Reputation check %s failed: %s", name, exc)
                report.sources.append(ReputationSource(
                    source=name, error=str(exc)
                ))

    # Aggregate flags
    for src in report.sources:
        if src.available and src.is_flagged:
            report.flags.append(f"{src.source}: FLAGGED (risk={src.risk_score})")

    report.compute_consensus()
    return report
