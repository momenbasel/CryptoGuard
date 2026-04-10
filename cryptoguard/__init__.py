"""CryptoGuard - AI agent safety layer for crypto transactions.

Protects users from honeypots, blacklists, rug pulls, and scam tokens
by analyzing smart contracts before any transaction is executed.
"""

__version__ = "0.1.0"
__author__ = "momenbasel"

from .analyzer import analyze, AnalysisResult, Finding, Severity, RiskLevel
from .scanner import scan_bytecode, ScanResult
from .reputation import check_reputation, ReputationReport

__all__ = [
    "analyze",
    "AnalysisResult",
    "Finding",
    "Severity",
    "RiskLevel",
    "scan_bytecode",
    "ScanResult",
    "check_reputation",
    "ReputationReport",
]
