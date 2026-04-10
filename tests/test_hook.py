"""Tests for the hook module - address extraction and transaction detection."""

import pytest
from cryptoguard.hook import extract_addresses, is_transaction_command, detect_chain


class TestExtractAddresses:
    def test_single_address(self):
        text = "cast send 0xdAC17F958D2ee523a2206206994597C13D831ec7"
        addrs = extract_addresses(text)
        assert len(addrs) == 1
        assert addrs[0] == "0xdAC17F958D2ee523a2206206994597C13D831ec7"

    def test_multiple_addresses(self):
        text = (
            "cast send 0xdAC17F958D2ee523a2206206994597C13D831ec7 "
            "--to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        )
        addrs = extract_addresses(text)
        assert len(addrs) == 2

    def test_deduplication(self):
        text = (
            "0xdAC17F958D2ee523a2206206994597C13D831ec7 "
            "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        )
        addrs = extract_addresses(text)
        assert len(addrs) == 1

    def test_excludes_zero_address(self):
        text = "transfer 0x0000000000000000000000000000000000000000"
        addrs = extract_addresses(text)
        assert len(addrs) == 0

    def test_excludes_burn_address(self):
        text = "transfer 0x000000000000000000000000000000000000dEaD"
        addrs = extract_addresses(text)
        assert len(addrs) == 0

    def test_no_addresses(self):
        text = "echo hello world"
        addrs = extract_addresses(text)
        assert len(addrs) == 0

    def test_partial_hex_not_matched(self):
        text = "0xdAC17F958D"  # Too short
        addrs = extract_addresses(text)
        assert len(addrs) == 0


class TestIsTransactionCommand:
    def test_cast_send(self):
        assert is_transaction_command("cast send 0x1234... 'approve(address,uint256)'")

    def test_swap_call(self):
        assert is_transaction_command("curl -X POST ... swapExactTokensForTokens ...")

    def test_transfer(self):
        assert is_transaction_command("cast send 0x... 'transfer(address,uint256)' 0x... 1000")

    def test_read_only(self):
        assert not is_transaction_command("cast call 0x... 'balanceOf(address)' 0x...")

    def test_non_crypto(self):
        assert not is_transaction_command("git push origin main")

    def test_echo(self):
        assert not is_transaction_command("echo hello")

    def test_approve(self):
        assert is_transaction_command("approve(0x1234, 0xffffff)")

    def test_uniswap(self):
        assert is_transaction_command("uniswap swap --amount 100")


class TestDetectChain:
    def test_bsc(self):
        assert detect_chain("--rpc-url https://bsc-dataseed.binance.org") == "bsc"

    def test_polygon(self):
        assert detect_chain("--chain polygon --to 0x...") == "polygon"

    def test_arbitrum(self):
        assert detect_chain("arbitrum mainnet swap") == "arbitrum"

    def test_base(self):
        assert detect_chain("https://mainnet.base.org cast send") == "base"

    def test_default_ethereum(self):
        assert detect_chain("cast send 0x1234") == "ethereum"


class TestScannerImport:
    """Verify scanner module can be imported and basic structures work."""

    def test_import_scanner(self):
        from cryptoguard.scanner import ScanResult
        result = ScanResult(address="0x0", chain="ethereum")
        assert not result.is_contract
        assert not result.has_blacklist

    def test_import_analyzer(self):
        from cryptoguard.analyzer import AnalysisResult, RiskLevel
        result = AnalysisResult(address="0x0", chain="ethereum")
        assert result.risk_level == RiskLevel.SAFE
        assert result.is_safe

    def test_import_reputation(self):
        from cryptoguard.reputation import ReputationReport
        report = ReputationReport(address="0x0", chain="ethereum")
        report.compute_consensus()
        assert not report.consensus_flagged
