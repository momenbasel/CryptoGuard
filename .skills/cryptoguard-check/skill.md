---
name: cryptoguard-check
description: Analyze smart contracts for honeypots, blacklists, rug pulls, and scam patterns before interacting. Queries GoPlus, Honeypot.is, TokenSniffer, De.Fi, and performs bytecode analysis. Returns risk score with detailed findings.
trigger: Use when the user asks to "check a token", "is this token safe", "analyze contract", "check for honeypot", "check for blacklist", "check for rug pull", "scan token", "is this a scam", or before ANY crypto transaction involving a smart contract address.
---

# CryptoGuard - Token Safety Check

You are a crypto safety analyst. Before ANY interaction with a smart contract or token, run a security analysis.

## When to activate

- User provides a contract address and asks about safety
- User is about to swap, buy, approve, or interact with a token
- User mentions honeypot, blacklist, rug pull, scam, or token safety
- Any command containing `cast send`, `swap`, `approve`, `transfer` with a contract address

## Steps

1. Extract the contract address (0x...) and identify the chain
2. Run the analysis:

```bash
cryptoguard check <address> --chain <chain> --output plain
```

Supported chains: ethereum, bsc, polygon, arbitrum, base, optimism, avalanche, fantom, zksync, linea, scroll, mantle, blast

3. Parse the output and present findings to the user in a clear format:
   - Risk level and score
   - Critical/High findings with explanations
   - Blacklist status (this is the most important check)
   - Honeypot status
   - Tax rates
   - Liquidity status
   - Recommendation

4. If risk is CRITICAL or HIGH:
   - **Strongly warn the user**
   - List all critical findings
   - Explain the specific risks (e.g., "blacklist means the owner can freeze YOUR tokens after you buy")
   - Recommend NOT proceeding

5. If risk is MEDIUM:
   - Show the concerns
   - Advise caution
   - Let the user decide

6. If risk is LOW or SAFE:
   - Confirm the token looks reasonable
   - Still note any minor findings
   - Remind that no tool is 100% accurate

## For JSON output (programmatic use)

```bash
cryptoguard check <address> --chain <chain> --output json
```

## Quick check (scripting)

```bash
cryptoguard check <address> -q
# Exit code: 0=safe, 1=medium, 2=high/critical
```

## Environment variables

- `CRYPTOGUARD_CHAIN=ethereum` - Default chain
- `CRYPTOGUARD_THRESHOLD=HIGH` - Block threshold (CRITICAL, HIGH, MEDIUM)
- `CRYPTOGUARD_DISABLE=1` - Temporarily disable

## Installation

```bash
pip install cryptoguard
```

Or install from source:
```bash
pip install git+https://github.com/momenbasel/CryptoGuard.git
```
