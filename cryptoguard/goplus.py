"""GoPlus Security API client for comprehensive token safety analysis."""

from __future__ import annotations

import logging
from typing import Any

import requests

from .constants import CHAINS, CHAIN_ALIASES, GOPLUS_BASE_URL

logger = logging.getLogger(__name__)

# Timeout for API calls (seconds)
_TIMEOUT = 15


def _resolve_chain(chain: str) -> str:
    """Resolve chain name/alias to GoPlus chain ID."""
    chain = chain.lower().strip()
    if chain in CHAIN_ALIASES:
        chain = CHAIN_ALIASES[chain]
    if chain not in CHAINS:
        raise ValueError(
            f"Unsupported chain: {chain!r}. "
            f"Supported: {', '.join(sorted(CHAINS.keys()))}"
        )
    return CHAINS[chain]["id"]


def get_token_security(address: str, chain: str) -> dict[str, Any]:
    """Fetch token security data from GoPlus.

    Returns the raw GoPlus result dict for the given address, or an empty
    dict if the API call fails or the token is not found.
    """
    chain_id = _resolve_chain(chain)
    address = address.lower().strip()

    url = f"{GOPLUS_BASE_URL}/token_security/{chain_id}"
    params = {"contract_addresses": address}

    try:
        resp = requests.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("GoPlus token_security request failed: %s", exc)
        return {}

    if data.get("code") != 1:
        logger.warning("GoPlus returned error: %s", data.get("message", "unknown"))
        return {}

    result = data.get("result", {})
    # GoPlus keys are lowercased addresses
    return result.get(address, result.get(address.lower(), {}))


def get_address_security(address: str, chain: str) -> dict[str, Any]:
    """Check if a wallet address is flagged (malicious, phishing, etc.)."""
    chain_id = _resolve_chain(chain)
    address = address.lower().strip()

    url = f"{GOPLUS_BASE_URL}/address_security/{address}"
    params = {"chain_id": chain_id}

    try:
        resp = requests.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("GoPlus address_security request failed: %s", exc)
        return {}

    if data.get("code") != 1:
        return {}

    return data.get("result", {})


def get_approval_security(address: str, chain: str) -> dict[str, Any]:
    """Check approval (allowance) risks for a contract."""
    chain_id = _resolve_chain(chain)
    address = address.lower().strip()

    url = f"{GOPLUS_BASE_URL}/approval_security/{chain_id}"
    params = {"contract_addresses": address}

    try:
        resp = requests.get(url, params=params, timeout=_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("GoPlus approval_security request failed: %s", exc)
        return {}

    if data.get("code") != 1:
        return {}

    return data.get("result", {})


def _flag(data: dict, key: str) -> bool:
    """Interpret a GoPlus string flag as boolean. '1' = True, anything else = False."""
    val = data.get(key, "0")
    if isinstance(val, str):
        return val.strip() == "1"
    return bool(val)


def parse_goplus_flags(data: dict) -> dict[str, Any]:
    """Parse raw GoPlus response into structured boolean flags and values.

    Returns a dict with:
      - All boolean flags (is_honeypot, is_blacklisted, etc.)
      - Numeric fields (buy_tax, sell_tax, holder_count, etc.)
      - Holder/LP info
    """
    if not data:
        return {"available": False}

    parsed = {"available": True}

    # --- Boolean flags ---
    bool_fields = [
        "is_honeypot",
        "is_open_source",
        "is_proxy",
        "is_mintable",
        "is_in_dex",
        "is_blacklisted",
        "is_whitelisted",
        "is_true_token",
        "is_airdrop_scam",
        "is_anti_whale",
        "can_take_back_ownership",
        "owner_change_balance",
        "hidden_owner",
        "selfdestruct",
        "external_call",
        "transfer_pausable",
        "cannot_buy",
        "cannot_sell_all",
        "slippage_modifiable",
        "personal_slippage_modifiable",
        "trading_cooldown",
        "anti_whale_modifiable",
        "honeypot_with_same_creator",
    ]
    for field in bool_fields:
        parsed[field] = _flag(data, field)

    # --- String fields ---
    str_fields = [
        "token_name",
        "token_symbol",
        "owner_address",
        "creator_address",
        "total_supply",
        "other_potential_risks",
        "note",
    ]
    for field in str_fields:
        parsed[field] = data.get(field, "")

    # --- Numeric fields ---
    for field in ("buy_tax", "sell_tax"):
        raw = data.get(field, "0")
        try:
            parsed[field] = float(raw) if raw else 0.0
        except (ValueError, TypeError):
            parsed[field] = 0.0

    for field in ("holder_count", "lp_holder_count"):
        raw = data.get(field, "0")
        try:
            parsed[field] = int(raw) if raw else 0
        except (ValueError, TypeError):
            parsed[field] = 0

    # --- Trust list ---
    trust = data.get("trust_list", "0")
    parsed["on_trust_list"] = trust == "1" if isinstance(trust, str) else bool(trust)

    # --- Top holders ---
    holders = data.get("holders", [])
    parsed["holders"] = []
    for h in holders[:20]:
        parsed["holders"].append({
            "address": h.get("address", ""),
            "percent": _safe_float(h.get("percent", "0")),
            "is_locked": h.get("is_locked", 0) == 1,
            "is_contract": h.get("is_contract", 0) == 1,
            "tag": h.get("tag", ""),
        })

    # --- DEX info ---
    dex_info = data.get("dex", [])
    parsed["dex"] = []
    for d in dex_info:
        parsed["dex"].append({
            "name": d.get("name", "Unknown"),
            "pair": d.get("pair", ""),
            "liquidity": _safe_float(d.get("liquidity", "0")),
        })

    # --- LP holders ---
    lp_holders = data.get("lp_holders", [])
    parsed["lp_holders"] = []
    for lp in lp_holders[:10]:
        parsed["lp_holders"].append({
            "address": lp.get("address", ""),
            "percent": _safe_float(lp.get("percent", "0")),
            "is_locked": lp.get("is_locked", 0) == 1,
            "is_contract": lp.get("is_contract", 0) == 1,
            "tag": lp.get("tag", ""),
        })

    return parsed


def _safe_float(val: Any) -> float:
    try:
        return float(val) if val else 0.0
    except (ValueError, TypeError):
        return 0.0
