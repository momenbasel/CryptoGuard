"""Chain configurations, dangerous function selectors, and risk scoring weights."""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Supported EVM chains  (chain_name -> {goplus_id, rpc, explorer})
# ---------------------------------------------------------------------------
CHAINS: dict[str, dict] = {
    "ethereum": {
        "id": "1",
        "rpc": "https://eth.llamarpc.com",
        "explorer": "https://api.etherscan.io/api",
    },
    "bsc": {
        "id": "56",
        "rpc": "https://bsc-dataseed1.binance.org",
        "explorer": "https://api.bscscan.com/api",
    },
    "polygon": {
        "id": "137",
        "rpc": "https://polygon-rpc.com",
        "explorer": "https://api.polygonscan.com/api",
    },
    "arbitrum": {
        "id": "42161",
        "rpc": "https://arb1.arbitrum.io/rpc",
        "explorer": "https://api.arbiscan.io/api",
    },
    "base": {
        "id": "8453",
        "rpc": "https://mainnet.base.org",
        "explorer": "https://api.basescan.org/api",
    },
    "optimism": {
        "id": "10",
        "rpc": "https://mainnet.optimism.io",
        "explorer": "https://api-optimistic.etherscan.io/api",
    },
    "avalanche": {
        "id": "43114",
        "rpc": "https://api.avax.network/ext/bc/C/rpc",
        "explorer": "https://api.snowtrace.io/api",
    },
    "fantom": {
        "id": "250",
        "rpc": "https://rpc.ftm.tools",
        "explorer": "https://api.ftmscan.com/api",
    },
    "zksync": {
        "id": "324",
        "rpc": "https://mainnet.era.zksync.io",
        "explorer": "https://block-explorer-api.mainnet.zksync.io/api",
    },
    "linea": {
        "id": "59144",
        "rpc": "https://rpc.linea.build",
        "explorer": "https://api.lineascan.build/api",
    },
    "scroll": {
        "id": "534352",
        "rpc": "https://rpc.scroll.io",
        "explorer": "https://api.scrollscan.com/api",
    },
    "mantle": {
        "id": "5000",
        "rpc": "https://rpc.mantle.xyz",
        "explorer": "https://api.mantlescan.xyz/api",
    },
    "blast": {
        "id": "81457",
        "rpc": "https://rpc.blast.io",
        "explorer": "https://api.blastscan.io/api",
    },
}

# Aliases for convenience  (e.g. "eth" -> "ethereum")
CHAIN_ALIASES: dict[str, str] = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "bnb": "bsc",
    "binance": "bsc",
    "matic": "polygon",
    "arb": "arbitrum",
    "op": "optimism",
    "avax": "avalanche",
    "ftm": "fantom",
    "zk": "zksync",
}

# ---------------------------------------------------------------------------
# Dangerous function selectors found in bytecode
# These are the first 4 bytes of keccak256(signature).
# Presence in bytecode indicates the contract MAY have the function.
# ---------------------------------------------------------------------------
DANGEROUS_SELECTORS: dict[str, dict] = {
    # --- Blacklist / Freeze ---
    "f9f92be4": {"name": "blacklist(address)", "risk": "blacklist", "severity": "HIGH"},
    "44337ea1": {"name": "addToBlacklist(address)", "risk": "blacklist", "severity": "HIGH"},
    "fe575a87": {"name": "isBlacklisted(address)", "risk": "blacklist", "severity": "MEDIUM"},
    "537df3b6": {"name": "removeFromBlacklist(address)", "risk": "blacklist", "severity": "MEDIUM"},
    "0ecb93c0": {"name": "setBlacklist(address,bool)", "risk": "blacklist", "severity": "HIGH"},
    "e47d6060": {"name": "addBlackList(address)", "risk": "blacklist", "severity": "HIGH"},
    "e4997dc5": {"name": "removeBlackList(address)", "risk": "blacklist", "severity": "MEDIUM"},
    "80f55605": {"name": "isBlackListed(address)", "risk": "blacklist", "severity": "MEDIUM"},
    "520dd2e2": {"name": "getBlackListStatus(address)", "risk": "blacklist", "severity": "MEDIUM"},
    "0af004a0": {"name": "addToBlackList(address[])", "risk": "blacklist", "severity": "HIGH"},
    "ab039497": {"name": "batchBlacklist(address[],bool)", "risk": "blacklist", "severity": "CRITICAL"},
    # --- Pause / Freeze transfers ---
    "8456cb59": {"name": "pause()", "risk": "pause", "severity": "MEDIUM"},
    "3f4ba83a": {"name": "unpause()", "risk": "pause", "severity": "INFO"},
    "136439dd": {"name": "lockTheSwap()", "risk": "pause", "severity": "HIGH"},
    # --- Ownership / Control ---
    "715018a6": {"name": "renounceOwnership()", "risk": "ownership", "severity": "INFO"},
    "f2fde38b": {"name": "transferOwnership(address)", "risk": "ownership", "severity": "LOW"},
    "a9059cbb": {"name": "transfer(address,uint256)", "risk": "standard", "severity": "INFO"},
    # --- Dangerous admin functions ---
    "40c10f19": {"name": "mint(address,uint256)", "risk": "mint", "severity": "MEDIUM"},
    "42966c68": {"name": "burn(uint256)", "risk": "burn", "severity": "LOW"},
    "79cc6790": {"name": "burnFrom(address,uint256)", "risk": "burn", "severity": "MEDIUM"},
    "a0712d68": {"name": "mint(uint256)", "risk": "mint", "severity": "MEDIUM"},
    # --- Fee manipulation ---
    "dd62ed3e": {"name": "allowance(address,address)", "risk": "standard", "severity": "INFO"},
    "c0246668": {"name": "setFee(address,bool)", "risk": "fee", "severity": "HIGH"},
    "28a46b6f": {"name": "setMaxTxAmount(uint256)", "risk": "limit", "severity": "MEDIUM"},
    "ea2f0b37": {"name": "excludeFromFee(address)", "risk": "fee", "severity": "LOW"},
    "437823ec": {"name": "includeInFee(address)", "risk": "fee", "severity": "MEDIUM"},
    # --- Self-destruct (bytecode opcode, not selector) ---
    # 0xff is SELFDESTRUCT opcode - checked separately in scanner
}

# EVM opcodes that indicate elevated risk when found in bytecode
DANGEROUS_OPCODES: dict[str, dict] = {
    "ff": {"name": "SELFDESTRUCT", "severity": "CRITICAL", "description": "Contract can destroy itself and drain all ETH"},
    "f4": {"name": "DELEGATECALL", "severity": "MEDIUM", "description": "Contract delegates execution to another address (proxy pattern)"},
    "f2": {"name": "CALLCODE", "severity": "HIGH", "description": "Legacy dangerous call pattern"},
}

# ---------------------------------------------------------------------------
# Risk scoring weights
# ---------------------------------------------------------------------------
RISK_WEIGHTS: dict[str, int] = {
    # GoPlus flags -> risk score contribution
    "is_honeypot": 90,
    "cannot_sell_all": 80,
    "cannot_buy": 60,
    "is_blacklisted": 70,
    "is_airdrop_scam": 85,
    "selfdestruct": 50,
    "hidden_owner": 40,
    "owner_change_balance": 60,
    "can_take_back_ownership": 40,
    "transfer_pausable": 30,
    "slippage_modifiable": 35,
    "personal_slippage_modifiable": 40,
    "trading_cooldown": 15,
    "anti_whale_modifiable": 15,
    "is_mintable": 20,
    "is_proxy": 15,
    "external_call": 10,
    # Bytecode findings
    "blacklist_function": 45,
    "selfdestruct_opcode": 50,
    "delegatecall_opcode": 10,
    # Holder analysis
    "whale_concentration": 30,
    "low_holder_count": 15,
    "unlocked_liquidity": 35,
    "low_liquidity": 25,
    # Tax
    "high_sell_tax": 40,
    "high_buy_tax": 30,
    "moderate_sell_tax": 15,
    "moderate_buy_tax": 10,
    # Source
    "not_open_source": 25,
    "not_verified": 20,
}

# Risk level thresholds
RISK_THRESHOLDS = {
    "CRITICAL": 70,
    "HIGH": 50,
    "MEDIUM": 30,
    "LOW": 15,
    # Below LOW -> SAFE
}

# ---------------------------------------------------------------------------
# Transaction detection patterns for the hook
# ---------------------------------------------------------------------------
TX_KEYWORDS = [
    "cast send",
    "eth_sendTransaction",
    "eth_sendRawTransaction",
    "eth_signTransaction",
    "swap(",
    "swapExact",
    "swapTokens",
    "addLiquidity",
    "removeLiquidity",
    "approve(",
    "transfer(",
    "transferFrom(",
    "multicall(",
    "execute(",
    "uniswap",
    "sushiswap",
    "pancakeswap",
    "1inch",
]

# Read-only calls that should NOT trigger the hook
READONLY_KEYWORDS = [
    "cast call",
    "eth_call",
    "balanceOf",
    "totalSupply",
    "decimals",
    "symbol",
    "name",
    "allowance",
    "getReserves",
]

# GoPlus API base
GOPLUS_BASE_URL = "https://api.gopluslabs.io/api/v1"
