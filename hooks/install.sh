#!/usr/bin/env bash
# CryptoGuard Hook Installer
# Installs the pre-transaction safety hook for Claude Code and other AI agents.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/momenbasel/CryptoGuard/main/hooks/install.sh | bash
#   # or
#   ./hooks/install.sh

set -euo pipefail

BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${BOLD}CryptoGuard Installer${NC}"
echo "=============================="
echo ""

# Check Python version
if ! command -v python3 &> /dev/null; then
    echo -e "${RED}Error: Python 3 is required but not found.${NC}"
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo -e "Python version: ${GREEN}${PYTHON_VERSION}${NC}"

# Install the package
echo ""
echo -e "${BOLD}Installing CryptoGuard...${NC}"
pip install cryptoguard 2>/dev/null || pip3 install cryptoguard

# Verify installation
if ! command -v cryptoguard &> /dev/null; then
    echo -e "${YELLOW}Warning: 'cryptoguard' not found in PATH after install.${NC}"
    echo "You may need to add pip's bin directory to your PATH."
    echo "Trying: python -m cryptoguard --version"
    python3 -m cryptoguard --version
fi

# Install Claude Code hook
echo ""
echo -e "${BOLD}Installing Claude Code hook...${NC}"

CLAUDE_SETTINGS="$HOME/.claude/settings.json"

if [ -f "$CLAUDE_SETTINGS" ]; then
    # Check if already installed
    if grep -q "cryptoguard" "$CLAUDE_SETTINGS" 2>/dev/null; then
        echo -e "${YELLOW}CryptoGuard hook is already installed in Claude Code.${NC}"
    else
        cryptoguard install-hook
    fi
else
    echo "Creating Claude Code settings directory..."
    mkdir -p "$HOME/.claude"
    cryptoguard install-hook
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo ""
echo "CryptoGuard will now automatically protect you from:"
echo "  - Honeypot tokens (can't sell after buying)"
echo "  - Blacklist contracts (can freeze your funds)"
echo "  - Rug pulls (unlocked liquidity, whale dumps)"
echo "  - Scam tokens (airdrop scams, fake tokens)"
echo "  - Dangerous taxes (hidden or modifiable fees)"
echo ""
echo "Usage:"
echo "  cryptoguard check 0x<address> --chain ethereum"
echo "  cryptoguard check 0x<address> --chain bsc"
echo ""
echo "The hook runs automatically when you use Claude Code, Codex,"
echo "or any compatible AI agent to execute crypto transactions."
echo ""
echo "To disable temporarily: export CRYPTOGUARD_DISABLE=1"
echo "To uninstall: cryptoguard uninstall-hook && pip uninstall cryptoguard"
