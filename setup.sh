#!/usr/bin/env bash
# BetterDreamly setup script
# Run this once after unpacking to install all dependencies.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo ""
echo "========================================="
echo "  BetterDreamly Server Setup"
echo "  Bedrock 1.26.0 | API 4 Compatible"
echo "========================================="
echo ""

# Check Composer
if ! command -v composer &>/dev/null; then
    echo "[ERROR] Composer not found. Install from https://getcomposer.org"
    exit 1
fi

echo "[1/2] Installing Composer dependencies (bedrock-protocol 55.x for Bedrock 1.26.0)..."
composer install --no-dev --optimize-autoloader

echo ""
echo "[2/2] Verifying protocol version..."
PROTOCOL_FILE="vendor/pocketmine/bedrock-protocol/src/ProtocolInfo.php"
if [ -f "$PROTOCOL_FILE" ]; then
    PROTOCOL=$(grep "CURRENT_PROTOCOL" "$PROTOCOL_FILE" | grep -o '[0-9]\+' | head -1)
    if [ "$PROTOCOL" = "800" ]; then
        echo "    Protocol 800 (Bedrock 1.26.0) ✓"
    else
        echo "    WARNING: Expected protocol 800, got $PROTOCOL"
    fi
else
    echo "    WARNING: ProtocolInfo.php not found — run composer install"
fi

echo ""
echo "========================================="
echo "  Setup complete! Start with:"
echo "    ./start.sh"
echo "========================================="
echo ""
