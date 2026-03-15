#!/bin/bash
set -e

echo "========================================"
echo "  Phantom – Claude Ethical RedTeam"
echo "  Installer v1.2.0"
echo "========================================"
echo ""

# ─────────────────────────────────────────
# STEP 1 — Anthropic API key
# ─────────────────────────────────────────
echo "[ STEP 1 / 2 ] Anthropic API Key"
echo "-----------------------------------------"
echo "Get your key at : https://console.anthropic.com/settings/keys"
echo ""

while true; do
    read -rsp "Enter your ANTHROPIC_API_KEY : " api_key
    echo ""
    if [[ "$api_key" == sk-ant-* ]]; then
        break
    else
        echo "⚠️  Invalid key format (must start with sk-ant-). Try again."
    fi
done

# Write to .env and export for current session
echo "ANTHROPIC_API_KEY=$api_key" > .env
echo ""
echo "✅ API key saved to .env"
echo ""

# ─────────────────────────────────────────
# STEP 2 — Authorized scope
# ─────────────────────────────────────────
echo "[ STEP 2 / 2 ] Authorized Scope"
echo "-----------------------------------------"
echo "Define the target you are authorized to test."
echo ""

while true; do
    read -rp "Target URL (e.g. https://target.example.com) : " scope_url
    if [[ "$scope_url" == http* && "$scope_url" != "https://xxx" ]]; then
        break
    else
        echo "⚠️  Invalid URL or placeholder detected. Enter a real authorized target."
    fi
done

read -rp "Authorization note (e.g. 'Pentest contract signed 2026-03-15') : " scope_note
read -rp "Engagement date (e.g. 2026-03-15) : " scope_date

mkdir -p scopes
cat > scopes/current_scope.md <<EOF
**Scope autorisé :** $scope_url

**Autorisation :** $scope_note

**Date :** $scope_date
EOF

echo ""
echo "✅ Scope saved to scopes/current_scope.md"
echo ""

# ─────────────────────────────────────────
# System dependencies
# ─────────────────────────────────────────
echo "[ DEPS ] Installing system tools..."
echo "-----------------------------------------"
sudo apt update -q && sudo apt install -y golang-go ruby python3-pip curl git nmap nuclei sqlmap ffuf

# Bettercap
sudo apt install -y bettercap

# Zphisher (educational phishing templates)
git clone https://github.com/htr-tech/zphisher.git tools/zphisher_repo 2>/dev/null || true
chmod +x tools/zphisher_repo/zphisher.sh

# CyberStrikeAI
git clone https://github.com/Ed1s0nZ/CyberStrikeAI.git tools/cyberstrike_repo 2>/dev/null || true
mkdir -p bin
cd tools/cyberstrike_repo && go build -o ../../bin/cyberstrike ./cmd/cyberstrike && cd ../..

# Python dependencies
pip install -r requirements.txt -q

echo ""
echo "========================================"
echo "  ✅ Installation complete !"
echo "========================================"
echo ""
echo "  To start Phantom :"
echo ""
echo "    export \$(cat .env)"
echo "    export PATH=\$PATH:\$(pwd)/bin"
echo "    python agent/main.py"
echo ""
echo "  Scope : $(grep 'Scope' scopes/current_scope.md)"
echo "========================================"
