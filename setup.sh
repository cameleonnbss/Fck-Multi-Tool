#!/usr/bin/env bash
# FCK MULTI TOOL - setup (Linux / macOS)
set -e
cd "$(dirname "$0")"

echo ""
echo "   ============================================="
echo "      FCK MULTI TOOL - Installation"
echo "   ============================================="
echo ""

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

echo "   [~] Mise a jour de pip..."
$PY -m pip install --upgrade pip --quiet || true

echo "   [~] Installation des dependances..."
$PY -m pip install -r requirements.txt --quiet || true

echo "   [~] Verification des modules..."
$PY main.py --selftest

echo ""
echo "   [+] Setup termine. Lancez ./start.sh pour ouvrir le tool."
echo ""
