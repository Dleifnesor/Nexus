#!/usr/bin/env bash
# Nexus installer for Kali / Parrot Linux.
# Installs Nexus and its prerequisites (Docker, Ollama, core Kali tools, Playwright).
set -euo pipefail

echo "[*] Nexus installer for Kali/Parrot"

if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

echo "[*] Updating apt and installing base packages..."
$SUDO apt-get update -y
$SUDO apt-get install -y python3 python3-pip python3-venv git curl \
  nmap nikto whatweb theharvester || true

echo "[*] Installing Docker (for isolated dynamic tools)..."
if ! command -v docker >/dev/null 2>&1; then
  curl -fsSL https://get.docker.com | $SUDO sh
  $SUDO usermod -aG docker "${SUDO_USER:-$USER}" || true
  echo "[!] You may need to log out/in for docker group membership to apply."
fi

echo "[*] Installing Ollama (local LLM backend)..."
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
echo "[*] Pulling default model (llama3.1:8b)..."
ollama pull llama3.1:8b || echo "[!] Pull the model manually later: ollama pull llama3.1:8b"

echo "[*] Creating virtualenv and installing Nexus..."
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
pip install --upgrade pip
pip install -e ".[pdf,web]"

echo "[*] Installing Playwright Chromium for OSINT..."
python -m playwright install --with-deps chromium || echo "[!] Playwright browser install failed; OSINT browser disabled."

echo "[*] Running prerequisite checks..."
nexus --scope --check || true

cat <<'EOF'

[+] Install complete.

Usage:
  # Authorized engagement (prompts for scope):
  nexus --scope

  # Provide scope non-interactively:
  nexus --scope --scope-entry 10.0.0.0/24 --scope-entry example.com

  # Isolated lab (unrestricted):
  nexus --sandbox --scope-entry 10.0.0.0/24 --yes

Reports are written to ./nexus-out/reports/.
EOF
