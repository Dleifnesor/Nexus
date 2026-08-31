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

# Resolve the Nexus project root (parent of this script's directory) so the
# install location never depends on the caller's working directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEXUS_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="$NEXUS_DIR/venv"

# --- OS detection -----------------------------------------------------------
IS_KALI=false
if [[ -r /etc/os-release ]] && grep -qi 'kali' /etc/os-release; then
  IS_KALI=true
fi

echo "[*] Updating apt and installing base packages..."
$SUDO apt-get update -y
$SUDO apt-get install -y python3 python3-pip python3-venv git curl \
  nmap nikto whatweb theharvester || true

echo "[*] Installing Docker (for isolated dynamic tools)..."
if ! command -v docker >/dev/null 2>&1; then
  if $IS_KALI; then
    # get.docker.com does not support Kali: it registers a Debian apt repo
    # using the kali-rolling codename, which has no Release file. Kali ships
    # Docker as 'docker.io' in its own repos - install that instead.
    echo "[*] Kali detected - installing docker.io from Kali repos..."
    $SUDO apt-get install -y docker.io
  else
    if ! curl -fsSL https://get.docker.com | $SUDO sh; then
      echo "[!] get.docker.com failed; falling back to distro docker.io package..."
      $SUDO apt-get install -y docker.io
    fi
  fi
  $SUDO usermod -aG docker "${SUDO_USER:-$USER}" || true
  echo "[!] You may need to log out/in for docker group membership to apply."
fi
if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl enable --now docker 2>/dev/null || true
fi

echo "[*] Installing Ollama (local LLM backend)..."
if ! command -v ollama >/dev/null 2>&1; then
  curl -fsSL https://ollama.com/install.sh | sh
fi
echo "[*] Pulling default model (llama3.1:8b)..."
ollama pull llama3.1:8b || echo "[!] Pull the model manually later: ollama pull llama3.1:8b"

echo "[*] Creating virtualenv at $VENV_DIR and installing Nexus..."
python3 -m venv "$VENV_DIR"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate"
pip install --upgrade pip
pip install -e "$NEXUS_DIR[pdf,web]"

echo "[*] Installing nexus launcher (/usr/local/bin/nexus)..."
# Older installers left a launcher pointing at a venv path that is no longer
# created. Always (re)write it so it resolves the venv we just made.
if [[ $EUID -eq 0 || -n "$SUDO" || -w /usr/local/bin ]]; then
  $SUDO tee /usr/local/bin/nexus >/dev/null <<EOF
#!/usr/bin/env bash
# Nexus launcher - runs the Nexus CLI from the project virtualenv.
VENV_DIR="$VENV_DIR"
NEXUS_BIN="\$VENV_DIR/bin/nexus"
if [[ ! -x "\$NEXUS_BIN" ]]; then
  echo "Error: Nexus CLI not found at \$NEXUS_BIN" >&2
  echo "The virtualenv may be missing - re-run the installer:" >&2
  echo "  cd $NEXUS_DIR && bash scripts/install.sh" >&2
  exit 1
fi
exec "\$NEXUS_BIN" "\$@"
EOF
  $SUDO chmod +x /usr/local/bin/nexus
  hash -r 2>/dev/null || true
else
  echo "[!] Cannot write /usr/local/bin - activate the venv manually: source $VENV_DIR/bin/activate"
fi

echo "[*] Installing Playwright Chromium for OSINT..."
python -m playwright install --with-deps chromium || echo "[!] Playwright browser install failed; OSINT browser disabled."

echo "[*] Running prerequisite checks..."
if command -v nexus >/dev/null 2>&1; then
  nexus --scope --check || true
else
  "$VENV_DIR/bin/nexus" --scope --check || echo "[!] Run 'source $VENV_DIR/bin/activate' to use nexus from this shell."
fi

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
