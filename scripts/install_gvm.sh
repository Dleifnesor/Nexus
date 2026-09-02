#!/usr/bin/env bash
# Install and initialize Greenbone Vulnerability Manager (GVM / OpenVAS).
# Idempotent: safe to run repeatedly. Targets Kali / Debian.
set -euo pipefail

if ! command -v gvm-cli >/dev/null 2>&1; then
    echo "[*] Installing GVM packages (this can take a while)..."
    sudo apt-get update
    sudo apt-get install -y gvm
fi

if ! command -v gvm-check-setup >/dev/null 2>&1; then
    echo "[!] 'gvm' package installed but setup tools are missing; re-run after reboot."
    exit 1
fi

# Run the one-time feed download / setup only once.
if [ ! -f /var/lib/gvm/.nexus_setup_done ]; then
    echo "[*] Running gvm-setup (downloads vulnerability feeds; can take 30+ minutes)..."
    sudo gvm-setup || true
    sudo touch /var/lib/gvm/.nexus_setup_done
fi

echo "[*] Starting GVM services..."
sudo gvm-start || true
sleep 10

echo "[*] Verifying setup..."
sudo gvm-check-setup || true

cat <<'EOF'
[+] GVM is ready.
    Default admin user: admin
    Set the admin password with:
      sudo runuser -u _gvm -- gvmd --user=admin --new-password='<password>'
    The unix socket is at /run/gvmd/gvmd.sock (used by gvm-cli).
    To run a scan from Nexus, the gvm tool invokes:
      gvm-cli socket --socketpath /run/gvmd/gvmd.sock --xml "<commands><get_tasks/></commands>"
    A full scan helper is available at scripts/gvm_scan.sh.
EOF
