#!/usr/bin/env bash
# Run a Greenbone/OpenVAS (GVM) scan against a target via gvm-cli over the local socket.
# Requires a configured GVM (see install_gvm.sh) and gvm-cli on PATH.
#
# Usage: gvm_scan.sh <target> [port-list-id]
#   <target>         IP, CIDR, or hostname to scan.
#   [port-list-id]   GVM port list id (optional; defaults to "33d0cd82-57c6-11e1-8ed1-406186ea4fc5",
#                    the "All IANA assigned TCP" port list).
set -euo pipefail

TARGET="${1:?usage: gvm_scan.sh <target> [port-list-id]}"
PORT_LIST_ID="${2:-33d0cd82-57c6-11e1-8ed1-406186ea4fc5}"
SOCKET="/run/gvmd/gvmd.sock"

gvm() {
    gvm-cli socket --socketpath "$SOCKET" --xml "$1"
}

TASK_NAME="nexus-scan-$(date +%s)"

echo "[*] Creating target for $TARGET..."
TARGET_ID="$(gvm "<commands><create_target><name>$TASK_NAME</name><hosts>$TARGET</hosts><port_list id=\"$PORT_LIST_ID\"/></create_target></commands>" \
    | sed -n 's/.*id="\([a-f0-9-]*\)".*/\1/p' | head -n1)"

echo "[*] Creating task $TASK_NAME (target id $TARGET_ID)..."
TASK_ID="$(gvm "<commands><create_task><name>$TASK_NAME</name><comment>Nexus scan</comment><config id=\"daba56c8-73ec-11df-a475-002264764cea\"/><target id=\"$TARGET_ID\"/></create_task></commands>" \
    | sed -n 's/.*id="\([a-f0-9-]*\)".*/\1/p' | head -n1)"

echo "[*] Starting task $TASK_ID..."
gvm "<commands><start_task task_id=\"$TASK_ID\"/></commands>"

echo "[*] Polling for completion..."
for _ in $(seq 1 720); do
    STATUS="$(gvm "<commands><get_tasks task_id=\"$TASK_ID\"/></commands>" | sed -n 's/.*<status>\(.*\)<\/status>.*/\1/p' | head -n1)"
    if [ "$STATUS" = "Done" ]; then
        break
    fi
    sleep 15
done

echo "[*] Fetching report..."
REPORT_ID="$(gvm "<commands><get_tasks task_id=\"$TASK_ID\"/></commands>" | sed -n 's/.*<last_report>.*id="\([a-f0-9-]*\)".*/\1/p' | head -n1)"
gvm "<commands><get_reports report_id=\"$REPORT_ID\" filter=\"apply_overrides=0 min_qod=70\"/></commands>"

echo "[+] Scan complete (task $TASK_ID, report $REPORT_ID)."
