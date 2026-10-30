#!/usr/bin/env bash
# QEMU monitor snapshot helper.
#
#   ./snapshot.sh save baseline
#   ./snapshot.sh load baseline
#
# Snapshots are taken with the VM running (internal qcow2 snapshots), which keeps
# the lab fast: revert after capturing evidence, no reboot needed.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOCK="$HERE/monitor.sock"
ACTION="${1:-}"
NAME="${2:-}"

if [ -z "$ACTION" ] || [ -z "$NAME" ]; then
  echo "usage: $0 save|load <snapshot-name>" >&2
  exit 1
fi

case "$ACTION" in
  save) CMD="savevm $NAME" ;;
  load) CMD="loadvm $NAME" ;;
  *) echo "action must be save or load" >&2; exit 1 ;;
esac

python3 - "$SOCK" "$CMD" <<'PY'
import socket, sys, time

sock_path, command = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(5)
s.connect(sock_path)
time.sleep(0.2)
s.recv(65536)
s.sendall((command + "\n").encode())
time.sleep(0.5)
out = s.recv(65536).decode(errors="replace")
s.close()
print(out)
if "Error" in out or "error" in out:
    sys.exit(1)
PY
