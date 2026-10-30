#!/usr/bin/env bash
# Start the victim VM (Ubuntu 24.04 cloud image, QEMU/KVM, user-mode networking).
#
# No sudo required. The guest reaches the host through the slirp gateway 10.0.2.2;
# the host reaches the guest through forwarded ports 2222 (ssh) and 8080 (http).

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

BASE_IMG="images/noble-server-cloudimg-amd64.img"
DISK="disk.qcow2"
KEY="keys/id_ed25519"
SEED_DIR="seed"
SEED_PORT=8000

mkdir -p images keys "$SEED_DIR"

if [ ! -f "$BASE_IMG" ]; then
  echo "Downloading Ubuntu 24.04 cloud image (~600 MB)..."
  curl -L --fail --progress-bar -o "$BASE_IMG" \
    https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
fi

if [ ! -f "$KEY" ]; then
  echo "Generating lab SSH key"
  ssh-keygen -t ed25519 -N '' -f "$KEY" -C soc-l1-lab >/dev/null
fi

PUBKEY="$(cat "$KEY.pub")"
sed "s|__SSH_PUBKEY__|$PUBKEY|" "$SEED_DIR/user-data.tmpl" > "$SEED_DIR/user-data"

if [ ! -f "$DISK" ]; then
  echo "Creating 20G overlay disk"
  qemu-img create -f qcow2 -F qcow2 -b "$BASE_IMG" "$DISK" 20G >/dev/null
fi

if pgrep -f "http.server $SEED_PORT" >/dev/null 2>&1; then
  echo "Seed server already running on 127.0.0.1:$SEED_PORT"
else
  python3 -m http.server "$SEED_PORT" --bind 127.0.0.1 --directory "$SEED_DIR" \
    >/dev/null 2>&1 &
  sleep 1
fi

qemu-system-x86_64 \
  -name soc-victim \
  -enable-kvm -m 1536 -smp 2 \
  -drive file="$DISK",if=virtio \
  -netdev user,id=net0,hostfwd=tcp:127.0.0.1:2222-:22,hostfwd=tcp:127.0.0.1:8080-:80 \
  -device virtio-net-pci,netdev=net0 \
  -smbios "type=1,serial=ds=nocloud-net;s=http://10.0.2.2:${SEED_PORT}/" \
  -monitor unix:"$HERE/monitor.sock",server,nowait \
  -display none -serial file:"$HERE/console.log" \
  -daemonize

echo
echo "VM started."
echo "  console : $HERE/console.log"
echo "  ssh     : ssh -i $KEY -p 2222 analyst@127.0.0.1"
echo "  http    : http://127.0.0.1:8080"
echo "  monitor : $HERE/monitor.sock"
