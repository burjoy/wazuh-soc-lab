#!/usr/bin/env bash
# Bring up the Wazuh 4.14.7 single-node stack.
#
# Usage: ./setup.sh [checkout-path]
#
# The version is pinned deliberately. Do not run `git pull` against the checkout
# during the lab; a version change invalidates the evidence already collected.

set -euo pipefail

WAZUH_TAG="v4.14.7"
DEST="${1:-$HOME/wazuh-docker}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon unreachable. Add this user to the docker group:" >&2
  echo "  sudo usermod -aG docker \$USER   # then log out and back in" >&2
  exit 1
fi

if [ ! -d "$DEST/.git" ]; then
  echo "Cloning wazuh-docker at $WAZUH_TAG into $DEST"
  git clone --depth 1 --branch "$WAZUH_TAG" \
    https://github.com/wazuh/wazuh-docker.git "$DEST"
fi

cd "$DEST/single-node"

# Certificates are generated once. A previous run may have left them root-owned.
if [ ! -f config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
  docker compose -f generate-indexer-certs.yml run --rm generator
fi

docker compose up -d

echo
echo "Waiting for the dashboard to answer on https://localhost ..."
for _ in $(seq 1 60); do
  if curl -ksf -o /dev/null https://localhost; then
    echo "dashboard is up"
    exit 0
  fi
  sleep 5
done

echo "dashboard did not answer within 5 minutes; check: docker compose logs -f" >&2
exit 1
