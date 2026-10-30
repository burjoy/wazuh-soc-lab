#!/usr/bin/env bash
# Run INSIDE the victim VM, after cloud-init completes.
#
#   scp -i keys/id_ed25519 -P 2222 provision-agent.sh analyst@127.0.0.1:/tmp/
#   ssh -i keys/id_ed25519 -p 2222 analyst@127.0.0.1 'sudo bash /tmp/provision-agent.sh'
#
# Installs the Wazuh agent, loads audit rules, and narrows Suricata to a small
# rule set. The manager is the QEMU gateway, 10.0.2.2.

set -euo pipefail

WAZUH_MANAGER="${WAZUH_MANAGER:-10.0.2.2}"
WAZUH_VERSION="4.14.7-1"

echo "==> checking manager reachability at ${WAZUH_MANAGER}:1514"
if ! timeout 5 bash -c "cat < /dev/null > /dev/tcp/${WAZUH_MANAGER}/1514" 2>/dev/null; then
  echo "manager not reachable; start the Wazuh stack first" >&2
  exit 1
fi

echo "==> Wazuh agent"
if ! dpkg -s wazuh-agent >/dev/null 2>&1; then
  curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
  echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
    > /etc/apt/sources.list.d/wazuh.list
  apt-get update -qq
  WAZUH_MANAGER="$WAZUH_MANAGER" apt-get install -y "wazuh-agent=${WAZUH_VERSION}"
fi

echo "==> auditd rules"
cat > /etc/audit/rules.d/50-wazuh.rules <<'EOF'
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /etc/cron.d -p wa -k persistence
-w /var/www/html -p wa -k webroot
-a always,exit -F arch=b64 -S execve -k exec
EOF
augenrules --load
systemctl restart auditd || true

echo "==> Suricata: restrict to the lab network"
if ! grep -q 'HOME_NET: "\[10.0.2.0/24\]"' /etc/suricata/suricata.yaml; then
  cp /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.bak
  sed -i 's|^\(\s*HOME_NET:\s*\).*|\1"[10.0.2.0/24]"|' /etc/suricata/suricata.yaml
  sed -i 's|^\(\s*EXTERNAL_NET:\s*\).*|\1"!$HOME_NET"|' /etc/suricata/suricata.yaml
fi

echo "==> Suricata: enable a narrow rule set"
suricata-update update-sources >/dev/null 2>&1 || true
suricata-update >/dev/null 2>&1 || true
cat > /etc/suricata/disable.conf <<'EOF'
re:.*
EOF
cat > /etc/suricata/enable.conf <<'EOF'
re:^(emerging-scan|emerging-web-application-attack|emerging-web-server|emerging-dns)
EOF
suricata-update >/dev/null 2>&1 || true

suricata -T -c /etc/suricata/suricata.yaml >/tmp/suricata-test.log 2>&1 || {
  echo "suricata config test failed; see /tmp/suricata-test.log" >&2
  exit 1
}
systemctl restart suricata

echo "==> Suricata: filter eve.json down to alert/http/dns"
cat > /usr/local/bin/suricata-wazuh-filter.sh <<'EOF'
#!/usr/bin/env bash
exec tail -F /var/log/suricata/eve.json \
  | jq -c 'select(.event_type=="alert" or .event_type=="http" or .event_type=="dns")' \
  >> /var/log/suricata/wazuh.json
EOF
chmod +x /usr/local/bin/suricata-wazuh-filter.sh

cat > /etc/systemd/system/suricata-wazuh-filter.service <<'EOF'
[Unit]
Description=Filter Suricata eve.json for Wazuh ingestion
After=suricata.service

[Service]
ExecStart=/usr/local/bin/suricata-wazuh-filter.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now suricata-wazuh-filter

echo "==> Wazuh agent: forward filtered Suricata events"
python3 - <<'PY'
path = "/var/ossec/etc/ossec.conf"
block = """  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/wazuh.json</location>
  </localfile>
"""
text = open(path).read()
if "suricata/wazuh.json" not in text:
    text = text.replace("</ossec_config>", block + "</ossec_config>")
    open(path, "w").write(text)
PY

systemctl daemon-reload
systemctl enable --now wazuh-agent
systemctl restart wazuh-agent

echo "==> status"
systemctl is-active wazuh-agent suricata suricata-wazuh-filter auditd nginx
/var/ossec/bin/wazuh-control status | head -5
