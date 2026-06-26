#!/bin/sh
set -e
systemctl daemon-reload || true
mkdir -p /etc/ssl/vaultls
if [ ! -f /etc/vaultls/config.yaml ]; then
  echo "vaultls-agent installed. Configure it with:"
  echo "  sudo vaultls-agent setup"
  echo "or copy /etc/vaultls/config.example.yaml to /etc/vaultls/config.yaml"
else
  systemctl try-restart vaultls-agent || true
fi
