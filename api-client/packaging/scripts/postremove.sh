#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl stop vaultls-agent 2>/dev/null || true
  systemctl disable vaultls-agent 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi
