#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl stop vaultls-agent 2>/dev/null || true
  systemctl disable vaultls-agent 2>/dev/null || true
  systemctl daemon-reload 2>/dev/null || true
fi
if [ "$1" = "purge" ]; then
  # Remove only the anchors recorded in the agent's own state file. Every entry
  # is a "<sha256>": "<filename>" pair on its own line (json.MarshalIndent).
  state=/etc/ssl/vaultls/ca-trust.json
  if [ -f "$state" ]; then
    sed -n 's/.*"[0-9a-f]\{64\}"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$state" |
      while read -r f; do
        [ -n "$f" ] || continue
        rm -f "/usr/local/share/ca-certificates/$f" "/etc/pki/ca-trust/source/anchors/$f"
      done
    rm -f "$state"
    if command -v update-ca-certificates >/dev/null 2>&1; then
      update-ca-certificates >/dev/null 2>&1 || true
    elif command -v update-ca-trust >/dev/null 2>&1; then
      update-ca-trust extract >/dev/null 2>&1 || true
    fi
  fi
fi
