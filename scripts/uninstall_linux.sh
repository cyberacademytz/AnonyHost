#!/usr/bin/env bash
set -euo pipefail
APP="$HOME/.local/share/anonyhost-app"; DATA="${XDG_DATA_HOME:-$HOME/.local/share}/anonyhost"
if [ -x "$APP/scripts/anonyhost" ]; then "$APP/scripts/anonyhost" --stop-all || true; fi
rm -rf "$APP" "$HOME/.local/bin/anonyhost" "$HOME/.local/bin/anonyhost-panel" "$HOME/.local/share/applications/anonyhost.desktop" "$HOME/.local/share/applications/anonyhost-dashboard.desktop"
rm -f "$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")/anonyhost.desktop"
echo "Program removed. Your data (website, settings, onion keys) is still in: $DATA"
read -r -p "Delete it too? THIS PERMANENTLY LOSES YOUR ONION ADDRESS. Type DELETE to confirm: " c
if [ "$c" = "DELETE" ]; then rm -rf "$DATA"; echo "Data deleted."; else echo "Data kept."; fi
