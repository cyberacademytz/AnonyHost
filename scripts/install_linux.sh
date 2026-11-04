#!/usr/bin/env bash
# AnonyHost installer for Ubuntu/Debian. Only apt uses sudo; the rest stays in your home folder.
set -euo pipefail
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in *ubuntu*|*debian*) ;; *) echo "Unsupported distribution: ${ID:-unknown}. Ubuntu or Debian is required."; exit 1;; esac
[ "$(id -u)" -ne 0 ] || { echo "Run this as your normal user, not as root."; exit 1; }
SRC="$(cd "$(dirname "$0")/.." && pwd)"
APP="$HOME/.local/share/anonyhost-app"; DATA="${XDG_DATA_HOME:-$HOME/.local/share}/anonyhost"
cat <<MSG
AnonyHost will:
  1. sudo apt-get install tor nginx python3-venv python3-tk      (system packages)
  2. copy the program to $APP and create its Python environment
  3. add AnonyHost to your Applications menu and an 'anonyhost' command
Your website, settings and onion keys live in $DATA and are never removed by updates.
It does NOT change your system tor/nginx services or any file in /etc.
MSG
read -r -p "Continue? [y/N] " a; [[ "$a" =~ ^[Yy]$ ]] || exit 1
sudo apt-get update && sudo apt-get install -y tor nginx python3-venv python3-tk
if [ -x "$APP/scripts/anonyhost" ]; then "$APP/scripts/anonyhost" --stop || true; fi   # stop the old dashboard (hosting keeps running)
pkill -f "$APP/panel.py" 2>/dev/null || true                                          # close an old control panel window
mkdir -p "$APP" "$HOME/.local/bin" "$HOME/.local/share/applications"
tar -C "$SRC" --exclude=.venv --exclude=data --exclude=__pycache__ --exclude=.pytest_cache -cf - . | tar -C "$APP" -xf -
python3 -m venv "$APP/.venv" && "$APP/.venv/bin/pip" install -q -r "$APP/requirements.txt"
chmod +x "$APP/scripts/"*
if [ -e "$DATA" ]; then
  read -r -p "Existing AnonyHost data found in $DATA. Reset it to defaults first (your onion keys are kept)? [y/N] " r
  if [[ "$r" =~ ^[Yy]$ ]]; then "$APP/scripts/anonyhost" --factory-reset || true; fi
fi
ln -sf "$APP/scripts/anonyhost" "$HOME/.local/bin/anonyhost"
ln -sf "$APP/scripts/anonyhost-panel" "$HOME/.local/bin/anonyhost-panel"
mk_entry() {  # name, comment, command, file
  cat > "$HOME/.local/share/applications/$4" <<DESK
[Desktop Entry]
Type=Application
Name=$1
Comment=$2
Exec=$3
Icon=$APP/frontend/static/images/icon.png
Terminal=false
Categories=Network;Utility;
DESK
  chmod +x "$HOME/.local/share/applications/$4"
}
mk_entry "AnonyHost Control Panel" "Start, stop and monitor AnonyHost" "$APP/scripts/anonyhost-panel" anonyhost.desktop
mk_entry "AnonyHost Dashboard" "Open the AnonyHost dashboard" "$APP/scripts/anonyhost" anonyhost-dashboard.desktop
if [ -d "$SRC/data" ] && [ ! -e "$DATA" ]; then
  read -r -p "Found data from an earlier run in $SRC/data. Copy it (keeps your onion address)? [y/N] " m
  if [[ "$m" =~ ^[Yy]$ ]]; then cp -a "$SRC/data" "$DATA"; fi
fi
read -r -p "Also put a shortcut on your Desktop? [y/N] " s
if [[ "$s" =~ ^[Yy]$ ]]; then
  D="$(xdg-user-dir DESKTOP 2>/dev/null || echo "$HOME/Desktop")"; mkdir -p "$D"
  cp "$HOME/.local/share/applications/anonyhost.desktop" "$D/"; chmod +x "$D/anonyhost.desktop"
  gio set "$D/anonyhost.desktop" metadata::trusted true 2>/dev/null || true
fi
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true
echo "Done. Open AnonyHost from your Applications menu (or run: anonyhost)."
