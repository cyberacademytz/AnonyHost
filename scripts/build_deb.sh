#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
# Builds the Debian package:  scripts/build_deb.sh [output-folder]     (default: ./dist)
# Needs only dpkg-deb, tar, gzip and md5sum. Set MAINTAINER="Name <email>" to change the maintainer field.
# The same source gives the same package (set SOURCE_DATE_EPOCH to pick the file dates).
set -euo pipefail
export LC_ALL=C
SRC="$(cd "$(dirname "$0")/.." && pwd)"
PKG=anonyhost
VERSION="$(sed -n 's/^VERSION *= *"\(.*\)".*/\1/p' "$SRC/config/settings.py")"
[ -n "$VERSION" ] || { echo "Could not read VERSION from config/settings.py" >&2; exit 1; }
MAINTAINER="${MAINTAINER:-AnonyHost <anonyhost@localhost>}"
EPOCH="${SOURCE_DATE_EPOCH:-$(stat -c %Y "$SRC/config/settings.py")}"
OUT="${1:-$SRC/dist}"
DEB="$OUT/${PKG}_${VERSION}_all.deb"
command -v dpkg-deb >/dev/null || { echo "dpkg-deb is required (apt install dpkg-dev)." >&2; exit 1; }

STAGE="$(mktemp -d)"; trap 'rm -rf "$STAGE"' EXIT
R="$STAGE/root"
D="$SRC/packaging/debian"
install -d -m 755 "$R/DEBIAN" "$R/opt/anonyhost" "$R/usr/bin" "$R/usr/lib/anonyhost" "$R/usr/share/applications" \
    "$R/usr/share/doc/$PKG" "$R/usr/share/man/man1" "$R/usr/share/icons/hicolor/256x256/apps"

# 1. the program (no tests, data, caches or developer scripts)
tar -C "$SRC" --exclude='__pycache__' --exclude='*.pyc' -cf - app.py launcher.py config backend frontend | tar -C "$R/opt/anonyhost" -xf -

# 2. commands, helper, menu entries, icon
install -m 755 "$D/anonyhost" "$D/anonyhost-stop" "$R/usr/bin/"
install -m 755 "$D/system-services.sh" "$R/usr/lib/anonyhost/"
install -m 644 "$D/anonyhost-dashboard.desktop" "$R/usr/share/applications/"
install -m 644 "$SRC/frontend/static/images/icon.png" "$R/usr/share/icons/hicolor/256x256/apps/anonyhost.png"

# 3. documentation: manual page, copyright, changelog, readme
gzip -9n -c "$D/anonyhost.1" > "$R/usr/share/man/man1/anonyhost.1.gz"
for alias in anonyhost-stop; do printf '.so man1/anonyhost.1\n' | gzip -9n > "$R/usr/share/man/man1/$alias.1.gz"; done
# Debian copyright file: the OFL text (for the bundled font) is taken from the license file that ships with the font
OFL_TEXT="$(awk '/^SIL OPEN FONT LICENSE/ {on=1} on {if ($0 ~ /^[[:space:]]*$/) print " ."; else print " " $0}' "$SRC/frontend/static/fonts/OFL.txt")"
awk -v text="$OFL_TEXT" '{ if ($0 == "@OFL_TEXT@") print text; else print }' "$D/copyright.in" > "$R/usr/share/doc/$PKG/copyright"
DATE="$(date -u -d "@$EPOCH" -R)"
sed -e "s|@VERSION@|$VERSION|g" -e "s|@MAINTAINER@|$MAINTAINER|g" -e "s|@DATE@|$DATE|g" "$D/changelog.in" | gzip -9n > "$R/usr/share/doc/$PKG/changelog.gz"
gzip -9n -c "$SRC/README.md" > "$R/usr/share/doc/$PKG/README.md.gz"

# 4. permissions: root-owned, files 644, folders 755, programs 755
find "$R" -type d -exec chmod 755 {} +
find "$R" -type f -exec chmod 644 {} +
chmod 755 "$R/usr/bin/"* "$R/usr/lib/anonyhost/system-services.sh"
for f in $(find "$R/opt/anonyhost" -maxdepth 1 -name '*.py'); do head -c2 "$f" | grep -q '#!' && chmod 755 "$f"; done

# 5. control data
SIZE="$(du -sk --apparent-size "$R" | cut -f1)"
sed -e "s|@VERSION@|$VERSION|" -e "s|@SIZE@|$SIZE|" -e "s|@MAINTAINER@|$MAINTAINER|" "$D/control.in" > "$R/DEBIAN/control"
install -m 755 "$D/postinst" "$D/prerm" "$D/postrm" "$R/DEBIAN/"
(cd "$R" && find . -type f -not -path './DEBIAN/*' -printf '%P\0' | sort -z | xargs -0 md5sum) > "$R/DEBIAN/md5sums"
chmod 644 "$R/DEBIAN/md5sums" "$R/DEBIAN/control"

# 6. reproducible timestamps, then build
find "$R" -exec touch -h -d "@$EPOCH" {} +
mkdir -p "$OUT"
SOURCE_DATE_EPOCH="$EPOCH" dpkg-deb --root-owner-group -Zxz --build "$R" "$DEB" >/dev/null   # the variable also fixes the archive header dates
echo "Built $DEB"
dpkg-deb --field "$DEB" Package Version Architecture Installed-Size Depends
echo "sha256: $(sha256sum "$DEB" | cut -d' ' -f1)"
