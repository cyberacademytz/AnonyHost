#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
# Stops the AnonyHost dashboard AND the hosted website (Tor + Nginx).
exec "$(dirname "$(readlink -f "$0")")/anonyhost" --stop-all
