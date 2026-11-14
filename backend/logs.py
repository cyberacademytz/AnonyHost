# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Names of the logs the dashboard can show, and a safe way to read the end of them."""
import re
from pathlib import Path

LOGS = {"AnonyHost": "app.log", "Launcher": "launcher.log", "Tor": "tor.log", "Nginx errors": "nginx-error.log",
        "Site app": "site-app.log", "PHP-FPM": "php-fpm.log", "Auto-fix": "autofix.log", "Install": "install.log"}
ERR = re.compile(r"(?i)\b(err|error|fail|failed|alert|emerg|crit|critical|denied|traceback)\b")
WARN = re.compile(r"(?i)\bwarn(ing)?\b")

def tail_log(base, name, needle="", errors_only=False, max_lines=400):
    """Last lines of one of the known logs (LOGS), optionally filtered. Safe for any `name`."""
    if name not in LOGS:
        return []
    try:
        with open(Path(base) / "logs" / LOGS[name], "rb") as f:
            f.seek(0, 2); f.seek(max(0, f.tell() - 131072))
            lines = f.read().decode("utf-8", "replace").splitlines()
    except OSError:
        return []
    n = needle.lower()
    return [l for l in lines if (not n or n in l.lower()) and (not errors_only or ERR.search(l))][-max_lines:]
