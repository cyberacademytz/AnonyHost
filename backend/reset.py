# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
import re, shutil
from pathlib import Path

def reset_settings(base):
    (Path(base) / "settings.json").unlink(missing_ok=True)

def factory_reset(base, delete_keys=False):
    """Return the data folder to its first-run state.
    Always keeps backups/. Keeps onion-service/ (the .onion address) unless delete_keys is True.
    Tor and Nginx must be stopped by the caller first."""
    b = Path(base)
    for n in ("settings.json", "admin.json", "secret.key", "torrc", "nginx.conf", "php-fpm.conf", "proxy_local_host", "deployed_at"):
        (b / n).unlink(missing_ok=True)
    for n in ["tor-data", "site", "site.new", "site.old", "window-profile", "runtime"] + (["onion-service"] if delete_keys else []):
        shutil.rmtree(b / n, ignore_errors=True)
    (b / "site").mkdir(exist_ok=True)
    for f in (b / "logs").glob("*"):  # truncate: a running app may hold these files open
        if re.search(r"\.\d+$", f.name):
            f.unlink(missing_ok=True)
        elif f.is_file():
            open(f, "w").close()
    for n in ("tor.pid", "nginx.pid", "php-fpm.pid", "app.pid", "app.port", "hosting.want"):
        (b / "run" / n).unlink(missing_ok=True)
    for d in (b / "run").glob("*_temp"):
        shutil.rmtree(d, ignore_errors=True)
