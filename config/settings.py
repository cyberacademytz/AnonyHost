# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
import json, os
from pathlib import Path

VERSION = "0.9.0"

def build_id():
    """Changes whenever the program files change, so a stale running copy can be detected and replaced."""
    root = Path(__file__).resolve().parent.parent
    files = [root / "app.py", root / "launcher.py", *root.glob("backend/*.py"), *root.glob("frontend/templates/*"),
             *root.glob("frontend/static/css/*"), *root.glob("frontend/static/js/*.js")]
    return str(max((f.stat().st_mtime_ns for f in files if f.is_file()), default=0))

def data_dir():
    """ANONYHOST_DATA, else an existing ./data (older installs), else ~/.local/share/anonyhost."""
    if os.environ.get("ANONYHOST_DATA"):
        return Path(os.environ["ANONYHOST_DATA"])
    local = Path(__file__).resolve().parent.parent / "data"
    if (local / "admin.json").exists():
        return local
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local/share")) / "anonyhost"

def load_settings(base):
    try:
        return json.loads((Path(base) / "settings.json").read_text())
    except (OSError, ValueError):
        return {}

def save_settings(base, **kw):
    d = load_settings(base); d.update(kw)
    p = Path(base) / "settings.json"
    p.write_text(json.dumps(d)); os.chmod(p, 0o600)
