# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""There is one way in: the dashboard, behind its login. No separate control panel exists anywhere."""
import glob, re, shutil, subprocess, sys
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
from app import create_app
ROOT = Path(__file__).parent.parent

def test_no_control_panel_code_or_files_remain():
    for gone in ("panel.py", "backend/control.py", "scripts/anonyhost-panel", "packaging/debian/anonyhost-panel", "packaging/debian/anonyhost-panel.desktop", "tests/test_control.py"):
        assert not (ROOT / gone).exists(), gone
    for f in glob.glob(str(ROOT / "**/*.py"), recursive=True):
        t = Path(f).read_text()
        assert not re.search(r"^\s*(import|from)\s+tkinter", t, re.M), f           # no GUI toolkit anywhere
        if not f.endswith("test_single_entry.py"):
            assert "backend.control" not in t and "panel.py" not in t, f

def test_user_facing_text_does_not_send_people_to_a_control_panel():
    for f in glob.glob(str(ROOT / "frontend/templates/*.html")) + [str(ROOT / "app.py")]:
        assert "Control Panel" not in Path(f).read_text(), f
    readme = (ROOT / "README.md").read_text()
    assert "Open AnonyHost: Applications menu" in readme and "AnonyHost Control Panel" not in readme and "`anonyhost-panel`" not in readme

def test_recovery_hint_is_only_on_the_forgot_password_page(tmp_path):
    c = create_app(tmp_path / "d", password="pw").test_client()             # an account exists: sign-in and recovery pages are shown
    page = c.get("/recover").get_data(as_text=True)
    assert "anonyhost --reset-password" in page and "Control Panel" not in page          # where a locked-out person is
    assert "anonyhost --reset-password" not in c.get("/login").get_data(as_text=True)    # the sign-in and setup pages stay clean
    c2 = create_app(tmp_path / "d2").test_client()                          # first run: no account yet
    assert "anonyhost --reset-password" not in c2.get("/setup").get_data(as_text=True)

def test_every_page_still_needs_a_login(tmp_path):
    anon = create_app(tmp_path / "d", password="pw").test_client()
    for url in ("/", "/website", "/health", "/files", "/logs", "/settings", "/api/status", "/api/health", "/api/activity", "/api/install", "/api/logs"):
        r = anon.get(url)
        assert r.status_code in (302, 401) and "login" in (r.headers.get("Location", "") or "login"), url
    for url in ("/start", "/stop", "/restart-site", "/deploy", "/files/clear", "/health/fix", "/health/install", "/settings/startup"):
        assert anon.post(url, data={}).status_code in (302, 400, 401), url          # nothing can be changed without signing in
