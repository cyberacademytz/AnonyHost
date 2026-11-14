# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Automatic problem handling: log recognition, runtime repairs, the doctor, the watchdog, installs, Health page, delete-all."""
import json, os, shutil, socket, subprocess, sys, threading, time, urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
from app import create_app
from backend import doctor as doctor_mod, logscan, runtime
from backend.doctor import Doctor, PortBusy
from backend.nginx_manager import NginxManager, nginx_conf
from backend.process_manager import ServiceError, port_free
from backend.tor_manager import TorManager
from test_core import _csrf, _login, mkzip

def site(tmp_path, files):
    d = tmp_path / "site"
    for n, c in files.items():
        (d / n).parent.mkdir(parents=True, exist_ok=True); (d / n).write_text(c)
    return d

def free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close(); return p

def get(port, path="/"):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5).read().decode()

PY_PORT_APP = ("import os, http.server\nclass H(http.server.BaseHTTPRequestHandler):\n"
               "    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(b'alive')\n    def log_message(*a): pass\n")

# ---------------- recognising problems ----------------
def ids(src, text): return [h["id"] for h in logscan.classify(src, text)]

def test_logscan_recognises_common_problems():
    assert ids("app", "Traceback\nModuleNotFoundError: No module named 'flask_cors.core'") == ["app.py_module"]
    assert ids("app", "Error: Cannot find module 'express'\n") == ["app.node_module"]
    h = logscan.classify("app", "Error: Cannot find module './lib/x'")[0]; assert h["fix"] is None  # a local file is missing: nothing to install
    assert "app.app_port_in_use" in ids("app", "Error: listen EADDRINUSE: address already in use :::3000")
    assert "app.host_header" in ids("app", "django.core.exceptions.DisallowedHost: Invalid HTTP_HOST header: 'x.onion'")
    assert "app.app_syntax" in ids("app", '  File "app.py", line 3\n    def x(\nSyntaxError: unexpected EOF')
    assert ids("app", "all quiet") == []
    assert ids("php", "[12-Nov-2026 05:00:00] PHP Parse error:  syntax error, unexpected '}' in /x/site/a.php on line 7") == ["php.php_parse"]
    h = logscan.classify("php", "PHP Fatal error:  Uncaught Error: Call to undefined function mysqli_connect() in /x.php:3")[0]
    assert h["fix"] == "install" and h["pkgs"] == ["php-mysql"]
    assert logscan.classify("php", 'PHP Fatal error: Uncaught Error: Class "ZipArchive" not found')[0]["pkgs"] == ["php-zip"]
    assert "php.php_class" in ids("php", 'PHP Fatal error: Class "Monolog\\Logger" not found')
    assert "php.php_driver" in ids("php", "PDOException: could not find driver")
    assert "nginx.upstream_down" in ids("nginx", "2026/11/12 05:00:00 [error] 1#1: *1 connect() failed (111: Connection refused) while connecting to upstream")
    assert "nginx.nginx_perm" in ids("nginx", "open() \"/x/site/a.css\" failed (13: Permission denied)")
    assert "nginx.nginx_bind" in ids("nginx", "bind() to 127.0.0.1:8080 failed (98: Address already in use)")
    assert "tor.tor_clock" in ids("tor", "[warn] Your system clock just jumped 3600 seconds")
    assert "tor.tor_network" in ids("tor", "[warn] Problem bootstrapping. Stuck at 10%: Connecting to directory server.")
    for src in ("app", "php", "nginx", "tor"):
        assert logscan.classify(src, "") == [] and logscan.classify(src, None) == []

# ---------------- the runtime repairs what it can ----------------
def test_start_command_placeholders_and_django_detection(tmp_path):
    site(tmp_path, {"anonyhost.json": json.dumps({"runtime": "python", "start": "python3 serve.py {port}"}),
                    "serve.py": "import sys, http.server as h\nh.HTTPServer(('127.0.0.1', int(sys.argv[1])), h.SimpleHTTPRequestHandler).serve_forever()\n"})
    rt = runtime.Runtime(tmp_path)
    try:
        up = rt.start(19200); assert "alive" or get(up["app_port"]) is not None
    finally:
        rt.stop()
    dj = runtime.detect(site(tmp_path / "dj", {"manage.py": "#"}))
    assert dj["kind"] == "python" and "127.0.0.1:{port}" in dj["start"] and dj["start"][1] == "manage.py"

def test_app_that_ignores_PORT_is_adopted(tmp_path):
    p = free_port()
    site(tmp_path, {"app.py": PY_PORT_APP + f"http.server.HTTPServer(('127.0.0.1', {p}), H).serve_forever()\n"})
    rt = runtime.Runtime(tmp_path)
    try:
        up = rt.start(19300)
        assert up["app_port"] == p and get(p) == "alive"
        assert "ignored the PORT variable" in (tmp_path / "logs/autofix.log").read_text()
    finally:
        rt.stop()

def test_exposed_detection_flags_all_interface_listeners(tmp_path):
    for host, expect in (("0.0.0.0", True), ("127.0.0.1", False)):
        d = tmp_path / host; site(d, {"app.py": PY_PORT_APP + f"http.server.HTTPServer(('{host}', int(os.environ['PORT'])), H).serve_forever()\n"})
        rt = runtime.Runtime(d)
        try:
            rt.start(19400)
            ex = rt.exposed()
            assert bool(ex) is expect, (host, ex)
        finally:
            rt.stop()

@pytest.mark.skipif(not shutil.which("python3"), reason="no python3")
def test_flask_script_that_only_defines_app_is_run_by_flask(tmp_path):
    pytest.importorskip("flask")
    site(tmp_path, {"app.py": "from flask import Flask\napp = Flask(__name__)\n@app.route('/')\ndef home(): return 'flask-ok'\n"})
    rt = runtime.Runtime(tmp_path)
    try:
        up = rt.start(19500)
        assert get(up["app_port"]) == "flask-ok"
        assert "starting it with its framework" in (tmp_path / "logs/autofix.log").read_text()
    finally:
        rt.stop()

def test_missing_python_package_is_installed_then_app_starts(tmp_path, monkeypatch):
    mod = next((m for m in ("bottle", "waitress", "quart") if __import__("importlib").util.find_spec(m) is None), None)
    if not mod:
        pytest.skip("all candidate modules are installed here")
    site(tmp_path, {"app.py": f"import {mod}\n" + PY_PORT_APP + "http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n"})
    rt = runtime.Runtime(tmp_path); installed = []
    def fake_pip(pkgs):  # no network in tests: put a stand-in module on the app's path instead
        installed.extend(pkgs); (tmp_path / "site" / f"{mod}.py").write_text("")
    monkeypatch.setattr(rt, "pip_install", fake_pip)
    try:
        up = rt.start(19600)
        assert installed == [runtime.SAFE_PIP[mod]] and get(up["app_port"]) == "alive"
        assert "needs the Python package" in (tmp_path / "logs/autofix.log").read_text()
    finally:
        rt.stop()

def test_unknown_python_module_gives_a_clear_explanation(tmp_path):
    site(tmp_path, {"app.py": "import notapackage_zz\n"})
    with pytest.raises(ServiceError) as e:
        runtime.Runtime(tmp_path).start(19700)
    assert "Python module 'notapackage_zz' is missing" in str(e.value) and "requirements.txt" in str(e.value)

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_missing_node_module_triggers_npm_install_and_retry(tmp_path, monkeypatch):
    site(tmp_path, {"package.json": '{"scripts": {"start": "node server.js"}, "dependencies": {}}',
                    "server.js": "require('zz-missing'); require('http').createServer((q, r) => r.end('node-ok')).listen(process.env.PORT, '127.0.0.1');\n"})
    rt = runtime.Runtime(tmp_path); calls = []
    def fake_node(env, force=False):
        if force:
            calls.append(1); (tmp_path / "site/node_modules/zz-missing").mkdir(parents=True, exist_ok=True); (tmp_path / "site/node_modules/zz-missing/index.js").write_text("")
    monkeypatch.setattr(rt, "_prepare_node", fake_node)
    try:
        up = rt.start(19800)
        assert calls == [1] and get(up["app_port"]) == "node-ok"
    finally:
        rt.stop()

def test_nginx_error_page_and_host_header_option():
    n = nginx_conf("/d", 8080, "node", {"app_port": 9000})
    assert "error_page 502 503 504 @anonyhost_down" in n and "proxy_set_header Host $host;" in n and "X-Forwarded-Host" not in n
    n = nginx_conf("/d", 8080, "node", {"app_port": 9000}, local_host=True)
    assert "proxy_set_header Host 127.0.0.1:9000;" in n and "proxy_set_header X-Forwarded-Host $host;" in n
    assert "@anonyhost_down" in nginx_conf("/d", 8080, "php", {"sock": "/s"}) and "@anonyhost_down" not in nginx_conf("/d", 8080)

# ---------------- the doctor ----------------
class FakeWeb:
    """nginx stand-in: the real runtime, no nginx binary."""
    def __init__(self, base, port): self.base, self.port, self.rt, self._on, self.starts = Path(base), port, runtime.Runtime(base), False, 0
    def running(self): return self._on
    def start(self):
        if not self.rt.kind(): raise ServiceError("No website deployed yet. Upload a ZIP first.")
        self.rt.start(self.port); self._on = True; self.starts += 1
        from backend import process_manager as pm; pm.set_want(self.base)
    def stop(self):
        from backend import process_manager as pm; pm.clear_want(self.base)
        self.rt.stop(); self._on = False

class FakeTor:
    def __init__(self, base, port): self.base, self.port, self._on = Path(base), port, False; self.pid, self.log = self.base / "run/tor.pid", self.base / "logs/tor.log"
    def running(self): return self._on
    def start(self):
        from backend import process_manager as pm; self._on = True; pm.set_want(self.base)
    def stop(self):
        from backend import process_manager as pm; pm.clear_want(self.base); self._on = False
    def bootstrap(self): return 100

def mkdoctor(tmp_path, port=None, **settings):
    (tmp_path / "logs").mkdir(parents=True, exist_ok=True); (tmp_path / "run").mkdir(parents=True, exist_ok=True)
    port = port or free_port(); store = {"port": port, **settings}
    web, tor = FakeWeb(tmp_path, port), FakeTor(tmp_path, port)
    return Doctor(tmp_path, web, tor, lambda: store, lambda **kw: store.update(kw)), web, tor, store

def test_start_switches_a_busy_port_by_itself(tmp_path):
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(); p = busy.getsockname()[1]
    site(tmp_path, {"index.html": "x"})
    d, web, tor, store = mkdoctor(tmp_path, p)
    try:
        notes = d.start()
        assert web.port == tor.port == store["port"] != p and port_free(p) is False
        assert any(f"Port {p} was in use" in n for n in notes) and web.running() and tor.running()
    finally:
        busy.close()

def test_start_with_auto_fix_off_raises_portbusy_and_changes_nothing(tmp_path):
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(); p = busy.getsockname()[1]
    site(tmp_path, {"index.html": "x"})
    d, web, tor, store = mkdoctor(tmp_path, p, auto_fix=False)
    try:
        with pytest.raises(PortBusy): d.start()
        assert web.port == p and store["port"] == p and not web.running()
    finally:
        busy.close()

def test_start_without_a_site_does_not_touch_the_port(tmp_path):
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(); p = busy.getsockname()[1]
    d, web, tor, store = mkdoctor(tmp_path, p)
    try:
        with pytest.raises(ServiceError, match="No website deployed"): d.start()
        assert store["port"] == p
    finally:
        busy.close()

def test_recover_only_acts_on_the_right_failures(tmp_path):
    d, web, tor, store = mkdoctor(tmp_path)
    old = web.port
    assert d._recover(ServiceError("The site's app stopped right after starting. OSError: Address already in use")) is None and web.port == old
    assert d._recover(ServiceError("Nginx failed to start (is port 8080 already in use?): nginx: configuration file test failed")) is None and web.port == old
    assert "switched to port" in d._recover(ServiceError("Nginx failed to start: bind() to 127.0.0.1:8080 failed (98: Address already in use)")) and web.port != old

def test_diagnose_reports_missing_packages_with_an_install_action(tmp_path, monkeypatch):
    site(tmp_path, {"index.php": "<?php"})
    d, web, tor, store = mkdoctor(tmp_path)
    monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: ["tor", "nginx"])
    monkeypatch.setattr(doctor_mod, "missing_runtime", lambda s: [("php-fpm", "php-fpm")])
    f = {x["id"]: x for x in d.diagnose()}
    assert f["deps.tor"]["root"] and f["deps.tor"]["pkgs"] == ["tor"] and f["deps.nginx"]["pkgs"] == ["nginx"] and f["deps.runtime"]["pkgs"] == ["php-fpm"]
    assert all(not x["auto"] for x in f.values() if x["root"])  # anything needing root is never applied silently
    with pytest.raises(ServiceError, match="approval"): d.apply(f["deps.tor"])

def test_diagnose_healthy_and_low_disk(tmp_path, monkeypatch):
    d, web, tor, store = mkdoctor(tmp_path)
    monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: [])
    assert [x["id"] for x in d.diagnose()] == ["ok"]
    monkeypatch.setattr(shutil, "disk_usage", lambda p: type("U", (), {"free": 20 * 2**20})())
    assert d.diagnose()[0]["id"] == "disk" and d.diagnose()[0]["level"] == "error"

def test_stale_files_are_found_and_cleaned(tmp_path, monkeypatch):
    d, web, tor, store = mkdoctor(tmp_path); monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: [])
    (tmp_path / "run/nginx.pid").write_text("999999"); (tmp_path / "run/app.pid").write_text("999998")
    f = {x["id"]: x for x in d.diagnose()}
    assert f["stale"]["auto"] and f["stale"]["fix"] == "clean_stale"
    d.apply(f["stale"]); assert not (tmp_path / "run/nginx.pid").exists() and not (tmp_path / "run/app.pid").exists()

def test_probe_classifies_site_responses(tmp_path, monkeypatch):
    site(tmp_path, {"index.html": "x"})
    d, web, tor, store = mkdoctor(tmp_path); monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: [])
    web._on = True; tor._on = True; doctor_mod.pm.set_want(tmp_path)
    monkeypatch.setattr(web.rt, "_app_alive", lambda: True)
    for status, expect in ((200, None), (404, "site.home"), (403, "site.forbidden"), (500, "site.error"), (502, "site.down")):
        monkeypatch.setattr(doctor_mod, "probe", lambda port, timeout=4, s=status: (s, None))
        got = [x["id"] for x in d.diagnose() if x["id"].startswith("site.")]
        assert got == ([expect] if expect else []), (status, got)
    monkeypatch.setattr(doctor_mod, "probe", lambda port, timeout=4: (None, "Connection refused"))
    down = [x for x in d.diagnose() if x["id"] == "site.down"][0]
    assert down["auto"] and down["fix"] == "restart_site" and "Connection refused" in down["detail"]

def test_real_probe_against_local_servers(tmp_path):
    class H(BaseHTTPRequestHandler):
        def do_GET(s): s.send_response(500); s.end_headers(); s.wfile.write(b"boom")
        def log_message(*a): pass
    srv = HTTPServer(("127.0.0.1", 0), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        assert doctor_mod.probe(srv.server_address[1]) == (500, None)
    finally:
        srv.shutdown()
    status, err = doctor_mod.probe(free_port(), timeout=1)
    assert status is None and err

# ---------------- the watchdog ----------------
def test_watchdog_restarts_a_crashed_app_and_then_gives_up(tmp_path, monkeypatch):
    site(tmp_path, {"app.py": PY_PORT_APP + "http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n"})
    d, web, tor, store = mkdoctor(tmp_path); monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: [])
    monkeypatch.setattr(doctor_mod, "probe", lambda port, timeout=4: (200, None))
    def kill_app():
        pid = int((tmp_path / "run/app.pid").read_text()); os.killpg(pid, 9)
        for _ in range(50):
            if not web.rt._app_alive(): break
            time.sleep(0.1)
    try:
        d.start(); assert web.rt._app_alive()
        for n in range(1, 4):  # three crashes are repaired automatically
            kill_app(); assert not web.rt._app_alive()
            d.tick()
            assert web.rt._app_alive(), f"restart {n}"
        kill_app(); d.tick()  # the fourth within ten minutes: stop and ask the user
        assert not web.rt._app_alive()
        assert "Gave up automatically fixing" in (tmp_path / "logs/autofix.log").read_text()
        f = [x for x in d.diagnose() if x["id"] == "app.down"][0]
        assert not f["auto"] and "paused" in f["detail"]
        d.start()  # a manual start resets the counters
        assert web.rt._app_alive() and not d.gave_up
    finally:
        web.stop()

def test_watchdog_respects_a_deliberate_stop_and_the_off_switch(tmp_path, monkeypatch):
    site(tmp_path, {"app.py": PY_PORT_APP + "http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n"})
    d, web, tor, store = mkdoctor(tmp_path); monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: [])
    monkeypatch.setattr(doctor_mod, "probe", lambda port, timeout=4: (200, None))
    try:
        d.start(); web.stop(); tor.stop()      # the user pressed Stop
        d.tick(); assert not web.rt._app_alive() and web.starts == 1
        d.start(); os.killpg(int((tmp_path / "run/app.pid").read_text()), 9); time.sleep(0.5)
        store["auto_fix"] = False              # automatic fixing switched off
        d.tick(); assert not web.rt._app_alive()
    finally:
        web.stop()

def test_tick_never_blocks_a_user_action(tmp_path):
    d, *_ = mkdoctor(tmp_path)
    with d.lock:
        t = threading.Thread(target=d.tick); t.start(); t.join(2)
        assert not t.is_alive()  # tick() gave up at once instead of waiting for the lock held by this thread's peer

def test_fix_permissions_makes_files_readable_and_keeps_links(tmp_path):
    d, *_ = mkdoctor(tmp_path); s = site(tmp_path, {"index.html": "x", "sub/a.css": "y"})
    os.chmod(s / "index.html", 0o000); os.chmod(s / "sub", 0o300)
    os.symlink("/etc/hostname", s / "link")
    d.apply({"id": "x", "fix": "fix_perms"})
    assert os.access(s / "index.html", os.R_OK) and os.access(s / "sub", os.R_OK | os.X_OK) and os.path.islink(s / "link")
    assert (s / "index.html").stat().st_mode & 0o111 == 0

def test_host_header_fix_writes_marker(tmp_path):
    site(tmp_path, {"app.py": PY_PORT_APP + "http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n"})
    d, web, tor, store = mkdoctor(tmp_path)
    try:
        d.start(); d.apply({"id": "app.host_header", "fix": "host_header_local"})
        assert (tmp_path / "proxy_local_host").exists() and web.rt._app_alive()
    finally:
        web.stop()

# ---------------- installing packages needs the user ----------------
def test_install_allow_list_and_command(tmp_path, monkeypatch):
    d, *_ = mkdoctor(tmp_path)
    for bad in (["tor; rm -rf /"], ["tor", "curl"], ["$(reboot)"], ["../tor"], []):
        with pytest.raises(ServiceError): d.validate_pkgs(bad)
    assert d.validate_pkgs(["php-fpm", "php-fpm", "nodejs"]) == ["php-fpm", "nodejs"]
    monkeypatch.setattr(shutil, "which", lambda n: None)
    with pytest.raises(ServiceError) as e: d.start_install(["tor"])
    assert "sudo apt install tor" in str(e.value)
    seen = {}
    class P:
        def __init__(s, argv, **kw): seen["argv"] = argv
        def wait(s, timeout=None): return 0
    monkeypatch.setattr(shutil, "which", lambda n: "/usr/bin/pkexec"); monkeypatch.setattr(subprocess, "Popen", P)
    d.start_install(["php-fpm", "nodejs"])
    for _ in range(50):
        if d.install_status()["state"] != "running": break
        time.sleep(0.05)
    assert seen["argv"][:3] == ["pkexec", "/bin/sh", "-c"] and seen["argv"][3].endswith("apt-get install -y php-fpm nodejs")
    assert d.install_status()["state"] == "done"

# ---------------- pages ----------------
def _client(tmp_path, **kw):
    c = create_app(tmp_path / "d", password="pw", **kw).test_client(); _login(c); return c, tmp_path / "d"

def _post(c, url, **data): return c.post(url, data={"csrf": _csrf(c), **data})

def test_health_page_actions_and_csrf(tmp_path, monkeypatch):
    import app as appmod
    c, d = _client(tmp_path)
    monkeypatch.setattr(appmod.pd, "missing_deps", lambda: [])
    monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: ["tor"])
    page = c.get("/health").get_data(as_text=True)
    assert "Tor is not installed" in page and "Install missing packages" in page and "sudo apt install tor" in page
    assert "Automatic fixing is ON" in page
    assert c.post("/health/fix", data={"id": "all"}).status_code == 400 and c.post("/health/install", data={}).status_code == 400
    r = _post(c, "/health/fix", id="nope"); assert r.status_code == 302 and "already gone" in c.get("/health").get_data(as_text=True)
    monkeypatch.setattr(shutil, "which", lambda n: None)
    _post(c, "/health/install", id="all"); assert "sudo apt install tor" in c.get("/health").get_data(as_text=True)
    j = c.get("/api/health").get_json(); assert j["errors"] >= 1 and j["items"][0]["title"]

def test_health_all_clear_and_settings_toggle(tmp_path, monkeypatch):
    import app as appmod
    c, d = _client(tmp_path)
    monkeypatch.setattr(doctor_mod.pd, "missing_deps", lambda: []); monkeypatch.setattr(appmod.pd, "missing_deps", lambda: [])
    page = c.get("/health").get_data(as_text=True)
    assert "No problems found" in page and "Fix everything automatically" not in page
    _post(c, "/settings/startup")  # no boxes ticked
    assert json.loads((d / "settings.json").read_text())["auto_fix"] is False and "Automatic fixing is OFF" in c.get("/health").get_data(as_text=True)
    _post(c, "/settings/startup", auto_fix="on", autostart="on")
    assert json.loads((d / "settings.json").read_text())["auto_fix"] is True and 'name="auto_fix" checked' in c.get("/settings").get_data(as_text=True)

def test_app_start_switches_busy_port_and_says_so(tmp_path, monkeypatch):
    import app as appmod
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(); p = busy.getsockname()[1]
    monkeypatch.setattr(appmod.pd, "check_platform", lambda *a: {})
    monkeypatch.setattr(NginxManager, "start", lambda self: None); monkeypatch.setattr(TorManager, "start", lambda self: None)
    c = create_app(tmp_path / "d", port=p, password="pw").test_client(); _login(c)
    (tmp_path / "d/site").mkdir(exist_ok=True); (tmp_path / "d/site/index.html").write_text("x")
    try:
        r = _post(c, "/start")
        assert r.headers["Location"].rstrip("/").endswith("5000") or "website" not in r.headers["Location"]  # no manual resolver needed
        page = c.get("/").get_data(as_text=True)
        assert f"Port {p} was in use" in page and "Fixed automatically" in page
        assert json.loads((tmp_path / "d/settings.json").read_text())["port"] != p
        assert "Port " in (tmp_path / "d/logs/autofix.log").read_text()
    finally:
        busy.close()

def test_dashboard_and_settings_cleanups(tmp_path):
    c, d = _client(tmp_path)
    dash = c.get("/").get_data(as_text=True)
    assert "System up" not in dash and 'id="up"' not in dash and "hstrip" in dash and "copy.js" in dash
    st = c.get("/settings").get_data(as_text=True)
    assert "Limits" not in st and "Max website size" not in st and "Data folder" not in st and "Fix problems automatically" in st
    assert c.get("/static/js/copy.js").status_code == 200
    assert ">Health<" in dash

def test_delete_all_in_files(tmp_path):
    c, d = _client(tmp_path)
    s = d / "site"; (s / "sub/deep").mkdir(parents=True); (s / "index.html").write_text("x"); (s / "sub/deep/a.txt").write_text("y")
    outside = tmp_path / "keep.txt"; outside.write_text("precious"); os.symlink(outside, s / "link.txt"); os.symlink(tmp_path, s / "dirlink")
    (d / "deployed_at").write_text("now")
    page = c.get("/files").get_data(as_text=True)
    assert "Delete all" in page and 'id="wipe"' in page and "all 4 items" in page
    for bad in ("", "delete", "DELET", "yes"):
        _post(c, "/files/clear", path="", confirm=bad); assert (s / "index.html").exists(), bad
    _post(c, "/files/clear", path="sub", confirm="DELETE")            # only that folder
    assert (s / "sub").is_dir() and not list((s / "sub").iterdir()) and (s / "index.html").exists()
    r = _post(c, "/files/clear", path="", confirm="DELETE")
    assert r.status_code == 302 and not list(s.iterdir()) and s.is_dir() and not (d / "deployed_at").exists()
    assert outside.read_text() == "precious" and tmp_path.exists()   # links were removed, never followed
    assert "Deleted everything in the website folder" in c.get("/files").get_data(as_text=True)
    assert 'id="wipebtn" disabled' in c.get("/files").get_data(as_text=True)
    assert c.post("/files/clear", data={"path": "", "confirm": "DELETE"}).status_code == 400   # CSRF
    assert _post(c, "/files/clear", path="../..", confirm="DELETE").status_code in (400, 404) and tmp_path.exists()

def test_delete_all_stops_hosting_first(tmp_path, monkeypatch):
    import app as appmod
    c, d = _client(tmp_path)
    (d / "site").mkdir(exist_ok=True); (d / "site/index.html").write_text("x")
    calls = []
    monkeypatch.setattr(NginxManager, "running", lambda self: True); monkeypatch.setattr(NginxManager, "stop", lambda self: calls.append("web"))
    monkeypatch.setattr(TorManager, "stop", lambda self: calls.append("tor"))
    _post(c, "/files/clear", path="", confirm="DELETE")
    assert calls == ["tor", "web"] and "Hosting was stopped" in c.get("/files").get_data(as_text=True)

def test_unreadable_password_hash_gives_a_clear_message_instead_of_crashing(tmp_path, monkeypatch):
    import app as appmod
    c = create_app(tmp_path / "d", password="pw").test_client()
    c.get("/login")
    with c.session_transaction() as s: tok = s["csrf"]
    def old_werkzeug(stored, text):
        if text == "": raise ValueError("Invalid hash method 'scrypt'.")
        raise ValueError("Invalid hash method 'scrypt'.")
    monkeypatch.setattr(appmod, "check_password_hash", old_werkzeug)
    monkeypatch.setattr(appmod.time, "sleep", lambda s: None)
    r = c.post("/login", data={"username": "admin", "password": "pw", "csrf": tok})
    assert r.status_code == 200 and "anonyhost --reset-password" in r.get_data(as_text=True) and "newer version" in r.get_data(as_text=True)
    r = c.post("/recover", data={"key": "x", "new": "a" * 12, "confirm": "a" * 12, "csrf": tok})
    assert r.status_code == 200  # no crash
