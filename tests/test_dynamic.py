# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
import json, os, shutil, sys, time, urllib.request
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
from app import create_app
from backend import runtime, security
from backend.logs import tail_log
from backend.nginx_manager import nginx_conf
from backend.process_manager import ServiceError
from test_core import mkzip, _csrf, _login

def site(tmp_path, files):
    d = tmp_path / "site"
    for n, c in files.items():
        (d / n).parent.mkdir(parents=True, exist_ok=True); (d / n).write_text(c)
    return d

@pytest.mark.parametrize("files,kind", [
    ({"index.html": "x"}, "static"),
    ({"index.php": "<?php"}, "php"),
    ({"index.html": "x", "index.php": "<?php"}, "php"),
    ({"hello.php": "<?php"}, "php"),
    ({"package.json": '{"scripts":{"start":"node a.js"}}'}, "node"),
    ({"package.json": '{"name":"build-tools"}', "index.html": "x"}, "static"),
    ({"server.js": "//"}, "node"),
    ({"app.py": "#"}, "python"),
    ({"app.py": "#", "index.html": "x"}, "static"),
    ({"anonyhost.json": '{"runtime":"python","start":"python3 run.py"}', "index.html": "x"}, "python"),
    ({"readme.txt": "x"}, None),
])
def test_detect(tmp_path, files, kind):
    assert runtime.detect(site(tmp_path, files))["kind"] == kind

def test_detect_start_commands(tmp_path):
    assert runtime.detect(site(tmp_path / "a", {"package.json": '{"scripts":{"start":"x"}}'}))["start"][:2] == ["npm", "start"]
    assert runtime.detect(site(tmp_path / "b", {"app.js": "//"}))["start"] == ["node", "app.js"]
    assert runtime.detect(site(tmp_path / "c", {"main.py": "#"}))["start"] == ["python3", "main.py"]
    assert runtime.detect(site(tmp_path / "d", {"anonyhost.json": '{"runtime":"node","start":"node \\"my app.js\\""}'}))["start"] == ["node", "my app.js"]

def test_archive_accepts_dynamic_sites(tmp_path):
    for i, files in enumerate(({"app.py": "#"}, {"package.json": "{}"}, {"index.php": "<?php"}, {"mysite/server.js": "//"})):
        security.safe_extract(mkzip(tmp_path / f"{i}.zip", files), tmp_path / f"o{i}")
    assert (tmp_path / "o3/server.js").exists()
    with pytest.raises(security.UnsafeArchive):
        security.safe_extract(mkzip(tmp_path / "bad.zip", {"notes.txt": "x"}), tmp_path / "ob")

def test_nginx_conf_per_kind():
    st = nginx_conf("/d", 8080)
    assert "limit_except GET HEAD" in st and "fastcgi_pass" not in st and "proxy_pass" not in st
    php = nginx_conf("/d", 8080, "php", {"sock": "/d/run/php-fpm.sock"})
    assert "fastcgi_pass unix:/d/run/php-fpm.sock;" in php and "try_files $uri =404;" in php and "limit_except" not in php
    node = nginx_conf("/d", 8080, "node", {"app_port": 8081})
    assert "proxy_pass http://127.0.0.1:8081;" in node and "listen 127.0.0.1:8080;" in node
    assert "X-Forwarded" not in node and "X-Real-IP" not in node  # visitor addresses are never forwarded

PY_APP = ("import os, http.server\n"
          "class H(http.server.BaseHTTPRequestHandler):\n"
          "    def do_GET(s): s.send_response(200); s.end_headers(); s.wfile.write(('py:' + os.environ['PORT']).encode())\n"
          "    def log_message(*a): pass\n"
          "http.server.HTTPServer(('127.0.0.1', int(os.environ['PORT'])), H).serve_forever()\n")
JS_APP = ("require('http').createServer((q, r) => r.end('node-ok')).listen(process.env.PORT, '127.0.0.1');\n")

def _get(port):
    return urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5).read().decode()

def test_python_app_runs_and_stops(tmp_path):
    site(tmp_path, {"app.py": PY_APP})
    rt = runtime.Runtime(tmp_path)
    up = rt.start(18080)
    try:
        assert rt.running() and up["kind"] == "python" and _get(up["app_port"]) == f"py:{up['app_port']}"
        assert rt.start(18080)["app_port"] == up["app_port"]  # already running: same app, no second copy
    finally:
        rt.stop()
    assert not rt.running() and not (tmp_path / "run/app.pid").exists()

@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_node_app_runs_and_stops(tmp_path):
    site(tmp_path, {"server.js": JS_APP})
    rt = runtime.Runtime(tmp_path)
    up = rt.start(18090)
    try:
        assert up["kind"] == "node" and _get(up["app_port"]) == "node-ok"
    finally:
        rt.stop()
    assert not rt.running()

def test_crashing_app_reports_its_log(tmp_path):
    site(tmp_path, {"app.py": "raise SystemExit('boom-from-app')\n"})
    rt = runtime.Runtime(tmp_path)
    with pytest.raises(ServiceError) as e:
        rt.start(18100)
    assert "stopped right after starting" in str(e.value) and "boom-from-app" in str(e.value) and not rt.running()

def test_no_start_command_and_missing_php(tmp_path, monkeypatch):
    site(tmp_path, {"anonyhost.json": '{"runtime":"node"}'})
    with pytest.raises(ServiceError): runtime.Runtime(tmp_path).start(18110)
    monkeypatch.setattr(runtime, "php_fpm_bin", lambda: None)
    d = site(tmp_path / "p", {"index.php": "<?php"})
    assert runtime.missing_runtime(d) == [("php-fpm", "php-fpm")]
    with pytest.raises(ServiceError, match="PHP-FPM is not installed"): runtime.Runtime(tmp_path / "p").start(18120)

def _client(tmp_path):
    c = create_app(tmp_path / "d", password="pw").test_client()
    _login(c); return c, tmp_path / "d"

def _post(c, url, **data):
    return c.post(url, data={"csrf": _csrf(c), **data})

def test_deploy_dynamic_site_warns_and_reports_kind(tmp_path):
    c, d = _client(tmp_path)
    z = mkzip(tmp_path / "p.zip", {"index.php": "<?php echo 1;"})
    r = c.post("/deploy", data={"zip": (open(z, "rb"), "p.zip"), "csrf": _csrf(c)}, content_type="multipart/form-data")
    assert r.status_code == 302
    page = c.get("/").get_data(as_text=True)
    assert "PHP website deployed" in page and "Only deploy code you trust" in page
    st = c.get("/api/status").get_json()
    assert st["site"] and st["kind"] == "PHP"

def test_files_page_basics(tmp_path):
    c, d = _client(tmp_path)
    (d / "site/index.html").write_text("<h1>hi</h1>")
    page = c.get("/files").get_data(as_text=True)
    assert "index.html" in page and "soon" not in c.get("/").get_data(as_text=True)
    r = c.post("/files/upload", data={"csrf": _csrf(c), "path": "", "files": [(__import__("io").BytesIO(b"body{}"), "a b.css")]}, content_type="multipart/form-data")
    assert r.status_code == 302 and (d / "site/a b.css").read_bytes() == b"body{}" and not list((d / "site").glob(".upload-*"))
    _post(c, "/files/mkdir", path="", name="img")
    assert (d / "site/img").is_dir()
    r = _post(c, "/files/new", path="img", name="note.txt")
    assert r.status_code == 302 and r.headers["Location"].endswith("/files/edit?path=img/note.txt")
    assert "textarea" in c.get("/files/edit?path=img/note.txt").get_data(as_text=True)
    _post(c, "/files/save", path="img/note.txt", content="line1\r\nline2")
    assert (d / "site/img/note.txt").read_text() == "line1\nline2" and (d / "site/img/note.txt").stat().st_mode & 0o111 == 0
    assert c.get("/files/download?path=img/note.txt").data == b"line1\nline2"
    _post(c, "/files/delete", path="img")
    assert not (d / "site/img").exists()

def test_files_cannot_escape_or_touch_links(tmp_path):
    c, d = _client(tmp_path)
    (d / "site/index.html").write_text("x"); (tmp_path / "secret.txt").write_text("top secret")
    os.symlink(tmp_path / "secret.txt", d / "site/link.txt")
    (d / "admin.json").exists()
    for url in ("/files?path=..", "/files/edit?path=../admin.json", "/files/download?path=../../etc/passwd",
                "/files/download?path=link.txt", "/files/edit?path=link.txt", "/files?path=%2Fetc"):
        assert c.get(url).status_code in (400, 404), url
    for path in ("../admin.json", "link.txt", "../../etc/passwd"):
        _post(c, "/files/delete", path=path)
        _post(c, "/files/save", path=path, content="pwned")
    assert (tmp_path / "secret.txt").read_text() == "top secret" and (d / "admin.json").exists()
    assert "link" in c.get("/files").get_data(as_text=True)
    _post(c, "/files/mkdir", path="", name="../evil"); _post(c, "/files/new", path="", name="a/b")
    assert not (d / "evil").exists() and not (d / "site/a").exists()
    _post(c, "/files/delete", path="")  # the website folder itself cannot be deleted
    assert (d / "site/index.html").exists()

def test_files_binary_and_requires_login(tmp_path):
    c, d = _client(tmp_path)
    (d / "site/pic.png").write_bytes(b"\x89PNG\x00\x01")
    r = c.get("/files/edit?path=pic.png"); assert r.status_code == 302
    assert "binary" in c.get("/files").get_data(as_text=True)
    anon = create_app(tmp_path / "d2", password="pw").test_client()
    assert anon.get("/files").status_code == 302 and anon.get("/logs").status_code == 302 and anon.get("/api/logs").status_code == 302

def test_logs_page_filter_clear_and_unknown_name(tmp_path):
    c, d = _client(tmp_path)
    (d / "logs/tor.log").write_text("Bootstrapped 10%\n[warn] slow\n[err] Could not bind\n")
    page = c.get("/logs?name=Tor").get_data(as_text=True)
    assert "Could not bind" in page and "Site app" in page and "PHP-FPM" in page
    rows = c.get("/api/logs?name=Tor&errors=1").get_json()["rows"]
    assert [r["t"] for r in rows] == ["[err] Could not bind"] and rows[0]["c"] == "err"
    assert [r["c"] for r in c.get("/api/logs?name=Tor&q=slow").get_json()["rows"]] == ["warn"]
    esc = c.get("/logs?name=%3Cscript%3E&q=%3Cscript%3Ealert(1)").get_data(as_text=True)
    assert 'value="&lt;script&gt;alert(1)"' in esc and "<script>alert(1)" not in esc  # user input is escaped
    _post(c, "/logs/clear", name="Tor"); assert (d / "logs/tor.log").read_text() == ""
    _post(c, "/logs/clear", name="../../admin.json"); assert (d / "admin.json").exists()
    assert tail_log(d, "../../admin.json") == []

def test_restart_requires_running_hosting(tmp_path):
    c, d = _client(tmp_path)
    r = _post(c, "/restart-site"); assert r.status_code == 302
    assert "Hosting is not running" in c.get("/").get_data(as_text=True)

def test_launcher_skips_a_busy_dashboard_port(tmp_path):
    import socket, subprocess
    s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind(("127.0.0.1", 5000)); s.listen()
    except OSError:
        pytest.skip("port 5000 is already used by something else on this machine")
    env = {**os.environ, "ANONYHOST_DATA": str(tmp_path)}
    launcher = str(Path(__file__).parent.parent / "launcher.py")
    try:
        subprocess.run([sys.executable, launcher, "--no-browser"], env=env, timeout=30)
        url = tmp_path / "run/dashboard.url"
        for _ in range(100):
            if url.exists() and url.read_text().strip(): break
            time.sleep(0.1)
        assert url.read_text().strip() == "http://127.0.0.1:5001"
    finally:
        subprocess.run([sys.executable, launcher, "--stop"], env=env, timeout=30)
        s.close()

def test_no_globe_anywhere(tmp_path):
    c, d = _client(tmp_path)
    for url in ("/", "/files", "/logs", "/settings", "/login"):
        assert "globe" not in c.get(url).get_data(as_text=True).lower(), url
    root = Path(__file__).parent.parent / "frontend/static"
    assert not list(root.rglob("*globe*")) and not (root / "images/earth.jpg").exists()

def test_sidebar_has_dashboard_and_website_but_no_duplicates(tmp_path):
    c, d = _client(tmp_path)
    for url in ("/", "/website", "/files", "/logs", "/settings"):
        page = c.get(url).get_data(as_text=True)
        assert 'href="/website"' in page and ">Dashboard<" in page and ">Website<" in page, url
        assert "/#deploy" not in page and "/#hosting" not in page and ">Home<" not in page, url

def test_dashboard_is_read_only_overview(tmp_path):
    c, d = _client(tmp_path)
    page = c.get("/").get_data(as_text=True)
    assert 'action="/deploy"' not in page and 'action="/resolve"' not in page  # changing the site happens on /website
    for part in ("Onion address", "Quick actions", "System health", "Setup checklist", "Recent activity", 'id="banner"'):
        assert part in page, part
    assert 'action="/start"' in page and 'action="/stop"' in page and 'action="/restart-site"' in page
    st = c.get("/api/status").get_json()
    labels = [x["label"] for x in st["checks"]]
    assert labels == ["Tor is installed", "Nginx is installed", "Runtime for your site", "Website deployed", "Hosting started", "Recovery key created"]
    assert next(x for x in st["checks"] if x["label"] == "Website deployed")["ok"] is False
    assert {"cores", "ram_total", "disk_total", "uptime"} <= set(st)

def test_website_page_holds_deploy_and_hosting(tmp_path):
    c, d = _client(tmp_path)
    page = c.get("/website").get_data(as_text=True)
    assert 'action="/deploy"' in page and 'action="/start"' in page and 'action="/stop"' in page and 'action="/restart-site"' in page
    assert 'href="/files"' in page

def test_forms_return_to_the_page_they_came_from(tmp_path, monkeypatch):
    import app as appmod
    c, d = _client(tmp_path)
    monkeypatch.setattr(appmod.pd, "check_platform", lambda *a: {})
    loc = lambda r: r.headers["Location"].split("://", 1)[-1].split("/", 1)[-1]  # path part, without host
    assert loc(_post(c, "/stop", next="website")) == "website"
    assert loc(_post(c, "/stop", next="dashboard")) == ""
    assert "evil" not in _post(c, "/stop", next="//evil.example").headers["Location"]  # only known targets are accepted
    assert loc(_post(c, "/open-tor", next="website")) == "website"
    z = mkzip(tmp_path / "p.zip", {"index.html": "x"})
    r = c.post("/deploy", data={"zip": (open(z, "rb"), "p.zip"), "csrf": _csrf(c)}, content_type="multipart/form-data")
    assert loc(r) == "website"

def test_activity_api(tmp_path):
    c, d = _client(tmp_path)
    (d / "logs/nginx-error.log").write_text("[emerg] bind() failed\n")
    j = c.get("/api/activity").get_json()
    assert j["errors"] >= 1 and isinstance(j["rows"], list)

def test_edit_page_is_a_code_workspace_and_keeps_leading_newline(tmp_path):
    import re
    c, d = _client(tmp_path)
    (d / "site/lead.html").write_text("\n\n<b>x</b>")
    page = c.get("/files/edit?path=lead.html").get_data(as_text=True)
    for part in ('id="ide"', 'data-name="lead.html"', 'id="gut"', 'id="hl"', 'class="ide-status"', "editor-core.js", "editor.js"):
        assert part in page, part
    # browsers drop the first newline after <textarea>; the template adds one so the file's own leading newlines survive
    assert re.search(r'<textarea[^>]*>\n\n\n&lt;b&gt;x&lt;/b&gt;</textarea>', page)
    assert 'href="/files"' in page and "site" in page
    for js in ("editor-core.js", "editor.js"):
        assert c.get(f"/static/js/{js}").status_code == 200

def test_save_in_place_returns_json_and_never_redirects(tmp_path):
    c, d = _client(tmp_path)
    (d / "site/a.txt").write_text("old")
    h = {"X-Requested-With": "fetch"}
    r = c.post("/files/save", data={"csrf": _csrf(c), "path": "a.txt", "content": "new\r\nline"}, headers=h)
    assert r.status_code == 200 and r.get_json()["ok"] is True and r.get_json()["restart"] is False
    assert (d / "site/a.txt").read_text() == "new\nline"
    r = c.post("/files/save", data={"csrf": "wrong", "path": "a.txt", "content": "evil"}, headers=h)
    assert r.status_code == 400 and (d / "site/a.txt").read_text() == "new\nline"
    r = c.post("/files/save", data={"csrf": _csrf(c), "path": "a.txt", "content": "x" * (512 * 1024 + 1)}, headers=h)
    assert r.status_code == 413 and r.get_json()["ok"] is False and "512 KB" in r.get_json()["error"]
    r = c.post("/files/save", data={"csrf": _csrf(c), "path": "../admin.json", "content": "x"}, headers=h)
    assert r.status_code in (400, 404) and (d / "admin.json").exists()
    # without the header (no JavaScript) it still redirects back to the folder with a message
    r = c.post("/files/save", data={"csrf": _csrf(c), "path": "a.txt", "content": "plain"})
    assert r.status_code == 302 and (d / "site/a.txt").read_text() == "plain"
    assert "Saved a.txt" in c.get("/files").get_data(as_text=True)

def test_editor_core_javascript_tests():
    import subprocess
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    r = subprocess.run(["node", str(Path(__file__).parent / "js/editor_core.test.js")], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-800:] + r.stdout[-400:]
    assert "editor-core tests passed" in r.stdout

def test_author_credit_lives_in_the_sidebar_under_logout(tmp_path):
    c, d = _client(tmp_path)
    (d / "site/e.txt").write_text("x")
    for url in ("/", "/website", "/files", "/files/edit?path=e.txt", "/logs", "/settings"):
        page = c.get(url).get_data(as_text=True)
        assert page.count("Author:") == 1, url                             # one credit, not repeated in page footers
        assert "<footer" not in page, url
        assert page.index("Log out") < page.index("www.tca.ac.tz") < page.index("</aside>"), url   # inside the sidebar, below Log out
    anon = create_app(tmp_path / "d2", password="pw").test_client()
    assert "www.tca.ac.tz" in anon.get("/login").get_data(as_text=True)    # the login page keeps its own credit
