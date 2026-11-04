import sys, zipfile
from pathlib import Path
import pytest
sys.path.insert(0, str(Path(__file__).parent.parent))
from app import create_app
from backend import security, platform_detector as pd
from backend.nginx_manager import nginx_conf
from backend.tor_manager import torrc_text
from backend.process_manager import ServiceError

def mkzip(path, files, symlink=None):
    with zipfile.ZipFile(path, "w") as z:
        for n, d in files.items(): z.writestr(n, d)
        if symlink:
            i = zipfile.ZipInfo(symlink); i.external_attr = 0o120777 << 16; z.writestr(i, "/etc/passwd")
    return path

def test_valid_extract(tmp_path):
    security.safe_extract(mkzip(tmp_path / "a.zip", {"index.html": "hi", "css/s.css": "x"}), tmp_path / "o")
    assert (tmp_path / "o/css/s.css").exists()

@pytest.mark.parametrize("name", ["../evil.txt", "/abs.txt", "a/../../b", "C:\\x.txt"])
def test_traversal_rejected(tmp_path, name):
    with pytest.raises(security.UnsafeArchive):
        security.safe_extract(mkzip(tmp_path / "a.zip", {"index.html": "x", name: "y"}), tmp_path / "o")

def test_symlink_missing_index_and_size(tmp_path):
    with pytest.raises(security.UnsafeArchive):
        security.safe_extract(mkzip(tmp_path / "a.zip", {"index.html": "x"}, symlink="l"), tmp_path / "o")
    with pytest.raises(security.UnsafeArchive):
        security.safe_extract(mkzip(tmp_path / "b.zip", {"a.html": "x"}), tmp_path / "o2")
    with pytest.raises(security.UnsafeArchive):
        security.safe_extract(mkzip(tmp_path / "c.zip", {"index.html": "x" * 5000}), tmp_path / "o3", max_bytes=100)

def test_safe_join(tmp_path):
    assert security.safe_join(tmp_path, "a/b").parent.parent == tmp_path.resolve()
    with pytest.raises(ValueError): security.safe_join(tmp_path, "../x")

def test_onion_validation():
    assert security.valid_onion("a" * 56 + ".onion")
    assert not security.valid_onion("short.onion") and not security.valid_onion("A" * 56 + ".onion")

def test_configs():
    t = torrc_text("/d", 8080)
    assert "HiddenServiceDir /d/onion-service" in t and "HiddenServicePort 80 127.0.0.1:8080" in t and "SocksPort 0" in t
    n = nginx_conf("/d", 8080)
    assert "listen 127.0.0.1:8080;" in n and "autoindex off;" in n and "access_log off;" in n

def test_platform(tmp_path):
    f = tmp_path / "os"; f.write_text('ID=ubuntu\nID_LIKE=debian\n'); assert pd.check_platform(str(f))["ID"] == "ubuntu"
    f.write_text('ID=arch\n')
    with pytest.raises(ServiceError): pd.check_platform(str(f))

def test_auth_csrf_deploy(tmp_path):
    c = create_app(tmp_path / "d", password="pw").test_client()
    assert c.get("/").status_code == 302 and c.get("/api/status").status_code == 302
    c.get("/login")
    with c.session_transaction() as s: tok = s["csrf"]
    assert c.post("/login", data={"password": "pw"}).status_code == 400
    assert c.post("/login", data={"username": "admin", "password": "pw", "csrf": tok}).status_code == 302
    assert c.get("/").status_code == 200  # new session token issued after login
    with c.session_transaction() as s: tok = s["csrf"]
    assert c.get("/", headers={"Host": "evil.com"}).status_code == 400
    z = mkzip(tmp_path / "s.zip", {"index.html": "<h1>hi</h1>"})
    r = c.post("/deploy", data={"zip": (open(z, "rb"), "s.zip"), "csrf": tok}, content_type="multipart/form-data")
    assert r.status_code == 302 and (tmp_path / "d/site/index.html").read_text() == "<h1>hi</h1>"
    st = c.get("/api/status").get_json()
    assert st["site"] and not st["tor"] and st["onion"] is None

def test_port_conflict_flow(tmp_path, monkeypatch):
    import socket, json
    from backend.process_manager import port_free
    s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(); busy = s.getsockname()[1]
    assert not port_free(busy)
    monkeypatch.setattr(pd, "check_platform", lambda *a: {})
    c = create_app(tmp_path / "d", port=busy, password="pw").test_client()
    c.get("/login")
    with c.session_transaction() as ss: tok = ss["csrf"]
    c.post("/login", data={"username": "admin", "password": "pw", "csrf": tok})
    c.get("/")
    with c.session_transaction() as ss: tok = ss["csrf"]
    c.post("/start", data={"csrf": tok})
    page = c.get("/").get_data(as_text=True)
    assert f"Port {busy} is already in use" in page and "Use port" in page
    with c.session_transaction() as ss: tok = ss["csrf"]
    c.post("/resolve", data={"csrf": tok, "action": "alt"})
    new = json.loads((tmp_path / "d/settings.json").read_text())["port"]
    assert new != busy and port_free(new)
    s.close()

def test_deploy_wrapper_folder_and_bad_zips(tmp_path):
    c = create_app(tmp_path / "d", password="pw").test_client()
    c.get("/login")
    with c.session_transaction() as s: t = s["csrf"]
    c.post("/login", data={"username": "admin", "password": "pw", "csrf": t}); c.get("/")
    with c.session_transaction() as s: t = s["csrf"]
    def up(name, files):
        z = mkzip(tmp_path / f"{name}.zip", files)
        r = c.post("/deploy", data={"zip": (open(z, "rb"), "s.zip"), "csrf": t}, content_type="multipart/form-data")
        assert r.status_code == 302
        return c.get("/").get_data(as_text=True)
    assert "Deployment failed" in up("clash", {"index.html": "x", "a": "1", "a/b": "2"})
    assert "Deployment failed" in up("long", {"index.html": "x", "n" * 300: "y"})
    up("wrap", {"mysite/index.html": "<h1>ok</h1>", "mysite/css/a.css": "x"})
    assert (tmp_path / "d/site/index.html").read_text() == "<h1>ok</h1>" and (tmp_path / "d/site/css/a.css").exists()

import time, subprocess, urllib.request, os

def _tok(c):
    c.get("/login")
    with c.session_transaction() as s: return s["csrf"]

def _csrf(c):
    c.get("/")
    with c.session_transaction() as s: return s["csrf"]

def _login(c, user="admin", pw="pw"):
    assert c.post("/login", data={"csrf": _tok(c), "username": user, "password": pw}).status_code == 302

def test_size_limit_is_1gb():
    import inspect, app as appmod
    assert inspect.signature(security.safe_extract).parameters["max_bytes"].default == 1024**3 == appmod.MAX_BYTES

def test_first_run_setup_and_password_change(tmp_path):
    c = create_app(tmp_path / "d").test_client()
    assert c.get("/").headers["Location"].endswith("/setup")
    t = _tok(c)
    bad = lambda **k: c.post("/setup", data={"csrf": t, **k}).status_code == 200
    assert bad(username="ab", password="longenough1", confirm="longenough1")
    assert bad(username="admin", password="short", confirm="short")
    assert bad(username="admin", password="longenough1", confirm="different11")
    assert not (tmp_path / "d/admin.json").exists()
    assert c.post("/setup", data={"csrf": t, "username": "boss", "password": "longenough1", "confirm": "longenough1"}).status_code == 302
    raw = (tmp_path / "d/admin.json").read_text()
    assert "longenough1" not in raw and "boss" in raw
    assert c.get("/").status_code == 200 and c.get("/setup").headers["Location"].endswith("/login")
    c.post("/settings/password", data={"csrf": _csrf(c), "current": "wrong", "new": "anotherlong1", "confirm": "anotherlong1"})
    assert "incorrect" in c.get("/settings").get_data(as_text=True)
    r = c.post("/settings/password", data={"csrf": _csrf(c), "current": "longenough1", "new": "anotherlong1", "confirm": "anotherlong1"})
    assert r.headers["Location"].endswith("/login")
    assert c.post("/login", data={"csrf": _tok(c), "username": "boss", "password": "longenough1"}).status_code == 200
    _login(c, "boss", "anotherlong1")

def test_open_in_tor_browser(tmp_path, monkeypatch):
    import app as appmod
    d = tmp_path / "d"; c = create_app(d, password="pw").test_client(); _login(c)
    c.post("/open-tor", data={"csrf": _csrf(c)})
    assert "No onion address" in c.get("/").get_data(as_text=True)
    onion = "a" * 56 + ".onion"
    (d / "onion-service").mkdir(); (d / "onion-service/hostname").write_text(onion + "\n")
    monkeypatch.setattr(appmod, "find_tor_browser", lambda custom=None: None)
    c.post("/open-tor", data={"csrf": _csrf(c)})
    assert "Tor Browser was not found" in c.get("/").get_data(as_text=True)
    calls = []
    monkeypatch.setattr(appmod, "find_tor_browser", lambda custom=None: "/x/tb")
    monkeypatch.setattr(appmod, "open_in_tor_browser", lambda exe, url: calls.append((exe, url)))
    c.post("/open-tor", data={"csrf": _csrf(c)})
    assert calls == [("/x/tb", f"http://{onion}/")]

def test_quit_page_and_callback(tmp_path):
    hits = []
    a = create_app(tmp_path / "d", password="pw"); a.config.update(ON_QUIT=lambda: hits.append(1), QUIT_DELAY=0.01)
    c = a.test_client(); _login(c)
    r = c.post("/quit", data={"csrf": _csrf(c), "stop_hosting": "0"})
    assert r.status_code == 200 and b"AnonyHost has stopped" in r.data
    time.sleep(0.3); assert hits == [1]

def test_launcher_detaches_silently_and_lifecycle(tmp_path):
    root = Path(__file__).parent.parent
    env = {**os.environ, "ANONYHOST_DATA": str(tmp_path / "d")}
    cmd = [sys.executable, str(root / "launcher.py")]
    t0 = time.time()
    r = subprocess.run(cmd + ["--no-browser"], env=env, capture_output=True, text=True, timeout=15)
    assert r.returncode == 0 and r.stdout == "" and r.stderr == "" and time.time() - t0 < 10  # prompt returns, terminal silent
    urlf, pidf = tmp_path / "d/run/dashboard.url", tmp_path / "d/run/anonyhost.pid"
    for _ in range(100):
        if urlf.exists() and pidf.exists() and pidf.read_text().strip(): break
        time.sleep(0.1)
    url, pid = urlf.read_text().strip(), pidf.read_text().strip()
    assert url.startswith("http://127.0.0.1:")
    html = urllib.request.urlopen(url + "/").read().decode()
    assert "create your administrator account" in html and "globe" not in html and "www.tca.ac.tz" in html
    assert ".author{" in urllib.request.urlopen(url + "/static/css/torhost.css").read().decode()
    r2 = subprocess.run(cmd + ["--no-browser"], env=env, capture_output=True, text=True, timeout=15)
    assert r2.returncode == 0 and r2.stdout == ""
    time.sleep(1); assert pidf.read_text().strip() == pid  # still one instance
    subprocess.run(cmd + ["--stop"], env=env, timeout=15)
    for _ in range(100):
        if not pidf.exists(): break
        time.sleep(0.1)
    assert not pidf.exists()
    (tmp_path / "d/admin.json").write_text("{}")
    subprocess.run(cmd + ["--reset-password"], env=env, timeout=20)
    assert not (tmp_path / "d/admin.json").exists()

def test_open_window_prefers_app_window(monkeypatch):
    import backend.browser as b
    monkeypatch.setattr(b.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(b.shutil, "which", lambda n: "/usr/bin/chromium" if n == "chromium" else None)
    calls, opened = [], []
    monkeypatch.setattr(b.subprocess, "Popen", lambda args, **k: calls.append(args))
    monkeypatch.setattr(b.webbrowser, "open", lambda u: opened.append(u))
    assert b.open_window("http://127.0.0.1:5000", "/p") == "window" and "--app=http://127.0.0.1:5000" in calls[0] and not opened
    monkeypatch.setattr(b.shutil, "which", lambda n: None)
    assert b.open_window("http://127.0.0.1:5000", "/p") == "browser" and opened == ["http://127.0.0.1:5000"]

def _site_with_key(d, c):
    z = mkzip(d.parent / f"{d.name}.zip", {"index.html": "<h1>x</h1>"})
    c.post("/deploy", data={"zip": (open(z, "rb"), "s.zip"), "csrf": _csrf(c)}, content_type="multipart/form-data")
    (d / "onion-service").mkdir(exist_ok=True); (d / "onion-service/hostname").write_text("a" * 56 + ".onion\n")

def test_reset_settings_and_factory_reset(tmp_path):
    d = tmp_path / "d1"; c = create_app(d, password="pw").test_client(); _login(c); _site_with_key(d, c)
    c.post("/settings/startup", data={"csrf": _csrf(c), "autostart": "on"})
    assert (d / "settings.json").exists()
    c.post("/reset/settings", data={"csrf": _csrf(c)})
    assert not (d / "settings.json").exists() and (d / "site/index.html").exists()
    bad = dict(password="wrong", confirm="RESET")
    c.post("/reset/factory", data={"csrf": _csrf(c), **bad})
    c.post("/reset/factory", data={"csrf": _csrf(c), "password": "pw", "confirm": "reset"})
    assert (d / "admin.json").exists() and (d / "site/index.html").exists()  # refused: wrong password / confirmation
    r = c.post("/reset/factory", data={"csrf": _csrf(c), "password": "pw", "confirm": "RESET"})
    assert r.headers["Location"].endswith("/setup")
    assert not (d / "admin.json").exists() and not (d / "site/index.html").exists()
    assert (d / "onion-service/hostname").exists()  # keys kept by default
    assert c.get("/").headers["Location"].endswith("/setup")
    d2 = tmp_path / "d2"; c2 = create_app(d2, password="pw").test_client(); _login(c2); _site_with_key(d2, c2)
    c2.post("/reset/factory", data={"csrf": _csrf(c2), "password": "pw", "confirm": "RESET", "delete_keys": "on"})
    assert not (d2 / "onion-service").exists()

def test_cli_factory_reset(tmp_path):
    d = tmp_path / "d"; (d / "onion-service").mkdir(parents=True); (d / "onion-service/hostname").write_text("x")
    (d / "admin.json").write_text("{}"); (d / "backups").mkdir(); (d / "backups/k.tar").write_text("k")
    env = {**os.environ, "ANONYHOST_DATA": str(d)}
    cmd = [sys.executable, str(Path(__file__).parent.parent / "launcher.py"), "--factory-reset", "--delete-keys"]
    subprocess.run(cmd, env=env, input="no\n", text=True, capture_output=True, timeout=20)
    assert (d / "admin.json").exists() and (d / "onion-service").exists()  # cancelled
    r = subprocess.run(cmd, env=env, input="RESET\n", text=True, capture_output=True, timeout=20)
    assert r.returncode == 0 and not (d / "admin.json").exists() and not (d / "onion-service").exists()
    assert (d / "backups/k.tar").exists()

def test_recovery_key_flow_and_clean_auth_pages(tmp_path):
    import re as _re
    a = create_app(tmp_path / "d"); c = a.test_client()
    page = c.get("/setup").get_data(as_text=True)
    assert "globe" not in page and "www.tca.ac.tz" in page and "reset-password" not in page
    t = _tok(c)
    assert c.post("/setup", data={"csrf": t, "username": "boss", "password": "longenough1", "confirm": "longenough1"}).headers["Location"].endswith("/recovery-key")
    shown = c.get("/recovery-key").get_data(as_text=True)
    key = _re.search(r"[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}", shown).group(0)
    assert c.get("/recovery-key").status_code == 302  # shown once only
    assert key not in (tmp_path / "d/admin.json").read_text()  # only a hash is stored
    c2 = a.test_client()
    login = c2.get("/login").get_data(as_text=True)
    assert "globe" not in login and "www.tca.ac.tz" in login and "/recover" in login and "reset-password" not in login
    t2 = _tok(c2)
    assert c2.post("/recover", data={"csrf": t2, "key": "AAAAA-AAAAA-AAAAA-AAAAA", "new": "brandnewpass1", "confirm": "brandnewpass1"}).status_code == 200
    assert c2.post("/login", data={"csrf": _tok(c2), "username": "boss", "password": "brandnewpass1"}).status_code == 200  # still refused
    r = c2.post("/recover", data={"csrf": _tok(c2), "key": key.lower().replace("-", " "), "new": "brandnewpass1", "confirm": "brandnewpass1"})
    assert r.headers["Location"].endswith("/recovery-key")
    new_key = _re.search(r"[A-Z2-7]{5}(?:-[A-Z2-7]{5}){3}", c2.get("/recovery-key").get_data(as_text=True)).group(0)
    assert new_key != key
    c3 = a.test_client(); _login(c3, "boss", "brandnewpass1")
    assert c3.post("/recover", data={"csrf": _tok(c3), "key": key, "new": "otherpass123", "confirm": "otherpass123"}).status_code == 200  # old key dead
    c3.post("/settings/recovery", data={"csrf": _csrf(c3), "current": "wrong"})
    assert c3.get("/recovery-key").status_code == 302  # wrong password: no key issued
    assert c3.post("/settings/recovery", data={"csrf": _csrf(c3), "current": "brandnewpass1"}).headers["Location"].endswith("/recovery-key")

def test_control_reset_account_keeps_site_and_keys(tmp_path):
    from backend.control import Control
    (tmp_path / "admin.json").write_text("{}"); (tmp_path / "onion-service").mkdir(); (tmp_path / "onion-service/hostname").write_text("x")
    c = Control(tmp_path); (tmp_path / "site/index.html").write_text("hi")
    c.reset_account()
    assert not (tmp_path / "admin.json").exists() and (tmp_path / "site/index.html").exists() and (tmp_path / "onion-service/hostname").exists()

def test_launcher_replaces_a_stale_running_copy(tmp_path):
    root = Path(__file__).parent.parent
    env = {**os.environ, "ANONYHOST_DATA": str(tmp_path / "d")}
    cmd = [sys.executable, str(root / "launcher.py"), "--no-browser"]
    pidf, buildf = tmp_path / "d/run/anonyhost.pid", tmp_path / "d/run/anonyhost.build"
    def up():
        for _ in range(150):
            if pidf.exists() and buildf.exists() and pidf.read_text().strip(): return pidf.read_text().strip()
            time.sleep(0.1)
    subprocess.run(cmd, env=env, timeout=20); old = up()
    from config.settings import build_id
    assert buildf.read_text() == build_id()
    subprocess.run(cmd, env=env, timeout=20); time.sleep(1)
    assert pidf.read_text().strip() == old  # same build: left alone
    buildf.write_text("old-build")  # pretend the running copy is from an older install
    subprocess.run(cmd, env=env, timeout=30)
    for _ in range(150):
        if pidf.exists() and pidf.read_text().strip() not in ("", old) and buildf.exists() and buildf.read_text() == build_id(): break
        time.sleep(0.1)
    assert pidf.read_text().strip() != old and buildf.read_text() == build_id()
    subprocess.run(cmd[:2] + ["--stop"], env=env, timeout=20)
