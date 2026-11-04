import os, shutil, subprocess, sys, urllib.request
from pathlib import Path
import pytest
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
from backend.control import Control
from config.settings import save_settings

def test_idle_status_and_port_sync(tmp_path):
    c = Control(tmp_path)
    s = c.status()
    assert not (s["dash"] or s["web"] or s["tor"]) and s["onion"] is None and s["port"] == 8080 and not s["site"]
    save_settings(tmp_path, port=9090)
    assert c.sync_settings() and c.tor.port == c.web.port == 9090
    c.set_port(9191); assert c.status()["port"] == 9191

def test_log_reading_and_filters(tmp_path):
    c = Control(tmp_path)
    assert c.read_log("Tor") == [] and c.log_stamp("Tor") is None
    (tmp_path / "logs/tor.log").write_text("Bootstrapped 10%\n[warn] slow\n[err] Could not bind\nBootstrapped 100%\n")
    assert len(c.read_log("Tor")) == 4 and c.log_stamp("Tor")
    assert c.read_log("Tor", errors_only=True) == ["[err] Could not bind"]
    assert c.read_log("Tor", needle="BOOTSTRAPPED") == ["Bootstrapped 10%", "Bootstrapped 100%"]

def test_start_and_stop_dashboard_for_real(tmp_path):
    c = Control(tmp_path)
    c.start_dashboard()
    s = c.status(); pid = c.dash_pid()
    assert s["dash"] and s["dash_url"].startswith("http://127.0.0.1:")
    assert "administrator account" in urllib.request.urlopen(s["dash_url"] + "/").read().decode()
    c.start_dashboard()  # already running: no second instance
    assert c.dash_pid() == pid
    c.stop_dashboard()
    assert not c.status()["dash"]

def test_panel_compiles_and_opens_headless(tmp_path):
    subprocess.run([sys.executable, "-m", "py_compile", str(ROOT / "panel.py")], check=True)
    pytest.importorskip("tkinter")
    if not shutil.which("xvfb-run"):
        pytest.skip("xvfb-run not available: GUI window not exercised")
    code = "import panel; p = panel.Panel(); p.r.update(); p.update_view(); p.logs_tick(); p.r.destroy()"
    r = subprocess.run(["xvfb-run", "-a", sys.executable, "-c", code], cwd=ROOT, capture_output=True, text=True,
                       env={**os.environ, "ANONYHOST_DATA": str(tmp_path)}, timeout=60)
    assert r.returncode == 0, r.stderr
