"""Control logic shared by the desktop control panel (no GUI code here, so it can be tested)."""
import os, re, subprocess, sys, time
from pathlib import Path
from . import process_manager as pm
from .nginx_manager import NginxManager
from .tor_manager import TorManager
from config.settings import data_dir, load_settings, save_settings

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = [sys.executable, str(ROOT / "launcher.py")]
LOGS = {"AnonyHost": "app.log", "Launcher": "launcher.log", "Tor": "tor.log", "Nginx errors": "nginx-error.log"}
ERR = re.compile(r"(?i)\b(err|error|fail|failed|alert|emerg|crit|critical|denied|traceback)\b")
WARN = re.compile(r"(?i)\bwarn(ing)?\b")

class Control:
    def __init__(self, base=None):
        self.base = Path(base or data_dir())
        for d in ("site", "run", "logs", "backups"):
            (self.base / d).mkdir(parents=True, exist_ok=True)
        os.chmod(self.base, 0o700)
        self.env = {**os.environ, "ANONYHOST_DATA": str(self.base)}
        self.port = 8080
        self.tor, self.web = TorManager(self.base, self.port), NginxManager(self.base, self.port)
        self.sync_settings()

    def sync_settings(self):
        """Follow port changes made in the dashboard or settings. Returns True if the port changed."""
        try:
            p = int(load_settings(self.base).get("port", 8080))
        except (TypeError, ValueError):
            p = 8080
        changed = p != self.port
        self.port = self.tor.port = self.web.port = p
        return changed

    def set_port(self, p):
        save_settings(self.base, port=int(p)); self.sync_settings()

    def reset_account(self):
        """Remove the administrator account only; website, settings and onion keys are kept."""
        (self.base / "admin.json").unlink(missing_ok=True)

    def has_site(self):
        return (self.base / "site/index.html").exists()

    def dash_pid(self):
        pid = pm.read_pid(self.base / "run/anonyhost.pid")
        try:
            return pid if pid and b"launcher.py" in Path(f"/proc/{pid}/cmdline").read_bytes() else None
        except OSError:
            return None

    def dash_url(self):
        try:
            return (self.base / "run/dashboard.url").read_text().strip() or None
        except OSError:
            return None

    @staticmethod
    def _wait(cond, timeout=10):
        end = time.time() + timeout
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.2)
        return False

    def _launcher(self, *args):
        return subprocess.run(LAUNCHER + list(args), env=self.env, capture_output=True, text=True, timeout=30)

    def start_dashboard(self):
        if self.dash_pid():
            return
        self._launcher("--no-browser")
        if not self._wait(lambda: self.dash_pid() and self.dash_url()):
            raise pm.ServiceError("The dashboard did not start. See the Launcher log.")

    def stop_dashboard(self):
        self._launcher("--stop"); self._wait(lambda: not self.dash_pid())

    def start_web(self):
        self.web.start()

    def start_tor(self):
        self.tor.start()

    def stop_hosting(self):
        self.tor.stop(); self.web.stop()

    def status(self):
        self.sync_settings()
        tor_on = self.tor.running()
        return {"dash": bool(self.dash_pid()), "dash_url": self.dash_url(), "web": self.web.running(), "tor": tor_on,
                "boot": self.tor.bootstrap() if tor_on else 0, "onion": self.tor.onion(), "site": self.has_site(), "port": self.port}

    def log_stamp(self, name):
        try:
            st = (self.base / "logs" / LOGS[name]).stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def read_log(self, name, needle="", errors_only=False, max_lines=400):
        try:
            with open(self.base / "logs" / LOGS[name], "rb") as f:
                f.seek(0, 2); f.seek(max(0, f.tell() - 131072))
                lines = f.read().decode("utf-8", "replace").splitlines()
        except OSError:
            return []
        n = needle.lower()
        return [l for l in lines if (not n or n in l.lower()) and (not errors_only or ERR.search(l))][-max_lines:]
