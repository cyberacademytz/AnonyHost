import os, re, shutil, subprocess
from pathlib import Path
from . import process_manager as pm
from .security import valid_onion

BOOT = re.compile(r"Bootstrapped (\d+)%")

def torrc_text(base, port):
    b = Path(base)
    return (f"DataDirectory {b}/tor-data\nPidFile {b}/run/tor.pid\n"
            f"Log notice file {b}/logs/tor.log\nSocksPort 0\n"
            f"HiddenServiceDir {b}/onion-service\n"
            f"HiddenServicePort 80 127.0.0.1:{int(port)}\n")

class TorManager:
    def __init__(self, base, port):
        self.base, self.port = Path(base), int(port)
        self.pid, self.rc, self.log = self.base / "run/tor.pid", self.base / "torrc", self.base / "logs/tor.log"

    def running(self):
        return pm.alive(self.pid, "tor")

    def start(self):
        exe = shutil.which("tor")
        if not exe:
            raise pm.ServiceError("Tor is not installed. Run scripts/install_linux.sh first.")
        if self.running():
            return
        for d in ("tor-data", "onion-service"):  # Tor requires 0700 and refuses otherwise
            p = self.base / d
            p.mkdir(exist_ok=True)
            os.chmod(p, 0o700)
        self.rc.write_text(torrc_text(self.base, self.port))
        chk = subprocess.run([exe, "--verify-config", "-f", str(self.rc)], capture_output=True, text=True)
        if chk.returncode:
            raise pm.ServiceError("Tor rejected the configuration: " + chk.stdout[-300:])
        self.log.unlink(missing_ok=True)
        subprocess.run([exe, "-f", str(self.rc), "--RunAsDaemon", "1"], capture_output=True, timeout=20)
        if not pm.wait_for_pid(self.pid, "tor"):
            raise pm.ServiceError("Tor did not start. See the Tor log: " + self._tail())

    def stop(self):
        pm.terminate(self.pid, "tor")

    def _tail(self):
        try:
            return self.log.read_text()[-300:]
        except OSError:
            return "(no log yet)"

    def bootstrap(self):
        try:
            m = BOOT.findall(self.log.read_text())
            return int(m[-1]) if m else 0
        except OSError:
            return 0

    def onion(self):
        try:
            a = (self.base / "onion-service/hostname").read_text().strip()
        except OSError:
            return None
        return a if valid_onion(a) else None
