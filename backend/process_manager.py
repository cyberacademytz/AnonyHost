"""PID-file based process helpers (no shell, no systemd; runs unprivileged)."""
import os, signal, time
from pathlib import Path

class ServiceError(RuntimeError):
    pass

def read_pid(pidfile):
    try:
        return int(Path(pidfile).read_text().strip())
    except (OSError, ValueError):
        return None

def alive(pidfile, name=None):
    pid = read_pid(pidfile)
    if not pid:
        return False
    try:
        os.kill(pid, 0)
        if name:  # guard against PID reuse by an unrelated process
            return Path(f"/proc/{pid}/comm").read_text().strip() == name
        return True
    except OSError:
        return False

def terminate(pidfile, name=None, timeout=10):
    if not alive(pidfile, name):
        return
    pid = read_pid(pidfile)
    os.kill(pid, signal.SIGTERM)
    end = time.time() + timeout
    while time.time() < end:
        if not alive(pidfile, name):
            return
        time.sleep(0.2)
    os.kill(pid, signal.SIGKILL)

def wait_for_pid(pidfile, name, timeout=8):
    end = time.time() + timeout
    while time.time() < end:
        if alive(pidfile, name):
            return True
        time.sleep(0.2)
    return False

import re, socket, subprocess

def port_free(port):
    with socket.socket() as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", int(port)))
            return True
        except OSError:
            return False

def port_owner(port):
    """Return {'name','pid'} of the listener on a loopback port, or None if unknown."""
    try:
        out = subprocess.run(["ss", "-H", "-ltnp", f"sport = :{int(port)}"],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r'\("([^"]+)",pid=(\d+)', out)
    return {"name": m.group(1), "pid": int(m.group(2))} if m else None

def stop_listener(pid, port, timeout=5):
    """SIGTERM, then SIGKILL, until the port is free. Raises ServiceError on failure."""
    try:
        os.kill(pid, signal.SIGTERM)
        for sig in (None, signal.SIGKILL):
            end = time.time() + timeout
            while time.time() < end:
                if port_free(port):
                    return
                time.sleep(0.2)
            if sig:
                os.kill(pid, sig)
        time.sleep(1)
    except PermissionError:
        raise ServiceError("Permission denied: that program belongs to another user.")
    except ProcessLookupError:
        pass
    if not port_free(port):
        raise ServiceError(f"Port {port} is still in use after stopping the program.")
