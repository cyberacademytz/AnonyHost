#!/usr/bin/env python3
"""AnonyHost desktop launcher: one instance, loopback-only dashboard, opens the default browser."""
import argparse, fcntl, logging, os, signal, subprocess, sys, threading, time
from pathlib import Path
from werkzeug.serving import make_server
from app import create_app
from backend import process_manager as pm
from backend import reset as resetlib
from backend.browser import open_window
from config.settings import build_id, data_dir

def ours(pid):  # never signal a PID that isn't this program
    try:
        return b"launcher.py" in Path(f"/proc/{pid}/cmdline").read_bytes()
    except OSError:
        return False

def main():
    ap = argparse.ArgumentParser(prog="anonyhost", description="AnonyHost - DarkWeb Hosting Tool")
    ap.add_argument("--foreground", action="store_true", help="stay attached to the terminal (default: detach silently)")
    ap.add_argument("--no-browser", action="store_true", help="do not open the browser")
    ap.add_argument("--factory-reset", action="store_true", help="return AnonyHost to its first-run state (asks you to confirm)")
    ap.add_argument("--delete-keys", action="store_true", help="with --factory-reset: also delete the onion keys (the .onion address is lost forever)")
    ap.add_argument("--stop", action="store_true", help="stop the dashboard (hosting keeps running)")
    ap.add_argument("--stop-all", action="store_true", help="stop the dashboard and the hosted website")
    ap.add_argument("--reset-password", action="store_true", help="remove the administrator account; a new one is created at next launch")
    a = ap.parse_args()
    base = data_dir(); (base / "run").mkdir(parents=True, exist_ok=True); os.chmod(base, 0o700)
    pidf, urlf, buildf = base / "run/anonyhost.pid", base / "run/dashboard.url", base / "run/anonyhost.build"
    if a.reset_password:
        (base / "admin.json").unlink(missing_ok=True)
        print("Administrator account removed. Start AnonyHost to create a new one."); return 0
    if a.factory_reset:
        print("This stops AnonyHost and deletes your website, settings, logs and administrator account.")
        print("It ALSO DELETES your onion keys: the .onion address is lost forever." if a.delete_keys else "Your onion address keys are kept.")
        if input("Type RESET to continue: ").strip() != "RESET":
            print("Cancelled."); return 1
        pid = pm.read_pid(pidf)
        if pid and ours(pid):
            os.kill(pid, signal.SIGTERM)
            for _ in range(50):
                if not pidf.exists(): break
                time.sleep(0.1)
        pm.terminate(base / "run/nginx.pid", "nginx"); pm.terminate(base / "run/tor.pid", "tor")
        resetlib.factory_reset(base, a.delete_keys)
        print("Done. AnonyHost is back to its first-run state."); return 0
    if a.stop or a.stop_all:
        pid = pm.read_pid(pidf)
        if pid and ours(pid):
            os.kill(pid, signal.SIGTERM)
        if a.stop_all:
            pm.terminate(base / "run/nginx.pid", "nginx"); pm.terminate(base / "run/tor.pid", "tor")
        print("Stopped."); return 0
    if not a.foreground:  # like a desktop app: give the terminal back, stay silent, run in the background
        (base / "logs").mkdir(parents=True, exist_ok=True)
        log = open(base / "logs/launcher.log", "ab")
        subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--foreground", *sys.argv[1:]],
                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
        return 0
    lock = open(base / "run/anonyhost.lock", "w")
    def take():
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB); return True
        except OSError:
            return False
    got = take()
    if not got and (not buildf.exists() or buildf.read_text().strip() != build_id()):
        pid = pm.read_pid(pidf)  # an older copy of the dashboard is running: replace it (hosting keeps running)
        if pid and ours(pid):
            os.kill(pid, signal.SIGTERM)
        for _ in range(100):
            got = take()
            if got: break
            time.sleep(0.1)
    if not got:
        url = urlf.read_text().strip() if urlf.exists() else ""
        if url and not a.no_browser:
            open_window(url, base / "window-profile")
        print("AnonyHost is already running."); return 0
    logging.getLogger("werkzeug").setLevel(logging.ERROR)  # no per-request logging
    app = create_app(base)
    done = threading.Event(); app.config["ON_QUIT"] = done.set
    srv = None
    for p in range(5000, 5030):
        try:
            srv = make_server("127.0.0.1", p, app, threaded=True); break
        except OSError:
            continue
    if not srv:
        print("No free local port for the dashboard (5000-5029)."); return 1
    url = f"http://127.0.0.1:{p}"
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    urlf.write_text(url); buildf.write_text(build_id()); pidf.write_text(str(os.getpid()))
    for sg in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sg, lambda *_: done.set())
    threading.Thread(target=app.autostart, daemon=True).start()
    if not a.no_browser:
        open_window(url, base / "window-profile")
    done.wait(); srv.shutdown()
    pidf.unlink(missing_ok=True); urlf.unlink(missing_ok=True)
    return 0

if __name__ == "__main__":
    sys.exit(main())
