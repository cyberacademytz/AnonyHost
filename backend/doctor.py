# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Health checks and automatic repairs for hosting, static or dynamic.

What it does, in three layers:
  start()      starts the site and repairs known problems on the way (busy port, stale files, ...)
  diagnose()   finds problems in a running or stopped setup and says how to fix each one
  tick()       the watchdog: restarts what crashed, answers 5xx errors, with a back-off so it never loops forever
Fixes that need administrator rights (installing packages) are never run silently: the user approves them
in the system's password prompt (pkexec)."""
import http.client, os, re, shutil, subprocess, threading, time
from pathlib import Path
from . import logscan, platform_detector as pd, process_manager as pm
from .process_manager import ServiceError, port_free, port_owner
from .runtime import SAFE_PIP, missing_runtime, note as write_note

# Packages the tool may ask the system to install (explicit allow-list; nothing else is ever passed to apt).
APT_ALLOW = {"tor", "nginx", "nginx-common", "php-fpm", "nodejs", "npm", "python3", "python3-venv", "php-mysql", "php-curl", "php-mbstring",
             "php-gd", "php-xml", "php-zip", "php-sqlite3", "php-pgsql", "php-intl", "php-bcmath", "php-imagick"}

FIX_LABELS = {"restart_site": "Restart the site", "restart_tor": "Restart Tor", "port_free": "Use a free port", "clean_stale": "Clean up leftovers",
              "fix_perms": "Repair file permissions", "site_deps": "Reinstall the site's dependencies", "pip_install": "Install the Python package",
              "npm_install": "Run npm install", "host_header_local": "Send a local Host header", "install": "Install (asks for your password)"}
LEVELS = {"error": 0, "warn": 1, "info": 2, "ok": 3}
MAX_RETRIES, RETRY_WINDOW = 3, 600  # automatic repairs of the same problem: 3 per 10 minutes, then stop and ask the user


class PortBusy(ServiceError):
    """The hosting port is taken and automatic fixing is turned off."""


def probe(port, timeout=4):
    """GET / on the local hosting port. Returns (status, None) or (None, error text)."""
    try:
        c = http.client.HTTPConnection("127.0.0.1", int(port), timeout=timeout)
        c.request("GET", "/", headers={"User-Agent": "AnonyHost-health", "Connection": "close"})
        r = c.getresponse(); r.read(2048); c.close()
        return r.status, None
    except (OSError, http.client.HTTPException) as e:
        return None, str(e) or type(e).__name__


def since_marker(path, limit=20000):
    """Text of a log after its last '--- ' start marker (problems from before the last restart are history)."""
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return ""
    marks = list(re.finditer(r"(?m)^--- ", text))
    return (text[marks[-1].start():] if marks else text)[-limit:]


class Doctor:
    def __init__(self, base, web, tor, get_settings, save_settings):
        self.base, self.web, self.tor = Path(base), web, tor
        self._get, self._save = get_settings, save_settings
        self.lock = threading.RLock()          # one start / stop / repair at a time
        self._hist, self.gave_up = {}, {}
        self.cache = (0.0, [])
        self.install = {"state": "idle", "pkgs": [], "manual": "", "rc": None}

    # ---------- small helpers ----------
    def auto_on(self):
        return bool(self._get().get("auto_fix", True))

    def want(self):
        return pm.wanted(self.base)

    def note(self, msg):
        write_note(self.base, msg)

    def _f(self, id, level, title, detail="", fix=None, auto=False, pkgs=None):
        return {"id": id, "level": level, "title": title, "detail": detail, "fix": fix, "fix_label": FIX_LABELS.get(fix, ""),
                "auto": bool(auto and fix and fix != "install"), "root": fix == "install", "pkgs": pkgs or []}

    @staticmethod
    def _from_hit(h, auto=False):
        return {"id": h["id"], "level": h["level"], "title": h["title"], "detail": h["detail"], "fix": h.get("fix"),
                "fix_label": FIX_LABELS.get(h.get("fix"), ""), "auto": bool(auto and h.get("fix") and h.get("fix") != "install"),
                "root": h.get("fix") == "install", "pkgs": h.get("pkgs") or [], "module": h.get("module")}

    # ---------- port ----------
    def set_port(self, p):
        self.web.port = self.tor.port = int(p)
        self._save(port=int(p))

    def pick_port(self):
        for p in range(self.web.port + 1, self.web.port + 60):
            if port_free(p):
                return p
        raise ServiceError("No free port was found near the current one. Free a port manually and try again.")

    def _switch_port(self):
        old, owner = self.web.port, port_owner(self.web.port)
        new = self.pick_port()
        if self.tor.running():
            self.tor.stop()  # Tor reads the port at start, so it has to restart on the new one
        self.set_port(new)
        msg = f"Port {old} was in use{' by ' + owner['name'] if owner else ''}, so AnonyHost switched to port {new}. Your onion address stays the same."
        self.note(msg)
        return msg

    # ---------- leftovers ----------
    def clean_stale(self):
        """Remove pid files and sockets of processes that are no longer running. Returns what was removed."""
        run, rt, removed = self.base / "run", self.web.rt, []
        checks = [("tor.pid", lambda: pm.alive(run / "tor.pid", "tor")), ("nginx.pid", lambda: pm.alive(run / "nginx.pid", "nginx")),
                  ("php-fpm.pid", rt._fpm_alive), ("app.pid", rt._app_alive)]
        for name, alive in checks:
            f = run / name
            if f.exists() and not alive():
                f.unlink(missing_ok=True); removed.append(name)
        if (run / "app.port").exists() and not rt._app_alive():
            (run / "app.port").unlink(missing_ok=True)
        if not rt._fpm_alive():
            rt.sock.unlink(missing_ok=True)
        return removed

    # ---------- starting, with repairs ----------
    def start(self, parts=("web", "tor")):
        """Start hosting and repair known problems on the way. Returns a list of what was repaired.
        Raises PortBusy when the port is taken and automatic fixing is off."""
        with self.lock:
            notes = []
            if "web" in parts and not self.web.rt.kind():
                raise ServiceError("No website deployed yet. Upload a ZIP first.")
            self.gave_up.clear(); self._hist.clear()
            last = None
            for _ in range(3):
                try:
                    removed = self.clean_stale()
                    if removed:
                        notes.append("Cleaned up leftovers from an earlier run: " + ", ".join(removed)); self.note(notes[-1])
                    if "web" in parts and not self.web.running() and not port_free(self.web.port):
                        if not self.auto_on():
                            raise PortBusy(f"Port {self.web.port} is already in use.")
                        notes.append(self._switch_port())
                    if "web" in parts:
                        self.web.start()
                    if "tor" in parts:
                        self.tor.start()
                    return notes
                except PortBusy:
                    raise
                except ServiceError as e:
                    last = e
                    fix = self._recover(e) if self.auto_on() else None
                    if not fix:
                        raise
                    notes.append(fix)
            raise last

    def _recover(self, e):
        """Repair what a failed start tells us is wrong. Returns a note, or None when there is nothing safe to do."""
        msg = str(e)
        if "site's app" in msg:
            return None  # the app's own port problems are handled by the runtime, not by moving the hosting port
        if re.search(r"Address already in use|\(98:", msg):
            return self._switch_port()
        if "PHP-FPM did not start" in msg:
            self.web.rt.stop()
            self.note("Removed a stale PHP-FPM socket and tried again.")
            return "Removed a stale PHP-FPM socket and tried again."
        if "Tor did not start" in msg and re.search(r"permission|too permissive|not private", msg, re.I):
            self._fix_fix_perms({})
            return "Repaired Tor's folder permissions and tried again."
        return None

    # ---------- diagnosis ----------
    def diagnose(self, probe_site=True):
        out, kind, running = [], self.web.rt.kind(), self.web.running()
        for check in (self._check_deps, self._check_disk, self._check_stale):
            out += check(kind)
        out += self._check_port(running)
        if kind:
            out += self._check_components(kind, running)
            if running:
                out += self._check_probe(kind) if probe_site else []
                out += self._check_exposure(kind)
            out += self._check_logs(kind)
        out += self._check_tor()
        seen, uniq = set(), []
        for f in out:  # the same problem can be seen from several angles
            if f["id"] not in seen:
                seen.add(f["id"]); uniq.append(f)
        uniq.sort(key=lambda f: LEVELS.get(f["level"], 9))
        if not uniq:
            uniq = [self._f("ok", "ok", "No problems found", "Hosting, the site and its dependencies look healthy.")]
        return uniq

    def _check_deps(self, kind):
        out, miss = [], pd.missing_deps()
        for name in miss:
            out.append(self._f(f"deps.{name}", "error", f"{name.capitalize()} is not installed", f"AnonyHost needs {name} to host your site.", "install", pkgs=[name]))
        for prog, apt in missing_runtime(self.base / "site"):
            out.append(self._f("deps.runtime", "error", f"{prog} is not installed", f"Your {self.web.rt.label()} site needs it.", "install", pkgs=[apt]))
        if shutil.which("nginx") and not Path("/etc/nginx/mime.types").exists():
            out.append(self._f("deps.mime", "error", "Nginx's mime.types file is missing", "Without it nginx cannot start.", "install", pkgs=["nginx-common"]))
        if kind == "python" and (self.base / "site/requirements.txt").is_file() and not (self.base / "runtime/venv/bin/python").exists():
            try:
                import ensurepip
                ok = (Path(ensurepip.__file__).parent / "_bundled").is_dir()
            except Exception:
                ok = False
            if not ok:
                out.append(self._f("deps.venv", "error", "python3-venv is not installed", "It is needed to install your site's requirements.txt.", "install", pkgs=["python3-venv"]))
        if kind == "node" and not shutil.which("npm") and (self.base / "site/package.json").is_file():
            out.append(self._f("deps.runtime", "error", "npm is not installed", "Your site's package.json lists dependencies.", "install", pkgs=["npm"]))
        return out

    def _check_disk(self, kind):
        try:
            free = shutil.disk_usage(self.base).free
        except OSError:
            return []
        if free < 50 * 2**20:
            return [self._f("disk", "error", "The disk is almost full", f"Only {free // 2**20} MB are free. Hosting and logs may fail.")]
        if free < 300 * 2**20:
            return [self._f("disk", "warn", "Free disk space is low", f"{free // 2**20} MB are free.")]
        return []

    def _check_stale(self, kind):
        run, rt = self.base / "run", self.web.rt
        stale = [n for n, alive in (("tor.pid", lambda: pm.alive(run / "tor.pid", "tor")), ("nginx.pid", lambda: pm.alive(run / "nginx.pid", "nginx")),
                                    ("php-fpm.pid", rt._fpm_alive), ("app.pid", rt._app_alive)) if (run / n).exists() and not alive()]
        return [self._f("stale", "warn", "Leftovers from an earlier run", "Old process files point to programs that are not running.", "clean_stale", auto=True)] if stale else []

    def _check_port(self, running):
        if running or port_free(self.web.port):
            return []
        o = port_owner(self.web.port)
        return [self._f("port", "warn", f"Port {self.web.port} is already in use", (f"Used by {o['name']} (PID {o['pid']}). " if o else "") + "AnonyHost can switch to a free port; your onion address does not change.", "port_free", auto=True)]

    def _check_components(self, kind, running):
        out = []
        if not self.want():
            return out
        gu = self.gave_up
        if not self.tor.running():
            out.append(self._f("tor.down", "error", "Tor stopped unexpectedly", "Visitors cannot reach your site while Tor is down." + (" Automatic restarts are paused because it keeps failing." if "tor.down" in gu else ""),
                               "restart_tor", auto="tor.down" not in gu))
        if not running:
            out.append(self._f("web.down", "error", "The web server stopped unexpectedly", "Nginx is not running." + (" Automatic restarts are paused because it keeps failing." if "web.down" in gu else ""),
                               "restart_site", auto="web.down" not in gu))
        else:
            rt = self.web.rt
            dead = (kind in ("node", "python") and not rt._app_alive()) or (kind == "php" and not rt._fpm_alive())
            if dead:
                out.append(self._f("app.down", "error", "Your site's app stopped unexpectedly", "It crashed or was stopped." + (" Automatic restarts are paused because it keeps failing. See the Site app log." if "app.down" in gu else ""),
                                   "restart_site", auto="app.down" not in gu))
        return out

    def _check_probe(self, kind):
        status, err = probe(self.web.port)
        if status is None or status in (502, 503, 504):
            return [self._f("site.down", "error", "Your site is not answering", (err or f"HTTP {status}") + ". " + ("Automatic restarts are paused because it keeps failing." if "site.down" in self.gave_up else "Restarting the site usually fixes this."),
                            "restart_site", auto="site.down" not in self.gave_up)]
        if status >= 500:
            return [self._f("site.error", "error", f"Your site answers with an error (HTTP {status})", "The problem is inside the site's own code. The details below, when available, say what to change.")]
        if status == 403:
            return [self._f("site.forbidden", "warn", "Your site answers 'Forbidden' (HTTP 403)", "A file or folder is not readable, or a folder has no index file.", "fix_perms")]
        if status == 404 and kind in ("static", "php"):
            return [self._f("site.home", "warn", "The home page was not found (HTTP 404)", "Add an index.html (or index.php) at the top level of your site.")]
        return []

    def _check_exposure(self, kind):
        if kind not in ("node", "python"):
            return []
        ex = self.web.rt.exposed()
        if not ex:
            return []
        return [self._f("app.exposed", "warn", "Your app is reachable from your local network", "It listens on " + ", ".join(ex) + ", so people on your network can open it without Tor. "
                        "Make it listen on 127.0.0.1 only (use the HOST and PORT environment variables).")]

    def _check_logs(self, kind):
        rt, out = self.web.rt, []
        sources = [("nginx", since_marker(self.base / "logs/nginx-error.log"))]
        if kind in ("node", "python"):
            sources.append(("app", rt.log_since_start()))
        if kind == "php":
            sources.append(("php", since_marker(self.base / "logs/php-fpm.log")))
        for src, text in sources:
            for h in logscan.classify(src, text[-12000:]):
                if h["code"] == "host_header" and (self.base / "proxy_local_host").exists():  # already tried: only the app's own settings can help now
                    h = {**h, "fix": None, "detail": "AnonyHost already sends a local Host header. Add the onion address to your app's allowed hosts (ALLOWED_HOSTS in Django)."}
                out.append(self._from_hit(h, auto=h.get("fix") in ("restart_site", "pip_install", "npm_install", "host_header_local", "fix_perms")))
        return out

    def _check_tor(self):
        out = []
        if self.tor.running():
            boot = self.tor.bootstrap()
            try:
                age = time.time() - self.tor.pid.stat().st_mtime
            except OSError:
                age = 0
            if boot < 100 and age > 240:
                out.append(self._f("tor.slow", "warn", f"Tor has been connecting for {int(age // 60)} minutes (at {boot}%)", "Check your internet connection and the system clock.", "restart_tor", auto=age > 600))
            for h in logscan.classify("tor", self._tor_text()):
                out.append(self._from_hit(h))
        return out

    def _tor_text(self):
        try:
            return self.tor.log.read_text(errors="replace")[-12000:]
        except OSError:
            return ""

    # ---------- applying fixes ----------
    def apply(self, f):
        """Apply the fix of one finding (a dict from diagnose()). Returns a message; raises ServiceError on failure."""
        fix = f.get("fix")
        handler = getattr(self, f"_fix_{fix}", None) if fix in FIX_LABELS else None
        if not handler or fix == "install":
            raise ServiceError("This problem cannot be fixed automatically." if fix != "install" else "Installing packages needs your approval: use the Install button.")
        with self.lock:
            msg = handler(f)
            self.note(f"{FIX_LABELS[fix]} ({f.get('id')}): {msg}")
            self.cache = (0.0, [])
            return msg

    def apply_all(self, findings=None):
        """Apply every non-privileged fix once. Returns (messages, errors)."""
        done, msgs, errs = set(), [], []
        for f in findings if findings is not None else self.diagnose():
            key = (f.get("fix"), f.get("module"))
            if not f.get("fix") or f.get("root") or key in done:
                continue
            done.add(key)
            try:
                msgs.append(f"{f['title']}: {self.apply(f)}")
            except ServiceError as e:
                errs.append(f"{f['title']}: {e}")
        return msgs, errs

    def _restart_web(self):
        keep = self.want() or self.web.running()
        self.web.stop()
        if keep:
            self.web.start()
            if not self.tor.running():
                self.tor.start()

    def _fix_port_free(self, f):
        was = self.web.running() or self.tor.running()
        if was:
            self.web.stop(); self.tor.stop()
        msg = self._switch_port()
        if was:
            self.start()
        return msg

    def _fix_clean_stale(self, f):
        r = self.clean_stale()
        return "Removed " + ", ".join(r) if r else "Nothing to clean up."

    def _fix_restart_site(self, f):
        self._restart_web()
        return "The site was restarted."

    def _fix_restart_tor(self, f):
        self.tor.stop(); self.tor.start()
        return "Tor was restarted."

    def _fix_fix_perms(self, f):
        """Make the site readable and writable by its owner and readable by others; keep Tor's folders private."""
        n = 0
        for dp, dns, fns in os.walk(self.base / "site"):
            for name in dns + fns:
                p = os.path.join(dp, name)
                try:
                    if os.path.islink(p):
                        continue
                    mode = os.stat(p).st_mode & 0o7777
                    want = mode | (0o755 if os.path.isdir(p) else 0o644)
                    if want != mode:
                        os.chmod(p, want); n += 1
                except OSError:
                    pass
        for d in ("tor-data", "onion-service"):
            try:
                os.chmod(self.base / d, 0o700)
            except OSError:
                pass
        return f"Repaired permissions on {n} file{'s' if n != 1 else ''} and folders."

    def _fix_site_deps(self, f):
        was = self.web.running()
        if was:
            self.web.stop()
        self.web.rt.reinstall_deps()
        if was:
            self.web.start()
        return "The site's dependencies were reinstalled."

    def _fix_pip_install(self, f):
        pkg = SAFE_PIP.get((f.get("module") or "").split(".")[0])
        if not pkg:
            raise ServiceError("That package is not on the list AnonyHost installs by itself. Add it to requirements.txt.")
        self.web.rt.pip_install([pkg])
        self._restart_web()
        return f"Installed {pkg} and restarted the site."

    def _fix_npm_install(self, f):
        self.web.rt.npm_install()
        self._restart_web()
        return "Ran npm install and restarted the site."

    def _fix_host_header_local(self, f):
        (self.base / "proxy_local_host").write_text("1")
        self._restart_web()
        return "The app now receives a local Host header (the visitor's address is passed in X-Forwarded-Host)."

    # ---------- the watchdog ----------
    def _allowed(self, key):
        now = time.time()
        h = [t for t in self._hist.get(key, []) if now - t < RETRY_WINDOW]
        self._hist[key] = h
        if len(h) >= MAX_RETRIES:
            if key not in self.gave_up:
                self.gave_up[key] = now
                self.note(f"Gave up automatically fixing '{key}' after {MAX_RETRIES} tries in {RETRY_WINDOW // 60} minutes. Open the Health page.")
            return False
        h.append(now)
        return True

    def tick(self):
        """One watchdog pass: look for problems and repair the safe ones. Never blocks a user's action."""
        if not self.lock.acquire(blocking=False):
            return
        try:
            findings = self.diagnose()
            self.cache = (time.time(), findings)
            if not (self.auto_on() and self.want()):
                return
            for f in findings:
                if f.get("auto") and f.get("fix") and self._allowed(f["id"]):
                    try:
                        self.apply(f)
                    except ServiceError as e:
                        self.note(f"Automatic fix '{f['fix']}' for {f['id']} failed: {e}")
        finally:
            self.lock.release()

    def run_forever(self, stop_event, interval=20):
        while not stop_event.wait(interval):
            try:
                self.tick()
            except Exception as e:  # the watchdog must never die
                self.note(f"Watchdog error: {type(e).__name__}: {e}")

    def findings(self, max_age=30):
        """Recent findings (from the watchdog when it runs, otherwise computed now)."""
        t, f = self.cache
        if time.time() - t > max_age or not f:
            f = self.diagnose(); self.cache = (time.time(), f)
        return f

    # ---------- installing system packages (asks for the user's approval) ----------
    @staticmethod
    def validate_pkgs(pkgs):
        out = []
        for p in pkgs:
            if p not in APT_ALLOW or not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*", p):
                raise ServiceError(f"'{p}' is not on the list of packages AnonyHost may install.")
            if p not in out:
                out.append(p)
        if not out:
            raise ServiceError("Nothing to install.")
        return out

    def start_install(self, pkgs):
        pkgs = self.validate_pkgs(pkgs)
        manual = "sudo apt install " + " ".join(pkgs)
        if self.install["state"] == "running":
            raise ServiceError("An installation is already running. Wait for it to finish.")
        if not shutil.which("pkexec"):
            raise ServiceError(f"The graphical password prompt (pkexec) is not available here. Run this in a terminal instead: {manual}")
        script = "apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y " + " ".join(pkgs)  # names are allow-listed above
        self.install = {"state": "running", "pkgs": pkgs, "manual": manual, "rc": None}
        self.note(f"Installing packages with the user's approval: {' '.join(pkgs)}")
        threading.Thread(target=self._run_install, args=(script, manual), daemon=True).start()

    def _run_install(self, script, manual):
        rc, log = None, self.base / "logs/install.log"
        try:
            with open(log, "w") as lf:
                lf.write(f"$ pkexec sh -c '{script}'\n"); lf.flush()
                rc = subprocess.Popen(["pkexec", "/bin/sh", "-c", script], stdout=lf, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL).wait(timeout=1800)
        except (OSError, subprocess.TimeoutExpired):
            rc = -1
        self.install = {**self.install, "state": "done" if rc == 0 else "failed", "rc": rc}
        self.note("Package installation finished." if rc == 0 else f"Package installation did not finish (code {rc}). You can run: {manual}")
        self.cache = (0.0, [])

    def install_status(self):
        s = dict(self.install)
        try:
            s["tail"] = (self.base / "logs/install.log").read_text(errors="replace")[-1500:]
        except OSError:
            s["tail"] = ""
        return s

    def history(self, n=15):
        try:
            return (self.base / "logs/autofix.log").read_text(errors="replace").splitlines()[-n:]
        except OSError:
            return []
