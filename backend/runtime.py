# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Site runtimes. A site is static (nginx serves the files) or dynamic:
  php     private php-fpm instance, reached by nginx over a unix socket
  node    a Node.js app that listens on 127.0.0.1:$PORT, reverse-proxied by nginx
  python  a Python app that listens on 127.0.0.1:$PORT, reverse-proxied by nginx
Everything runs unprivileged, as the current user, and only on loopback.
Common start-up problems are repaired automatically (see Runtime._repair)."""
import glob, hashlib, ipaddress, json, os, re, shlex, shutil, signal, socket, subprocess, threading, time
from datetime import datetime
from pathlib import Path
from . import logscan, process_manager as pm

KINDS = ("static", "php", "node", "python")
LABELS = {"static": "Static", "php": "PHP", "node": "Node.js", "python": "Python"}
MANIFEST = "anonyhost.json"
NODE_ENTRIES = ("server.js", "app.js", "index.js", "main.js")
PY_ENTRIES = ("app.py", "server.py", "main.py")
ENTRY_FILES = {"index.html", "index.php", "package.json", "manage.py", MANIFEST, *NODE_ENTRIES, *PY_ENTRIES}
INSTALL_TIMEOUT = 900
START_WAIT = 25

# Well-known Python packages AnonyHost may install on its own when an app imports them (module name -> pip name).
SAFE_PIP = {"flask": "Flask", "flask_cors": "flask-cors", "flask_sqlalchemy": "Flask-SQLAlchemy", "flask_login": "Flask-Login",
            "flask_wtf": "Flask-WTF", "flask_migrate": "Flask-Migrate", "django": "Django", "requests": "requests", "fastapi": "fastapi",
            "uvicorn": "uvicorn", "gunicorn": "gunicorn", "waitress": "waitress", "jinja2": "Jinja2", "werkzeug": "Werkzeug",
            "markupsafe": "MarkupSafe", "itsdangerous": "itsdangerous", "click": "click", "sqlalchemy": "SQLAlchemy", "pymysql": "PyMySQL",
            "psycopg2": "psycopg2-binary", "bs4": "beautifulsoup4", "yaml": "PyYAML", "dotenv": "python-dotenv", "PIL": "Pillow",
            "numpy": "numpy", "pandas": "pandas", "markdown": "Markdown", "aiohttp": "aiohttp", "jwt": "PyJWT", "bcrypt": "bcrypt",
            "pydantic": "pydantic", "starlette": "starlette", "websockets": "websockets", "lxml": "lxml", "redis": "redis",
            "pymongo": "pymongo", "cryptography": "cryptography", "tornado": "tornado", "bottle": "bottle", "quart": "Quart"}


def note(base, msg):
    """Record an automatic repair in logs/autofix.log (shown on the Health and Logs pages)."""
    try:
        p = Path(base) / "logs/autofix.log"
        p.parent.mkdir(parents=True, exist_ok=True)
        if p.exists() and p.stat().st_size > 200_000:
            p.write_text("")
        with open(p, "a") as f:
            f.write(f"{datetime.now():%Y-%m-%d %H:%M:%S} {msg}\n")
    except OSError:
        pass


def manifest(site):
    """Optional anonyhost.json: {"runtime": "static|php|node|python", "start": "node server.js"}  ({port} is replaced)"""
    try:
        d = json.loads((Path(site) / MANIFEST).read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _package(site):
    try:
        d = json.loads((Path(site) / "package.json").read_text())
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def detect(site):
    """Return {'kind': static|php|node|python|None, 'start': [argv] or None} for a site folder."""
    site = Path(site)
    has = lambda n: (site / n).is_file()
    m, pj = manifest(site), _package(site)
    scripts = pj.get("scripts") if isinstance(pj.get("scripts"), dict) else {}
    kind = m.get("runtime") if m.get("runtime") in KINDS else None
    if not kind:
        no_html = not has("index.html")
        if scripts.get("start"):
            kind = "node"
        elif has("index.php"):
            kind = "php"
        elif no_html and any(has(n) for n in NODE_ENTRIES):
            kind = "node"
        elif no_html and (has("manage.py") or any(has(n) for n in PY_ENTRIES)):
            kind = "python"
        elif no_html and next(site.glob("*.php"), None):
            kind = "php"
        elif has("index.html"):
            kind = "static"
    cmd = None
    if isinstance(m.get("start"), str) and m["start"].strip():
        try:
            cmd = shlex.split(m["start"])
        except ValueError:
            cmd = None
    if kind == "node" and not cmd:
        main = pj.get("main") if isinstance(pj.get("main"), str) else None
        if scripts.get("start"):
            cmd = ["npm", "start", "--silent"]
        else:
            entry = next((n for n in NODE_ENTRIES if has(n)), None)
            if not entry and main and re.fullmatch(r"[\w./-]+", main) and ".." not in main and has(main):
                entry = main
            cmd = ["node", entry] if entry else None
    if kind == "python" and not cmd:
        entry = next((n for n in PY_ENTRIES if has(n)), None)
        if has("manage.py") and not entry:
            cmd = ["python3", "manage.py", "runserver", "127.0.0.1:{port}", "--noreload"]  # Django
        else:
            cmd = ["python3", entry] if entry else None
    return {"kind": kind, "start": cmd}


def site_kind(site):
    return detect(site)["kind"]


def php_fpm_bin():
    cands = sorted(glob.glob("/usr/sbin/php-fpm[0-9]*") + glob.glob("/usr/local/sbin/php-fpm*"), reverse=True)
    for c in [shutil.which("php-fpm"), *cands]:
        if c and os.access(c, os.X_OK):
            return c
    return None


def missing_runtime(site):
    """Programs the deployed site needs that are not installed, as [(program, apt package)]."""
    spec = detect(site)
    if spec["kind"] == "php":
        return [] if php_fpm_bin() else [("php-fpm", "php-fpm")]
    if spec["kind"] in ("node", "python") and spec["start"]:
        exe = spec["start"][0]
        apt = {"node": "nodejs", "npm": "npm", "npx": "npm", "python3": "python3", "python": "python3"}.get(exe, exe)
        return [] if shutil.which(exe) else [(exe, apt)]
    return []


# ---------- process / socket inspection (Linux /proc) ----------
def _proc_alive(pid):
    try:
        state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return state != "Z"
    except (OSError, IndexError):
        return False


def _kill_group(pid, timeout=8):
    """SIGTERM the process group (the app was started as its own session), then SIGKILL."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pid, sig)
        except (ProcessLookupError, PermissionError):
            return
        end = time.time() + timeout
        while time.time() < end:
            if not _proc_alive(pid):
                return
            time.sleep(0.2)


def _tree(pgid):
    """All process ids in a process group (an app and the helpers it spawned)."""
    out = []
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                f = Path(f"/proc/{d}/stat").read_text().rsplit(")", 1)[1].split()
                if int(f[2]) == pgid:
                    out.append(int(d))
            except (OSError, IndexError, ValueError):
                pass
    return out


def _hex_ip(h, v6):
    if not v6:
        return socket.inet_ntoa(bytes.fromhex(h)[::-1])
    return str(ipaddress.IPv6Address(b"".join(bytes.fromhex(h[i:i + 8])[::-1] for i in range(0, 32, 8))))


def is_loopback(ip):
    try:
        a = ipaddress.ip_address(ip)
        if a.version == 6 and a.ipv4_mapped:  # ::ffff:127.0.0.1
            a = a.ipv4_mapped
        return a.is_loopback
    except ValueError:
        return False


def listening_sockets(pids):
    """[(ip, port)] of TCP sockets in LISTEN state that belong to the given processes."""
    inodes = set()
    for pid in pids:
        try:
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    link = os.readlink(f"/proc/{pid}/fd/{fd}")
                except OSError:
                    continue
                if link.startswith("socket:["):
                    inodes.add(link[8:-1])
        except OSError:
            pass
    found = []
    for fn, v6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        try:
            rows = Path(fn).read_text().splitlines()[1:]
        except OSError:
            continue
        for row in rows:
            p = row.split()
            if len(p) > 9 and p[3] == "0A" and p[9] in inodes:
                try:
                    ip, port = p[1].split(":")
                    found.append((_hex_ip(ip, v6), int(port, 16)))
                except (ValueError, IndexError):
                    pass
    return found


def _accepts(port):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.5):
            return True
    except OSError:
        return False


class Runtime:
    def __init__(self, base, note_fn=None):
        self.base = Path(base)
        self.site = self.base / "site"
        self.run = self.base / "run"
        self.note = note_fn or (lambda m: note(self.base, m))
        self.app_pid, self.app_port_file = self.run / "app.pid", self.run / "app.port"
        self.fpm_pid, self.fpm_conf = self.run / "php-fpm.pid", self.base / "php-fpm.conf"
        sock = self.run / "php-fpm.sock"
        self.sock = sock if len(str(sock)) < 100 else Path(f"/tmp/anonyhost-{os.getuid()}-php.sock")  # AF_UNIX path limit
        self.work = self.base / "runtime"
        self.app_log, self.fpm_log = self.base / "logs/site-app.log", self.base / "logs/php-fpm.log"

    # ---- state ----
    def spec(self):
        return detect(self.site)

    def kind(self):
        return self.spec()["kind"]

    def label(self):
        return LABELS.get(self.kind() or "", "")

    def app_port(self):
        return pm.read_pid(self.app_port_file)

    def _fpm_alive(self):
        pid = pm.read_pid(self.fpm_pid)
        try:
            return bool(pid) and Path(f"/proc/{pid}/comm").read_text().strip().startswith("php-fpm") and _proc_alive(pid)
        except OSError:
            return False

    def _app_alive(self):
        pid = pm.read_pid(self.app_pid)
        try:  # the cwd check guards against a recycled PID
            return bool(pid) and _proc_alive(pid) and str(Path(f"/proc/{pid}/cwd").resolve()).startswith(str(self.base.resolve()))
        except OSError:
            return False

    def running(self):
        return self._fpm_alive() or self._app_alive()

    def exposed(self):
        """['0.0.0.0:5000', ...]: sockets of the app that are reachable from the local network, not only from this computer."""
        pid = pm.read_pid(self.app_pid)
        if not (pid and self._app_alive()):
            return []
        return [f"{ip}:{port}" for ip, port in listening_sockets(_tree(pid)) if not is_loopback(ip)]

    def log_since_start(self, limit=20000):
        """The site app's output since it was last started."""
        try:
            text = self.app_log.read_text(errors="replace")
        except OSError:
            return ""
        i = text.rfind("--- starting:")
        return text[i:][-limit:] if i >= 0 else text[-limit:]

    # ---- start / stop ----
    def start(self, hosting_port):
        """Start whatever the site needs. Returns the details nginx needs to reach it."""
        spec = self.spec()
        self.run.mkdir(parents=True, exist_ok=True)
        if spec["kind"] == "php":
            self._start_php()
            return {"kind": "php", "sock": str(self.sock)}
        if spec["kind"] in ("node", "python"):
            return {"kind": spec["kind"], "app_port": self._start_app(spec, int(hosting_port))}
        return {"kind": spec["kind"]}

    def stop(self):
        pid = pm.read_pid(self.app_pid)
        if pid and self._app_alive():
            _kill_group(pid)
        if self._fpm_alive():
            pm.terminate(self.fpm_pid)
        for f in (self.app_pid, self.app_port_file):
            f.unlink(missing_ok=True)
        self.sock.unlink(missing_ok=True)

    # ---- PHP ----
    def _start_php(self):
        if self._fpm_alive():
            return
        exe = php_fpm_bin()
        if not exe:
            raise pm.ServiceError("PHP-FPM is not installed. Install it with: sudo apt install php-fpm")
        b = self.base
        for d in ("php-sessions", "php-tmp"):
            (self.work / d).mkdir(parents=True, exist_ok=True)
            os.chmod(self.work / d, 0o700)
        self.sock.unlink(missing_ok=True)
        self.fpm_conf.write_text(f"""[global]
pid = {self.fpm_pid}
error_log = {self.fpm_log}
daemonize = yes
[www]
listen = {self.sock}
listen.mode = 0600
pm = ondemand
pm.max_children = 8
pm.process_idle_timeout = 20s
catch_workers_output = yes
clear_env = yes
php_admin_value[expose_php] = Off
php_admin_value[display_errors] = Off
php_admin_value[log_errors] = On
php_admin_value[error_log] = {self.fpm_log}
php_admin_value[session.save_path] = {self.work}/php-sessions
php_admin_value[upload_tmp_dir] = {self.work}/php-tmp
php_admin_value[open_basedir] = {self.site}:{self.work}:/tmp:/usr/share/php
""")
        chk = subprocess.run([exe, "-t", "-y", str(self.fpm_conf), "-p", str(b)], capture_output=True, text=True, timeout=20)
        if chk.returncode:
            raise pm.ServiceError("PHP-FPM rejected the configuration: " + (chk.stderr or chk.stdout)[-300:])
        try:  # a marker lets the health check ignore errors from before this start
            with open(self.fpm_log, "a") as lf:
                lf.write(f"--- php-fpm starting {datetime.now():%Y-%m-%d %H:%M:%S} ---\n")
        except OSError:
            pass
        r = subprocess.run([exe, "-y", str(self.fpm_conf), "-p", str(b)], capture_output=True, text=True, timeout=20)
        end = time.time() + 8
        while time.time() < end and not (self._fpm_alive() and self.sock.exists()):
            time.sleep(0.2)
        if not (self._fpm_alive() and self.sock.exists()):
            raise pm.ServiceError("PHP-FPM did not start: " + (r.stderr or self._tail(self.fpm_log)))

    # ---- environment and dependencies ----
    def _env(self, port, venv=None):
        home = self.work / "home"
        home.mkdir(parents=True, exist_ok=True)
        path = os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")
        env = {"PATH": path, "HOME": str(home), "LANG": os.environ.get("LANG", "C.UTF-8"), "HOST": "127.0.0.1",
               "PORT": str(port), "NODE_ENV": "production", "PYTHONUNBUFFERED": "1"}
        if venv:
            env["PATH"], env["VIRTUAL_ENV"] = f"{venv}/bin:{path}", str(venv)
        return env

    def _run_step(self, argv, env, what):
        try:
            r = subprocess.run(argv, cwd=self.site, env=env, capture_output=True, text=True, timeout=INSTALL_TIMEOUT)
        except subprocess.TimeoutExpired:
            raise pm.ServiceError(f"{what} took too long and was stopped.")
        except OSError as e:
            raise pm.ServiceError(f"{what} could not run: {e}")
        if r.returncode:
            raise pm.ServiceError(f"{what} failed: " + (r.stderr or r.stdout)[-300:])

    def _venv(self):
        v = self.work / "venv"
        return v if (v / "bin/python").exists() else None

    def _ensure_venv(self, system_site=False):
        venv = self._venv()
        if venv:
            return venv
        py = shutil.which("python3")
        if not py:
            raise pm.ServiceError("python3 is not installed.")
        venv = self.work / "venv"
        argv = [py, "-m", "venv"] + (["--system-site-packages"] if system_site else []) + [str(venv)]
        self._run_step(argv, self._env(0), "Creating the Python environment (is python3-venv installed? sudo apt install python3-venv)")
        return venv

    def _prepare_python(self):
        """Install requirements.txt into a private virtualenv. Returns the venv path (an existing one is reused)."""
        req = self.site / "requirements.txt"
        if not req.is_file():
            return self._venv()
        venv = self._ensure_venv()
        mark, digest = venv / ".requirements-hash", hashlib.sha256(req.read_bytes()).hexdigest()
        if not mark.exists() or mark.read_text() != digest:
            self._run_step([str(venv / "bin/pip"), "install", "-q", "--disable-pip-version-check", "-r", str(req)], self._env(0, venv), "Installing requirements.txt")
            mark.write_text(digest)
        return venv

    def pip_install(self, packages):
        """Install well-known packages (SAFE_PIP names only) into the site's virtualenv."""
        allowed = set(SAFE_PIP.values())
        pkgs = [p for p in packages if p in allowed]
        if not pkgs:
            raise pm.ServiceError("That package is not on the list AnonyHost installs automatically. Add it to requirements.txt.")
        venv = self._ensure_venv(system_site=True)
        self._run_step([str(venv / "bin/pip"), "install", "-q", "--disable-pip-version-check", *pkgs], self._env(0, venv), "pip install " + " ".join(pkgs))
        return venv

    def _prepare_node(self, env, force=False):
        deps = _package(self.site).get("dependencies")
        if isinstance(deps, dict) and deps and (force or not (self.site / "node_modules").is_dir()):
            if not shutil.which("npm"):
                raise pm.ServiceError("npm is not installed. Install it with: sudo apt install nodejs npm")
            self._run_step(["npm", "install", "--omit=dev", "--no-audit", "--no-fund"], env, "npm install")

    def npm_install(self):
        self._prepare_node(self._env(0), force=True)

    def reinstall_deps(self):
        """Reinstall the site's declared dependencies (requirements.txt / package.json)."""
        kind = self.kind()
        if kind == "python":
            (self.work / "venv/.requirements-hash").unlink(missing_ok=True)
            self._prepare_python()
        elif kind == "node":
            self.npm_install()

    # ---- Node / Python apps ----
    def _free_port(self, hosting_port):
        for p in range(hosting_port + 1, hosting_port + 60):
            if p != hosting_port and pm.port_free(p):
                return p
        raise pm.ServiceError("No free local port was found for the site's app.")

    def _launch_once(self, cmd, env, port):
        """Start the app once. Returns (state, port, exit_code): ok | exited | silent."""
        argv = [a.replace("{port}", str(port)).replace("{host}", "127.0.0.1") for a in cmd]
        self.app_log.parent.mkdir(parents=True, exist_ok=True)
        if self.app_log.exists() and self.app_log.stat().st_size > 1_000_000:
            self.app_log.unlink()
        with open(self.app_log, "ab") as lf:
            lf.write(f"--- starting: {' '.join(argv)} (port {port}) ---\n".encode())
            proc = subprocess.Popen(argv, cwd=self.site, env=env, stdin=subprocess.DEVNULL, stdout=lf, stderr=lf, start_new_session=True)
        threading.Thread(target=proc.wait, daemon=True).start()  # reap it if it exits while we are running
        self.app_pid.write_text(str(proc.pid)); self.app_port_file.write_text(str(port))
        t0 = time.time()
        while time.time() - t0 < START_WAIT:
            if proc.poll() is not None:
                return "exited", None, proc.returncode
            if _accepts(port):
                return "ok", port, None
            if time.time() - t0 > 3:  # the app may ignore PORT and use its own: find what it really listens on
                found = listening_sockets(_tree(proc.pid))
                if found:
                    ip, p = sorted(found, key=lambda x: (not is_loopback(x[0]), x[1]))[0]
                    self.app_port_file.write_text(str(p))
                    self.note(f"Your app ignored the PORT variable and listens on port {p}; AnonyHost is using that port.")
                    return "ok", p, None
            time.sleep(0.3)
        return "silent", None, None

    def _framework_runner(self, cmd):
        """A script that only defines a Flask / FastAPI app and exits: run it with the framework's own server."""
        entry = cmd[-1] if cmd and cmd[-1].endswith(".py") else None
        stem = entry[:-3] if entry else ""
        if not (entry and re.fullmatch(r"[A-Za-z_]\w*", stem) and (self.site / entry).is_file()):
            return None
        try:
            src = (self.site / entry).read_text(errors="replace")[:200_000]
        except OSError:
            return None
        m = re.search(r"^(\w+)\s*=\s*Flask\(", src, re.M)
        if m:
            return ["python3", "-m", "flask", "--app", f"{stem}:{m.group(1)}", "run", "--host", "127.0.0.1", "--port", "{port}"]
        m = re.search(r"^(\w+)\s*=\s*FastAPI\(", src, re.M)
        if m:
            return ["python3", "-m", "uvicorn", f"{stem}:{m.group(1)}", "--host", "127.0.0.1", "--port", "{port}"]
        return None

    def _repair(self, kind, cmd, log, rc, state, tried):
        """Fix what the app's own output says is wrong. Returns the command to try next, or None."""
        hits = logscan.classify("app", log)
        if kind == "python":
            for h in hits:
                if h["code"] != "py_module":
                    continue
                pkg = SAFE_PIP.get(h["module"].split(".")[0])
                if pkg and ("pip", pkg) not in tried:
                    tried.add(("pip", pkg))
                    self.note(f"Your app needs the Python package {pkg}; installing it.")
                    self.pip_install([pkg])
                    return cmd
        if kind == "node":
            for h in hits:
                if h["code"] == "node_module" and ("npm",) not in tried and (self.site / "package.json").is_file():
                    tried.add(("npm",))
                    self.note("A Node.js module was missing; running npm install.")
                    self._prepare_node(self._env(0), force=True)
                    return cmd
        if kind == "python" and state == "exited" and rc == 0 and ("runner",) not in tried:
            alt = self._framework_runner(cmd)
            if alt:
                tried.add(("runner",))
                self.note("Your script only defines an app and exited; starting it with its framework's server instead.")
                return alt
        return None

    def _explain(self, state, rc, log):
        hits = logscan.classify("app", log)
        why = "; ".join(f"{h['title']}. {h['detail']}" for h in hits[:2])
        head = ("The site's app stopped right after starting." if state == "exited"
                else "The site's app did not listen on its port within 25 seconds. It must read the PORT environment variable.")
        tail = self._tail(self.app_log)
        return f"{head} {why + ' ' if why else ''}{tail}"

    def _start_app(self, spec, hosting_port):
        if self._app_alive() and self.app_port():
            return self.app_port()
        cmd, kind = list(spec["start"] or []), spec["kind"]
        if not cmd:
            raise pm.ServiceError('No start command found. Add package.json (with "scripts.start"), app.py/server.py/main.py, manage.py (Django), '
                                  'or an anonyhost.json with "runtime" and "start".')
        venv = self._prepare_python() if kind == "python" else None
        if kind == "node":
            self._prepare_node(self._env(0))
        port, tried, state, rc, log = self._free_port(hosting_port), set(), "exited", None, ""
        for _ in range(5):
            if kind == "python" and venv is None:
                venv = self._venv()
            env = self._env(port, venv)
            if not shutil.which(cmd[0], path=env["PATH"]):
                hint = {"node": "sudo apt install nodejs npm", "npm": "sudo apt install nodejs npm"}.get(cmd[0], "")
                raise pm.ServiceError(f"'{cmd[0]}' is not installed." + (f" Install it with: {hint}" if hint else ""))
            state, got, rc = self._launch_once(cmd, env, port)
            if state == "ok":
                return got
            self.stop()
            log = self.log_since_start()
            nxt = self._repair(kind, cmd, log, rc, state, tried)
            if not nxt:
                break
            cmd = nxt
        raise pm.ServiceError(self._explain(state, rc, log))

    @staticmethod
    def _tail(path, n=300):
        try:
            return "Last log lines: " + Path(path).read_text(errors="replace")[-n:].strip()
        except OSError:
            return "(no log yet)"
