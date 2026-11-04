import json, logging, logging.handlers, os, re, secrets, signal, shutil, tempfile, threading, time, zipfile
from datetime import datetime
from pathlib import Path
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from backend import platform_detector as pd, reset as resetlib, security
from backend.nginx_manager import NginxManager
from backend.process_manager import ServiceError, port_free, port_owner, stop_listener
from backend.browser import find_tor_browser, open_in_tor_browser
from backend.tor_manager import TorManager
from config.settings import VERSION, data_dir as default_data_dir

MAX_BYTES = 1024 ** 3  # maximum website size: 1 GB (upload and extracted)

def create_app(data_dir=None, port=8080, password=None):
    base = Path(data_dir or default_data_dir()).resolve()
    for d in ("site", "run", "logs", "backups"):
        (base / d).mkdir(parents=True, exist_ok=True)
    os.chmod(base, 0o700)
    adm, skf = base / "admin.json", base / "secret.key"

    def load_admin():
        try:
            return json.loads(adm.read_text())
        except (OSError, ValueError):
            return None

    pending = {}  # a new recovery key waiting to be shown once (kept out of the cookie)

    def save_admin(user, pw=None, recovery=None):
        old = load_admin() or {}
        data = {"user": user, "hash": generate_password_hash(pw) if pw else old["hash"], "secret": old.get("secret", ""),
                "recovery": generate_password_hash(security.norm_key(recovery)) if recovery else old.get("recovery", "")}
        adm.write_text(json.dumps(data)); os.chmod(adm, 0o600)

    if password and not adm.exists():  # unattended provisioning and tests
        save_admin("admin", password)
    a0 = load_admin()
    if a0 and a0.get("secret"):  # accounts created by earlier versions keep their key
        secret = a0["secret"]
    else:
        if not skf.exists():
            skf.write_text(secrets.token_hex(32)); os.chmod(skf, 0o600)
        secret = skf.read_text().strip()
    app = Flask(__name__, template_folder="frontend/templates", static_folder="frontend/static")
    app.config.update(SECRET_KEY=secret, MAX_CONTENT_LENGTH=MAX_BYTES + 2**20, SEND_FILE_MAX_AGE_DEFAULT=0,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict")
    app.logger.handlers.clear()
    lh = logging.handlers.RotatingFileHandler(base / "logs/app.log", maxBytes=1_000_000, backupCount=3)
    lh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    app.logger.addHandler(lh); app.logger.setLevel(logging.INFO)
    sf = base / "settings.json"

    def S():
        try:
            return json.loads(sf.read_text())
        except (OSError, ValueError):
            return {}

    def save_S(**kw):
        d = S(); d.update(kw)
        sf.write_text(json.dumps(d)); os.chmod(sf, 0o600)

    default_port = port
    try:
        port = int(S()["port"])
    except (KeyError, ValueError, TypeError):
        pass
    tor, web = TorManager(base, port), NginxManager(base, port)

    def set_port(p):
        web.port = tor.port = p
        save_S(port=p)

    def begin():
        """Start nginx + tor. Returns False (and flags a conflict) if the port is taken."""
        try:  # the control panel may have changed the port since this app started
            web.port = tor.port = int(S().get("port", default_port))
        except (TypeError, ValueError):
            pass
        pd.check_platform()
        if not web.running() and not port_free(web.port):
            session["conflict"] = True
            return False
        web.start(); tor.start()
        return True
    stamp = base / "deployed_at"

    @app.before_request
    def guard():
        if request.host.split(":")[0] not in ("127.0.0.1", "localhost"):
            abort(400)  # blocks DNS-rebinding
        session.setdefault("csrf", secrets.token_hex(16))
        if request.method == "POST" and not secrets.compare_digest(
                request.form.get("csrf", request.headers.get("X-CSRF", "")), session["csrf"]):
            abort(400, "Invalid CSRF token")
        if request.endpoint == "static":
            return
        if load_admin() is None:
            return None if request.endpoint == "setup" else redirect("/setup")
        if request.endpoint not in ("login", "setup", "recover") and not session.get("auth"):
            return redirect("/login")

    @app.context_processor
    def ctx():
        return {"csrf": session.get("csrf", "")}

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            a = load_admin()
            u_ok = secrets.compare_digest(request.form.get("username", "").encode(), a.get("user", "admin").encode())
            p_ok = check_password_hash(a["hash"], request.form.get("password", ""))
            if u_ok and p_ok:
                session.clear(); session["auth"] = True
                return redirect("/")
            time.sleep(1)
            flash("Wrong username or password.", "danger")
        return render_template("login.html")

    @app.route("/setup", methods=["GET", "POST"])
    def setup():
        if load_admin():
            return redirect("/login")
        if request.method == "POST":
            u, p, p2 = request.form.get("username", "").strip(), request.form.get("password", ""), request.form.get("confirm", "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", u):
                flash("Username: 3-32 letters, digits, dot, dash or underscore.", "danger")
            elif len(p) < 10:
                flash("Password must be at least 10 characters.", "danger")
            elif p != p2:
                flash("Passwords do not match.", "danger")
            else:
                key = security.new_recovery_key()
                save_admin(u, p, key); session.clear(); session["auth"] = True
                pending["key"] = key; session["show_key"] = True
                return redirect("/recovery-key")
        return render_template("setup.html")

    @app.route("/recover", methods=["GET", "POST"])
    def recover():
        a, f = load_admin(), request.form
        if request.method == "POST":
            if not a.get("recovery"):
                flash("This account has no recovery key. Open the AnonyHost Control Panel and choose Reset account.", "danger")
            elif not check_password_hash(a["recovery"], security.norm_key(f.get("key", ""))):
                time.sleep(2); flash("That recovery key is not correct.", "danger")
            elif len(f.get("new", "")) < 10:
                flash("New password must be at least 10 characters.", "danger")
            elif f.get("new") != f.get("confirm"):
                flash("Passwords do not match.", "danger")
            else:
                key = security.new_recovery_key()
                save_admin(a.get("user", "admin"), f["new"], key); session.clear(); session["auth"] = True
                pending["key"] = key; session["show_key"] = True
                return redirect("/recovery-key")
        return render_template("recover.html")

    @app.get("/recovery-key")
    def recovery_key():
        key = pending.pop("key", None) if session.pop("show_key", False) else None
        return render_template("recovery_key.html", key=key) if key else redirect("/")

    @app.post("/settings/recovery")
    def new_recovery():
        a = load_admin()
        if not check_password_hash(a["hash"], request.form.get("current", "")):
            flash("Current password is incorrect.", "danger"); return redirect("/settings")
        key = security.new_recovery_key(); save_admin(a.get("user", "admin"), None, key)
        pending["key"] = key; session["show_key"] = True
        return redirect("/recovery-key")

    @app.get("/settings")
    def settings():
        return render_template("settings.html", page="settings", has_recovery=bool((load_admin() or {}).get("recovery")), tb=find_tor_browser(S().get("tor_browser") or None),
                               tb_path=S().get("tor_browser", ""), autostart=S().get("autostart", False),
                               base=str(base), port=web.port, max_gb=MAX_BYTES // 1024**3, version=VERSION)

    @app.post("/settings/password")
    def change_password():
        a, f = load_admin(), request.form
        if not check_password_hash(a["hash"], f.get("current", "")):
            flash("Current password is incorrect.", "danger")
        elif len(f.get("new", "")) < 10:
            flash("New password must be at least 10 characters.", "danger")
        elif f.get("new") != f.get("confirm"):
            flash("New passwords do not match.", "danger")
        else:
            save_admin(a.get("user", "admin"), f["new"]); session.clear()
            flash("Password changed. Please sign in again.", "success")
            return redirect("/login")
        return redirect("/settings")

    @app.post("/settings/torbrowser")
    def set_torbrowser():
        p = request.form.get("path", "").strip()
        if p and not (Path(p).is_file() and os.access(p, os.X_OK)):
            flash("That file does not exist or is not executable.", "danger")
        else:
            save_S(tor_browser=p); flash("Saved.", "success")
        return redirect("/settings")

    @app.post("/settings/startup")
    def set_startup():
        save_S(autostart=request.form.get("autostart") == "on"); flash("Saved.", "success")
        return redirect("/settings")

    @app.post("/reset/settings")
    def reset_settings():
        tor.stop(); web.stop()
        resetlib.reset_settings(base); web.port = tor.port = default_port
        flash("Settings restored to defaults. Hosting was stopped.", "success")
        return redirect("/settings")

    @app.post("/reset/factory")
    def reset_factory():
        f, a = request.form, load_admin()
        keys = f.get("delete_keys") == "on"
        if not a or not check_password_hash(a["hash"], f.get("password", "")):
            time.sleep(1); flash("Password is incorrect. Nothing was reset.", "danger")
        elif f.get("confirm", "").strip() != "RESET":
            flash("Type RESET (capital letters) to confirm. Nothing was reset.", "danger")
        else:
            tor.stop(); web.stop()
            resetlib.factory_reset(base, delete_keys=keys)
            web.port = tor.port = default_port
            session.clear()
            flash("AnonyHost was reset to its first-run state. " +
                  ("Your onion address was deleted." if keys else "Your onion address was kept."), "success")
            return redirect("/setup")
        return redirect("/settings")

    @app.post("/open-tor")
    def open_tor():
        onion = tor.onion()
        if not onion:
            flash("No onion address yet. Start hosting first.", "warning")
        else:
            exe = find_tor_browser(S().get("tor_browser") or None)
            if not exe:
                flash("Tor Browser was not found. Install it (sudo apt install torbrowser-launcher, or torproject.org/download) "
                      "or set its location in Settings.", "warning")
            else:
                open_in_tor_browser(exe, f"http://{onion}/"); flash("Opening in Tor Browser...", "success")
        return redirect("/")

    @app.post("/quit")
    def quit_app():
        stop = request.form.get("stop_hosting") == "1"
        if stop:
            tor.stop(); web.stop()
        threading.Timer(app.config.get("QUIT_DELAY", 0.7), app.config.get("ON_QUIT") or (lambda: os._exit(0))).start()
        return render_template("bye.html", stopped=stop)

    @app.get("/")
    def index():
        try:
            pd.check_platform(); problem = None
        except ServiceError as e:
            problem = str(e)
        conflict = None
        if session.pop("conflict", False) and not web.running() and not port_free(web.port):
            alt = next((p for p in range(web.port + 1, web.port + 50) if port_free(p)), None)
            conflict = {"port": web.port, "owner": port_owner(web.port), "alt": alt}
        return render_template("index.html", missing=pd.missing_deps(), problem=problem, conflict=conflict, page="home", port=web.port)

    def sysinfo():
        try:
            mem = {l.split(":")[0]: int(l.split()[1]) for l in open("/proc/meminfo")}
            du, n = shutil.disk_usage(base), os.cpu_count() or 1
            return {"os": pd.os_release().get("PRETTY_NAME", "Linux"),
                    "uptime": int(float(open("/proc/uptime").read().split()[0])),
                    "load": round(os.getloadavg()[0] / n * 100, 1), "cores": n,
                    "ram_used": (mem["MemTotal"] - mem["MemAvailable"]) // 1024, "ram_total": mem["MemTotal"] // 1024,
                    "disk_used": du.used // 2**30, "disk_total": du.total // 2**30}
        except (OSError, KeyError, ValueError):
            return {}

    def status():
        return {"tor": tor.running(), "bootstrap": tor.bootstrap(), "onion": tor.onion(),
                "web": web.running(), "site": (base / "site/index.html").exists(),
                "deployed": stamp.read_text() if stamp.exists() else None, "root": str(base / "site"), **sysinfo()}

    @app.get("/api/status")
    def api_status():
        return jsonify(status())

    @app.post("/deploy")
    def deploy():
        f = request.files.get("zip")
        if not f or not f.filename.lower().endswith(".zip"):
            flash("Choose a .zip file.", "danger"); return redirect("/")
        tmp, new, old, site = Path(tempfile.mkdtemp(dir=base)), base / "site.new", base / "site.old", base / "site"
        try:
            z = tmp / "u.zip"; f.save(z)
            if shutil.disk_usage(base).free < 2 * z.stat().st_size + 2**26:
                raise ServiceError("Not enough free disk space for this upload.")
            shutil.rmtree(new, ignore_errors=True)
            security.safe_extract(z, new, max_bytes=MAX_BYTES)
            was = web.running()
            if was: web.stop()
            shutil.rmtree(old, ignore_errors=True)
            site.rename(old); new.rename(site)
            try:
                if was: web.start()
            except ServiceError:
                shutil.rmtree(site); old.rename(site)  # roll back
                if was: web.start()
                raise
            stamp.write_text(datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
            flash("Website deployed.", "success")
        except (security.UnsafeArchive, zipfile.BadZipFile, ServiceError) as e:
            flash(f"Deployment failed: {e}", "danger")
        except Exception as e:  # never show a bare 500; keep the site usable and log the traceback
            app.logger.exception("Deployment failed")
            if not site.exists() and old.exists():
                old.rename(site)
            flash(f"Deployment failed unexpectedly ({type(e).__name__}: {str(e)[:150]}). Details: data/logs/app.log", "danger")
        finally:
            shutil.rmtree(tmp, ignore_errors=True); shutil.rmtree(new, ignore_errors=True)
        return redirect("/")

    @app.post("/start")
    def start():
        try:
            if begin():
                flash("Hosting started. Tor can take a minute or two to publish your address.", "success")
            else:
                flash(f"Port {web.port} is already in use. Choose how to fix it below.", "warning")
        except ServiceError as e:
            flash(str(e), "danger")
        return redirect("/")

    @app.post("/resolve")
    def resolve():
        act = request.form.get("action")
        try:
            if act == "kill":
                o = port_owner(web.port)
                if not o or o["pid"] == os.getpid():
                    raise ServiceError("I can't safely identify that program. Choose another port instead.")
                stop_listener(o["pid"], web.port)
            elif act == "alt":
                new = next((p for p in range(web.port + 1, web.port + 50) if port_free(p)), None)
                if not new:
                    raise ServiceError("No free port found nearby. Free one manually and try again.")
                tor.stop(); web.stop(); set_port(new)
                flash(f"Switched the website to port {new}.", "success")
            else:
                return redirect("/")
            if begin():
                flash("Hosting started. Tor can take a minute or two to publish your address.", "success")
        except ServiceError as e:
            flash(str(e), "danger")
        return redirect("/")

    @app.post("/stop")
    def stop():
        tor.stop(); web.stop(); flash("Hosting stopped.", "success")
        return redirect("/")

    @app.errorhandler(Exception)
    def oops(e):
        if isinstance(e, HTTPException):
            return e
        app.logger.exception("Unhandled error on %s", request.path)
        msg = f"Unexpected error: {type(e).__name__}: {str(e)[:200]}. Details: data/logs/app.log"
        if request.endpoint in (None, "index", "login"):
            return msg, 500
        flash(msg, "danger")
        return redirect("/")

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect("/login")

    def autostart():
        """Called by the launcher when 'start hosting automatically' is enabled."""
        if not (S().get("autostart") and (base / "site/index.html").exists()):
            return
        try:
            if not web.running() and not port_free(web.port):
                app.logger.error("Autostart skipped: port %s is in use", web.port); return
            pd.check_platform(); web.start(); tor.start()
        except ServiceError as e:
            app.logger.error("Autostart failed: %s", e)
    app.autostart = autostart
    return app

if __name__ == "__main__":
    create_app().run("127.0.0.1", 5000)
