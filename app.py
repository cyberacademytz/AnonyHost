# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
import json, logging, logging.handlers, os, re, secrets, signal, shutil, tempfile, threading, time, zipfile
from datetime import datetime
from pathlib import Path
from flask import Flask, abort, flash, jsonify, redirect, render_template, request, send_file, session
from werkzeug.exceptions import HTTPException
from werkzeug.security import check_password_hash, generate_password_hash
from backend import platform_detector as pd, reset as resetlib, security
from backend.nginx_manager import NginxManager
from backend.process_manager import ServiceError, port_free, port_owner, stop_listener
from backend.browser import find_tor_browser, open_in_tor_browser
from backend.logs import ERR, LOGS, WARN, tail_log
from backend.doctor import Doctor, PortBusy
from backend.runtime import missing_runtime
from backend.tor_manager import TorManager
from config.settings import VERSION, data_dir as default_data_dir

MAX_BYTES = 1024 ** 3  # maximum website size: 1 GB (upload and extracted)
MAX_EDIT = 512 * 1024  # largest text file the Files page will open in the editor

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

    doctor = Doctor(base, web, tor, S, save_S)  # automatic repairs, health checks and the watchdog
    app.doctor = doctor

    def start_supervisor(stop_event):
        threading.Thread(target=doctor.run_forever, args=(stop_event,), daemon=True, name="anonyhost-watchdog").start()
    app.start_supervisor = start_supervisor

    def begin():
        """Start hosting, repairing known problems on the way. Returns False if the port is taken and automatic fixing is off."""
        try:  # the control panel may have changed the port since this app started
            web.port = tor.port = int(S().get("port", default_port))
        except (TypeError, ValueError):
            pass
        pd.check_platform()
        try:
            notes = doctor.start()
        except PortBusy:
            session["conflict"] = True
            return False
        for n in notes:
            flash("Fixed automatically: " + n, "success")
        return True
    stamp = base / "deployed_at"

    def go(default="/"):
        """Redirect back to the page a form was submitted from (the form's hidden `next` field)."""
        return redirect({"dashboard": "/", "website": "/website", "files": "/files"}.get(request.form.get("next"), default))

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

    def verify(stored, text):
        """check_password_hash that cannot crash: a hash made by a newer Werkzeug (e.g. scrypt) is 'cannot verify' on an older one."""
        try:
            return check_password_hash(stored, text)
        except (ValueError, TypeError, AttributeError):
            return False

    def hash_readable(stored):
        try:
            check_password_hash(stored, "")
            return True
        except (ValueError, TypeError, AttributeError):
            return False

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            a = load_admin()
            u_ok = secrets.compare_digest(request.form.get("username", "").encode(), a.get("user", "admin").encode())
            p_ok = verify(a["hash"], request.form.get("password", ""))
            if u_ok and p_ok:
                session.clear(); session["auth"] = True
                return redirect("/")
            time.sleep(1)
            if not hash_readable(a.get("hash", "")):
                flash("This account was created with a newer version of the system libraries, so its password cannot be checked here. "
                      "In a terminal run: anonyhost --reset-password (your website and onion address are kept), then create the account again.", "danger")
            else:
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
                flash("This account has no recovery key. In a terminal run: anonyhost --reset-password (your website and onion address are kept), then create the account again.", "danger")
            elif not verify(a["recovery"], security.norm_key(f.get("key", ""))):
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
        if not verify(a["hash"], request.form.get("current", "")):
            flash("Current password is incorrect.", "danger"); return redirect("/settings")
        key = security.new_recovery_key(); save_admin(a.get("user", "admin"), None, key)
        pending["key"] = key; session["show_key"] = True
        return redirect("/recovery-key")

    @app.get("/settings")
    def settings():
        return render_template("settings.html", page="settings", has_recovery=bool((load_admin() or {}).get("recovery")), tb=find_tor_browser(S().get("tor_browser") or None),
                               tb_path=S().get("tor_browser", ""), autostart=S().get("autostart", False), auto_fix=S().get("auto_fix", True),
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
        save_S(autostart=request.form.get("autostart") == "on", auto_fix=request.form.get("auto_fix") == "on"); flash("Saved.", "success")
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

    # ---------------- restart ----------------
    @app.post("/restart-site")
    def restart_site():
        try:
            with doctor.lock:
                if not web.running():
                    flash("Hosting is not running. Press Start hosting first.", "warning")
                else:
                    web.stop(); web.start()  # Tor keeps running, so the onion address stays online
                    flash("Site restarted.", "success")
        except ServiceError as e:
            flash(str(e), "danger")
        return go()

    # ---------------- files ----------------
    def fs(rel):
        """Resolve a path inside the website folder. Never outside it, never a symlink itself."""
        rel = (rel or "").replace("\\", "/").strip("/")
        root = (base / "site").resolve()
        try:
            p = security.safe_join(root, rel)
            if rel and (root / rel).is_symlink():
                raise ValueError("symlink")
        except (ValueError, OSError):
            abort(400)
        return root, p, rel

    def clean_name(name):
        name = (name or "").strip()
        if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name or len(name) > 200:
            raise ValueError("That name is not allowed (no slashes, 200 characters at most).")
        return name

    def tree_size(root):
        total = 0
        for dp, _, fn in os.walk(root):
            for f in fn:
                try:
                    total += os.lstat(os.path.join(dp, f)).st_size
                except OSError:
                    pass
        return total

    def back(rel):
        return redirect("/files" + (f"?path={rel}" if rel else ""))

    @app.get("/files")
    def files():
        root, p, rel = fs(request.args.get("path"))
        if not p.is_dir():
            abort(404)
        rows = []
        for e in sorted(os.scandir(p), key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.lower())):
            st = e.stat(follow_symlinks=False)
            rows.append({"name": e.name, "rel": f"{rel}/{e.name}".lstrip("/"), "dir": e.is_dir(follow_symlinks=False),
                         "link": e.is_symlink(), "size": st.st_size, "mtime": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M")})
        parts = [x for x in rel.split("/") if x]
        crumbs = [(n, "/".join(parts[:i + 1])) for i, n in enumerate(parts)]
        return render_template("files.html", page="files", rel=rel, rows=rows, crumbs=crumbs, parent="/".join(parts[:-1]),
                               dynamic=web.rt.kind() in ("node", "python"), running=web.running())

    @app.post("/files/upload")
    def files_upload():
        root, p, rel = fs(request.form.get("path"))
        if not p.is_dir():
            abort(400)
        used, done = tree_size(root), 0
        for f in request.files.getlist("files"):
            try:
                name = clean_name(Path(f.filename or "").name)
                target = p / name
                if target.is_symlink() or target.is_dir():
                    raise ValueError(f"{name} already exists as a folder or link.")
                tmpf = p / f".upload-{secrets.token_hex(4)}"
                f.save(tmpf)
                size = tmpf.stat().st_size
                if used + size > MAX_BYTES:
                    tmpf.unlink(missing_ok=True)
                    raise ValueError(f"{name}: the website would be larger than {MAX_BYTES // 1024**3} GB.")
                os.chmod(tmpf, 0o644); os.replace(tmpf, target); used += size; done += 1
            except ValueError as e:
                flash(str(e), "danger")
        if done:
            flash(f"Uploaded {done} file{'s' if done != 1 else ''}.", "success")
        elif not request.files.getlist("files") or not any(f.filename for f in request.files.getlist("files")):
            flash("Choose one or more files first.", "warning")
        return back(rel)

    @app.post("/files/mkdir")
    def files_mkdir():
        root, p, rel = fs(request.form.get("path"))
        try:
            (p / clean_name(request.form.get("name"))).mkdir()
            flash("Folder created.", "success")
        except FileExistsError:
            flash("A file or folder with that name already exists.", "danger")
        except (ValueError, OSError) as e:
            flash(str(e), "danger")
        return back(rel)

    @app.post("/files/new")
    def files_new():
        root, p, rel = fs(request.form.get("path"))
        try:
            name = clean_name(request.form.get("name"))
            with open(p / name, "x"):
                pass
            os.chmod(p / name, 0o644)
            return redirect("/files/edit?path=" + f"{rel}/{name}".lstrip("/"))
        except FileExistsError:
            flash("A file or folder with that name already exists.", "danger")
        except (ValueError, OSError) as e:
            flash(str(e), "danger")
        return back(rel)

    @app.post("/files/delete")
    def files_delete():
        root, p, rel = fs(request.form.get("path"))
        if not rel or not os.path.lexists(p):
            flash("Nothing to delete.", "danger")
            return back("")
        try:
            shutil.rmtree(p) if p.is_dir() else p.unlink()
            flash(f"Deleted {p.name}.", "success")
        except OSError as e:
            flash(f"Could not delete: {e}", "danger")
        return back("/".join(rel.split("/")[:-1]))

    @app.get("/files/download")
    def files_download():
        root, p, rel = fs(request.args.get("path"))
        if not p.is_file():
            abort(404)
        return send_file(p, as_attachment=True, download_name=p.name)

    @app.get("/files/edit")
    def files_edit():
        root, p, rel = fs(request.args.get("path"))
        if not p.is_file():
            abort(404)
        parent = "/".join(rel.split("/")[:-1])
        try:
            if p.stat().st_size > MAX_EDIT:
                raise ValueError("too large")
            text = p.read_bytes().decode("utf-8")
            if "\x00" in text:
                raise ValueError("binary")
        except (ValueError, UnicodeDecodeError, OSError):
            flash(f"{p.name} is binary or larger than {MAX_EDIT // 1024} KB, so it cannot be edited here. Download it instead.", "warning")
            return back(parent)
        parts = [x for x in rel.split("/") if x]
        crumbs = [(n, "/".join(parts[:k + 1])) for k, n in enumerate(parts)][:-1] + [(parts[-1], rel)]
        return render_template("edit.html", page="files", rel=rel, name=p.name, parent=parent, text=text, crumbs=crumbs)

    @app.post("/files/save")
    def files_save():
        wants_json = request.headers.get("X-Requested-With") == "fetch"  # the code workspace saves in place without leaving the page
        root, p, rel = fs(request.form.get("path"))
        text = request.form.get("content", "").replace("\r\n", "\n")
        restart = web.rt.kind() in ("node", "python") and web.running()

        def fail(msg, code):
            if wants_json:
                return jsonify({"ok": False, "error": msg}), code
            flash(msg, "danger")
            return redirect("/files/edit?path=" + rel)

        if not p.is_file():
            abort(404)
        if len(text.encode()) > MAX_EDIT:
            return fail(f"The file is larger than {MAX_EDIT // 1024} KB.", 413)
        tmpf = p.with_name(f".save-{secrets.token_hex(4)}")
        try:
            tmpf.write_text(text, encoding="utf-8"); os.chmod(tmpf, 0o644); os.replace(tmpf, p)
        except OSError as e:
            tmpf.unlink(missing_ok=True)
            return fail(f"Could not save: {e}", 500)
        if wants_json:
            return jsonify({"ok": True, "restart": restart, "size": len(text.encode())})
        flash(f"Saved {p.name}." + (" Restart the site to apply the change." if restart else ""), "success")
        return back("/".join(rel.split("/")[:-1]))

    # ---------------- health: problems and automatic fixes ----------------
    @app.get("/health")
    def health():
        findings = doctor.diagnose()
        doctor.cache = (time.time(), findings)
        return render_template("health.html", page="health", findings=findings, history=doctor.history(), auto=doctor.auto_on(),
                               install=doctor.install_status(), fixable=any(f["fix"] and not f["root"] for f in findings),
                               pkgs=sorted({p for f in findings if f["root"] for p in f["pkgs"]}))

    @app.post("/health/fix")
    def health_fix():
        target = request.form.get("id", "")
        try:
            findings = doctor.diagnose()
            if target == "all":
                msgs, errs = doctor.apply_all(findings)
                for m in msgs:
                    flash(m, "success")
                for e in errs:
                    flash(e, "danger")
                if not msgs and not errs:
                    flash("Nothing needed fixing automatically.", "success")
            else:
                f = next((x for x in findings if x["id"] == target), None)
                flash(doctor.apply(f) if f else "That problem is already gone.", "success")
        except ServiceError as e:
            flash(str(e), "danger")
        return redirect("/health")

    @app.post("/health/install")
    def health_install():
        target = request.form.get("id", "all")
        pkgs = [p for f in doctor.diagnose(probe_site=False) if f["root"] and target in ("all", f["id"]) for p in f["pkgs"]]
        try:
            doctor.start_install(pkgs)
            flash("Approve the installation in the password prompt that just opened. This page shows the progress.", "success")
        except ServiceError as e:
            flash(str(e), "danger")
        return redirect("/health")

    @app.get("/api/install")
    def api_install():
        return jsonify(doctor.install_status())

    @app.get("/api/health")
    def api_health():
        f = doctor.findings()
        return jsonify({"errors": sum(x["level"] == "error" for x in f), "warnings": sum(x["level"] == "warn" for x in f),
                        "items": [{"id": x["id"], "level": x["level"], "title": x["title"]} for x in f if x["level"] in ("error", "warn")][:5]})

    # ---------------- erase everything in a folder ----------------
    @app.post("/files/clear")
    def files_clear():
        root, p, rel = fs(request.form.get("path"))
        if not p.is_dir():
            abort(400)
        if request.form.get("confirm", "").strip() != "DELETE":
            flash("Nothing was deleted. Type DELETE (capital letters) to confirm.", "danger")
            return back(rel)
        with doctor.lock:
            stopped = False
            if not rel and (web.running() or tor.running()):  # a site cannot be hosted with no files
                tor.stop(); web.stop(); stopped = True
            n = 0
            for e in list(os.scandir(p)):
                try:
                    shutil.rmtree(e.path) if e.is_dir(follow_symlinks=False) else os.unlink(e.path)
                    n += 1
                except OSError as err:
                    flash(f"Could not delete {e.name}: {err}", "danger")
            if not rel:
                stamp.unlink(missing_ok=True)
        flash(f"Deleted everything in {'the website folder' if not rel else rel} ({n} item{'s' if n != 1 else ''})."
              + (" Hosting was stopped because there is no website left." if stopped else ""), "success")
        return back(rel)

    # ---------------- logs ----------------
    def log_rows(name, q, errors):
        return [{"t": l, "c": "warn" if WARN.search(l) else "err" if ERR.search(l) else ""} for l in tail_log(base, name, q, errors)]

    def log_args():
        name = request.args.get("name", "")
        return (name if name in LOGS else next(iter(LOGS)), request.args.get("q", "")[:100], request.args.get("errors") == "1")

    @app.get("/logs")
    def logs_page():
        name, q, errs = log_args()
        return render_template("logs.html", page="logs", names=list(LOGS), name=name, q=q, errs=errs, rows=log_rows(name, q, errs))

    @app.get("/api/logs")
    def api_logs():
        name, q, errs = log_args()
        return jsonify({"rows": log_rows(name, q, errs)})

    @app.post("/logs/clear")
    def logs_clear():
        name = request.form.get("name", "")
        if name in LOGS:
            try:
                open(base / "logs" / LOGS[name], "w").close(); flash(f"Cleared the {name} log.", "success")
            except OSError as e:
                flash(f"Could not clear the log: {e}", "danger")
        return redirect(f"/logs?name={name}" if name in LOGS else "/logs")

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
        return go()

    @app.post("/quit")
    def quit_app():
        stop = request.form.get("stop_hosting") == "1"
        if stop:
            tor.stop(); web.stop()
        threading.Timer(app.config.get("QUIT_DELAY", 0.7), app.config.get("ON_QUIT") or (lambda: os._exit(0))).start()
        return render_template("bye.html", stopped=stop)

    def page_info():
        try:
            pd.check_platform(); problem = None
        except ServiceError as e:
            problem = str(e)
        need = missing_runtime(base / "site")
        return dict(missing=pd.missing_deps(), problem=problem, port=web.port, kind=web.rt.label(),
                    need_rt=", ".join(n for n, _ in need), need_apt=" ".join(dict.fromkeys(a for _, a in need)), files=count_files())

    def count_files(limit=10000):
        n = 0
        for _, _, names in os.walk(base / "site"):
            n += len(names)
            if n >= limit:
                return f"{limit}+"
        return str(n)

    @app.get("/")
    def index():
        """Read-only overview. Everything that changes the site lives on the Website page."""
        session.pop("conflict", None)
        return render_template("index.html", page="home", **page_info())

    @app.get("/website")
    def website():
        conflict = None
        if session.pop("conflict", False) and not web.running() and not port_free(web.port):
            alt = next((p for p in range(web.port + 1, web.port + 50) if port_free(p)), None)
            conflict = {"port": web.port, "owner": port_owner(web.port), "alt": alt}
        return render_template("website.html", page="website", conflict=conflict, max_gb=MAX_BYTES // 1024**3, **page_info())

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

    def checks():
        miss, need, kind = pd.missing_deps(), missing_runtime(base / "site"), web.rt.kind()
        return [
            {"label": "Tor is installed", "ok": "tor" not in miss, "hint": "sudo apt install tor"},
            {"label": "Nginx is installed", "ok": "nginx" not in miss, "hint": "sudo apt install nginx"},
            {"label": "Runtime for your site", "ok": not need, "note": "" if kind in ("php", "node", "python") else "not needed",
             "hint": "sudo apt install " + " ".join(dict.fromkeys(a for _, a in need))},
            {"label": "Website deployed", "ok": bool(kind), "hint": "Upload a ZIP on the Website page", "href": "/website"},
            {"label": "Hosting started", "ok": web.running() and tor.running(), "hint": "Press Start", "href": "/website"},
            {"label": "Recovery key created", "ok": bool((load_admin() or {}).get("recovery")), "hint": "Create one in Settings", "href": "/settings"}]

    def status():
        return {"tor": tor.running(), "bootstrap": tor.bootstrap(), "onion": tor.onion(),
                "web": web.running(), "site": bool(web.rt.kind()), "kind": web.rt.label(), "checks": checks(),
                "deployed": stamp.read_text() if stamp.exists() else None, "root": str(base / "site"), **sysinfo()}

    @app.get("/api/activity")
    def api_activity():
        return jsonify({"errors": sum(len(tail_log(base, n, "", True)) for n in LOGS), "rows": log_rows("AnonyHost", "", False)[-8:]})

    @app.get("/api/status")
    def api_status():
        return jsonify(status())

    @app.post("/deploy")
    def deploy():
        f = request.files.get("zip")
        if not f or not f.filename.lower().endswith(".zip"):
            flash("Choose a .zip file.", "danger"); return go("/website")
        tmp, new, old, site = Path(tempfile.mkdtemp(dir=base)), base / "site.new", base / "site.old", base / "site"
        try:
            z = tmp / "u.zip"; f.save(z)
            if shutil.disk_usage(base).free < 2 * z.stat().st_size + 2**26:
                raise ServiceError("Not enough free disk space for this upload.")
            shutil.rmtree(new, ignore_errors=True)
            security.safe_extract(z, new, max_bytes=MAX_BYTES)
            with doctor.lock:  # the watchdog must not restart anything while the site is being swapped
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
            kind = web.rt.kind()
            flash("Website deployed." if kind in (None, "static") else f"{web.rt.label()} website deployed.", "success")
            if kind not in (None, "static"):
                flash("This is a dynamic site: its code runs on this computer with your user's permissions and can read your data folder. "
                      "Only deploy code you trust.", "warning")
        except (security.UnsafeArchive, zipfile.BadZipFile, ServiceError) as e:
            flash(f"Deployment failed: {e}", "danger")
        except Exception as e:  # never show a bare 500; keep the site usable and log the traceback
            app.logger.exception("Deployment failed")
            if not site.exists() and old.exists():
                old.rename(site)
            flash(f"Deployment failed unexpectedly ({type(e).__name__}: {str(e)[:150]}). Details: data/logs/app.log", "danger")
        finally:
            shutil.rmtree(tmp, ignore_errors=True); shutil.rmtree(new, ignore_errors=True)
        return go("/website")

    @app.post("/start")
    def start():
        try:
            if begin():
                flash("Hosting started. Tor can take a minute or two to publish your address.", "success")
            else:
                flash(f"Port {web.port} is already in use. Choose how to fix it below.", "warning")
                return redirect("/website")  # the port-conflict resolver lives on the Website page
        except ServiceError as e:
            flash(str(e), "danger")
        return go()

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
                return redirect("/website")
            if begin():
                flash("Hosting started. Tor can take a minute or two to publish your address.", "success")
        except ServiceError as e:
            flash(str(e), "danger")
        return redirect("/website")

    @app.post("/stop")
    def stop():
        with doctor.lock:
            tor.stop(); web.stop()
        flash("Hosting stopped.", "success")
        return go()

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
        if not (S().get("autostart") and web.rt.kind()):
            return
        try:
            pd.check_platform()
            for n in doctor.start():
                app.logger.info("Autostart: %s", n)
        except ServiceError as e:
            app.logger.error("Autostart failed: %s", e)
    app.autostart = autostart
    return app

if __name__ == "__main__":
    create_app().run("127.0.0.1", 5000)
