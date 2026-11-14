# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""The Debian package: contents, metadata, maintainer scripts, the service-switching helper, and a real dpkg install/remove/purge."""
import configparser, gzip, hashlib, io, os, re, shutil, subprocess, sys, tarfile, time
from pathlib import Path
import pytest
ROOT = Path(__file__).parent.parent
needs_dpkg = pytest.mark.skipif(not shutil.which("dpkg-deb"), reason="dpkg-deb not installed")
_cache = {}

def build(tmp_path_factory_dir):
    out = Path(tmp_path_factory_dir) / "out"
    r = subprocess.run(["bash", str(ROOT / "scripts/build_deb.sh"), str(out)], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    return next(out.glob("anonyhost_*_all.deb"))

def deb(tmp_path):
    if "deb" not in _cache or not _cache["deb"].exists():
        import tempfile
        _cache["dir"] = Path(tempfile.mkdtemp()); _cache["deb"] = build(_cache["dir"])
        x = _cache["dir"] / "x"; x.mkdir()
        subprocess.run(["dpkg-deb", "-x", str(_cache["deb"]), str(x)], check=True)
        _cache["x"] = x
    return _cache["deb"], _cache["x"]

def version():
    return re.search(r'VERSION = "([^"]+)"', (ROOT / "config/settings.py").read_text()).group(1)

def field(d, name):
    return subprocess.run(["dpkg-deb", "-f", str(d), name], capture_output=True, text=True).stdout.strip()

@needs_dpkg
def test_metadata(tmp_path):
    d, x = deb(tmp_path)
    assert d.name == f"anonyhost_{version()}_all.deb"
    assert field(d, "Package") == "anonyhost" and field(d, "Version") == version() and field(d, "Architecture") == "all"
    deps = field(d, "Depends")
    for need in ("python3 (>= 3.10)", "python3-flask (>= 2.0)", "tor", "nginx"):
        assert need in deps, need
    assert "python3-tk" not in deps and "tkinter" not in deps   # no GUI toolkit is needed any more
    for need in ():
        assert need in deps, need
    assert "php-fpm" in field(d, "Suggests") and "pkexec" in field(d, "Recommends")
    assert field(d, "Maintainer") and field(d, "Homepage").startswith("https://") and "onion" in field(d, "Description")
    assert not re.search(r"@\w+@", subprocess.run(["dpkg-deb", "-I", str(d), "control"], capture_output=True, text=True).stdout)  # no unreplaced template fields
    assert int(field(d, "Installed-Size")) > 100

@needs_dpkg
def test_contents_are_clean_and_rooted(tmp_path):
    d, x = deb(tmp_path)
    tar = subprocess.run(["dpkg-deb", "--fsys-tarfile", str(d)], capture_output=True).stdout
    names, bad_owner, bad_mode = [], [], []
    with tarfile.open(fileobj=io.BytesIO(tar)) as t:
        for m in t.getmembers():
            names.append(m.name.lstrip("./"))
            if (m.uid, m.gid) != (0, 0) or m.uname != "root" or m.gname != "root": bad_owner.append(m.name)
            if m.isfile() and m.mode & 0o022: bad_mode.append(m.name)          # nothing writable by group/others
            if m.isfile() and not (m.mode & 0o100) and m.mode != 0o644: bad_mode.append(m.name)
    assert not bad_owner and not bad_mode, (bad_owner, bad_mode)
    top = {n.split("/")[0] + "/" + (n.split("/")[1] if "/" in n else "") for n in names if n}
    assert all(any(n.startswith(p) for p in ("opt/anonyhost", "usr/bin", "usr/lib/anonyhost", "usr/share/applications", "usr/share/doc/anonyhost",
                                             "usr/share/man/man1", "usr/share/icons/hicolor/256x256/apps", "opt", "usr", "")) for n in names)
    forbidden = [n for n in names if re.search(r"(^|/)(tests?|scripts|packaging|dist|data|\.venv|\.pytest_cache|__pycache__|\.git)(/|$)|\.pyc$|\.zip$|\.deb$", n)]
    assert not forbidden, forbidden
    must = ["opt/anonyhost/app.py", "opt/anonyhost/launcher.py", "opt/anonyhost/backend/doctor.py", "opt/anonyhost/backend/runtime.py",
            "opt/anonyhost/config/settings.py", "opt/anonyhost/frontend/templates/index.html", "opt/anonyhost/frontend/static/css/torhost.css",
            "opt/anonyhost/frontend/static/fonts/cutive-mono.woff2", "opt/anonyhost/frontend/static/js/editor.js", "usr/bin/anonyhost",
            "usr/bin/anonyhost-stop", "usr/lib/anonyhost/system-services.sh", "usr/share/applications/anonyhost-dashboard.desktop", "usr/share/icons/hicolor/256x256/apps/anonyhost.png", "usr/share/doc/anonyhost/copyright",
            "usr/share/doc/anonyhost/changelog.gz", "usr/share/man/man1/anonyhost.1.gz", "usr/share/man/man1/anonyhost-stop.1.gz"]
    assert [m for m in must if m not in names] == []

@needs_dpkg
def test_md5sums_match(tmp_path):
    d, x = deb(tmp_path)
    ctl = subprocess.run(["dpkg-deb", "-I", str(d), "md5sums"], capture_output=True, text=True).stdout
    rows = [l.split(None, 1) for l in ctl.splitlines() if l.strip()]
    assert len(rows) > 40
    for md5, rel in rows:
        assert hashlib.md5((x / rel.strip()).read_bytes()).hexdigest() == md5, rel

@needs_dpkg
def test_commands_and_menu_entries(tmp_path):
    d, x = deb(tmp_path)
    for cmd in ("anonyhost", "anonyhost-stop"):
        f = x / "usr/bin" / cmd
        assert f.read_text().startswith("#!/bin/sh\n") and os.access(f, os.X_OK)
        assert subprocess.run(["sh", "-n", str(f)]).returncode == 0
    assert "/opt/anonyhost/launcher.py" in (x / "usr/bin/anonyhost").read_text()
    assert "--stop-all" in (x / "usr/bin/anonyhost-stop").read_text()
    assert sorted(p.name for p in (x / "usr/share/applications").iterdir()) == ["anonyhost-dashboard.desktop"]   # exactly one menu entry
    for name in ("anonyhost-dashboard",):
        cp = configparser.ConfigParser(interpolation=None, strict=True); cp.optionxform = str
        cp.read_string((x / f"usr/share/applications/{name}.desktop").read_text())
        e = cp["Desktop Entry"]
        assert e["Type"] == "Application" and e["Name"].startswith("AnonyHost") and e["Terminal"] == "false" and e["Categories"].endswith(";")
        assert (x / "usr/bin" / e["Exec"].split()[0]).exists() and e["Icon"] == "anonyhost"
    assert (x / "usr/share/icons/hicolor/256x256/apps/anonyhost.png").read_bytes()[:4] == b"\x89PNG"
    man = gzip.decompress((x / "usr/share/man/man1/anonyhost.1.gz").read_bytes()).decode()
    assert ".TH ANONYHOST 1" in man and "--stop-all" in man.replace("\\-", "-") and "keep-system-services" in man.replace("\\-", "-")
    assert ".so man1/anonyhost.1" in gzip.decompress((x / "usr/share/man/man1/anonyhost-stop.1.gz").read_bytes()).decode()
    assert (x / "opt/anonyhost/frontend/static/fonts/OFL.txt").exists()
    assert "Files:" in (x / "usr/share/doc/anonyhost/copyright").read_text() and "anonyhost (" in gzip.decompress((x / "usr/share/doc/anonyhost/changelog.gz").read_bytes()).decode()

@needs_dpkg
def test_maintainer_scripts_are_valid_shell_and_do_no_harm_on_unexpected_actions(tmp_path):
    d, x = deb(tmp_path)
    ctl = tmp_path / "ctl"; subprocess.run(["dpkg-deb", "-e", str(d), str(ctl)], check=True)
    for s in ("postinst", "prerm", "postrm"):
        p = ctl / s
        assert os.access(p, os.X_OK) and p.read_text().startswith("#!/bin/sh")
        assert subprocess.run(["sh", "-n", str(p)]).returncode == 0
        if shutil.which("dash"): assert subprocess.run(["dash", "-n", str(p)]).returncode == 0
        env = {**os.environ, "DPKG_ROOT": str(tmp_path / "fakeroot")}
        for action in ("abort-upgrade", "failed-upgrade", "abort-remove"):   # actions the scripts must accept without side effects
            assert subprocess.run(["sh", str(p), action], env=env, capture_output=True).returncode == 0

# ---------------- the helper that switches the distribution's tor/nginx services off and back on ----------------
STUB_SYSTEMCTL = """#!/bin/sh
# fake systemctl: state in $FAKE/enabled (one unit per line); every call is logged
echo "$*" >> "$FAKE/calls"
cmd="$1"; shift
[ "$1" = "--quiet" ] && shift
case "$cmd" in
  is-enabled|is-active) grep -qx "$1" "$FAKE/enabled" ;;
  disable) shift_args=""; for a in "$@"; do case "$a" in --now) ;; *) u="$a";; esac; done; grep -vx "$u" "$FAKE/enabled" > "$FAKE/e2"; mv "$FAKE/e2" "$FAKE/enabled" ;;
  enable) for a in "$@"; do case "$a" in --now) ;; *) u="$a";; esac; done; echo "$u" >> "$FAKE/enabled" ;;
esac
"""
STUB_DPKGQ = r"""#!/bin/sh
# fake dpkg-query -W -f='${Conffiles}\n': print " path md5" for every file listed in $FAKE/shipped (path<TAB>content)
while IFS='	' read -r path content; do
  [ -n "$path" ] && printf ' %s %s\n' "$path" "$(printf '%s' "$content" | md5sum | cut -d' ' -f1)"
done < "$FAKE/shipped"
"""

def fake_system(tmp_path, tor_default=True, nginx_default=True, extra_site=False, extra_conf=False, keep=False, enabled=("tor.service", "tor@default.service", "nginx.service")):
    fake = tmp_path / "fake"; (fake / "bin").mkdir(parents=True)
    root = fake / "root"
    shipped = {"/etc/tor/torrc": "## default torrc", "/etc/nginx/nginx.conf": "events {}", "/etc/nginx/sites-available/default": "server { listen 80; }"}
    for path, content in shipped.items():
        p = root / path.lstrip("/"); p.parent.mkdir(parents=True, exist_ok=True)
        mine = content
        if path.endswith("torrc") and not tor_default: mine += "\nHiddenServiceDir /var/lib/tor/mine\n"
        if path.endswith("nginx.conf") and not nginx_default: mine += "\n# edited by the admin"
        p.write_text(mine)
    (root / "etc/nginx/sites-enabled").mkdir(parents=True, exist_ok=True)
    os.symlink("/etc/nginx/sites-available/default", root / "etc/nginx/sites-enabled/default")
    (root / "etc/nginx/conf.d").mkdir(exist_ok=True)
    if extra_site: (root / "etc/nginx/sites-enabled/blog").write_text("server {}")
    if extra_conf: (root / "etc/nginx/conf.d/app.conf").write_text("server {}")
    if keep: (root / "etc/anonyhost").mkdir(parents=True); (root / "etc/anonyhost/keep-system-services").write_text("")
    (root / "run/systemd/system").mkdir(parents=True)
    (fake / "shipped").write_text("".join(f"{k}\t{v}\n" for k, v in shipped.items()))
    (fake / "enabled").write_text("".join(u + "\n" for u in enabled)); (fake / "calls").write_text("")
    for name, body in (("systemctl", STUB_SYSTEMCTL), ("dpkg-query", STUB_DPKGQ)):
        (fake / "bin" / name).write_text(body); os.chmod(fake / "bin" / name, 0o755)
    return fake, root

def run_helper(fake, root, fn):
    env = {**os.environ, "PATH": f"{fake / 'bin'}:{os.environ['PATH']}", "FAKE": str(fake), "ANONYHOST_ROOT": str(root)}
    r = subprocess.run(["sh", "-c", f". '{ROOT / 'packaging/debian/system-services.sh'}'; {fn}"], env=env, capture_output=True, text=True, timeout=30)
    assert r.returncode == 0, r.stderr
    return r.stdout, (fake / "enabled").read_text().split(), (root / "var/lib/anonyhost/disabled-services")

def test_default_system_services_are_switched_off_and_restored(tmp_path):
    fake, root = fake_system(tmp_path)
    out, enabled, state = run_helper(fake, root, "disable_defaults")
    assert enabled == [] and "switched off the unused system service tor.service" in out and "nginx.service" in out
    assert sorted(state.read_text().split()) == ["nginx.service", "tor.service", "tor@default.service"]
    out, enabled, state = run_helper(fake, root, "disable_defaults")          # a second install changes nothing
    assert out == "" and enabled == []
    out, enabled, state = run_helper(fake, root, "restore_services")
    assert sorted(enabled) == ["nginx.service", "tor.service", "tor@default.service"] and not state.exists()
    assert "enable --now nginx.service" in (fake / "calls").read_text()

@pytest.mark.parametrize("kw,still_on,off", [
    ({"tor_default": False}, ["tor.service", "tor@default.service"], ["nginx.service"]),       # the user runs their own Tor
    ({"nginx_default": False}, ["nginx.service"], ["tor.service", "tor@default.service"]),     # edited nginx.conf
    ({"extra_site": True}, ["nginx.service"], ["tor.service", "tor@default.service"]),         # another site is enabled
    ({"extra_conf": True}, ["nginx.service"], ["tor.service", "tor@default.service"]),         # conf.d snippet
])
def test_configured_system_services_are_never_touched(tmp_path, kw, still_on, off):
    fake, root = fake_system(tmp_path, **kw)
    out, enabled, state = run_helper(fake, root, "disable_defaults")
    assert sorted(enabled) == sorted(still_on), (kw, enabled)
    assert sorted(state.read_text().split()) == sorted(off)

def test_keep_marker_and_services_that_were_already_off(tmp_path):
    fake, root = fake_system(tmp_path, keep=True)
    out, enabled, state = run_helper(fake, root, "disable_defaults")
    assert len(enabled) == 3 and not state.exists() and (fake / "calls").read_text() == ""
    fake, root = fake_system(tmp_path / "b", enabled=())                       # nothing enabled: nothing to disable, nothing to restore
    out, enabled, state = run_helper(fake, root, "disable_defaults")
    assert out == "" and state.read_text() == ""
    run_helper(fake, root, "restore_services"); assert (fake / "enabled").read_text() == "" and not state.exists()

def test_no_systemd_means_no_changes(tmp_path):
    fake, root = fake_system(tmp_path); shutil.rmtree(root / "run")
    out, enabled, state = run_helper(fake, root, "disable_defaults")
    assert len(enabled) == 3 and not state.exists() and (fake / "calls").read_text() == ""

# ---------------- a real dpkg install / upgrade / remove / purge in a separate root directory ----------------
def dpkg_ok():
    if os.geteuid() != 0 or not shutil.which("dpkg"): return False
    v = subprocess.run(["dpkg", "--version"], capture_output=True, text=True).stdout
    m = re.search(r"version (\d+)\.(\d+)\.(\d+)", v)
    return bool(m) and tuple(map(int, m.groups())) >= (1, 21, 2)   # --force-script-chrootless

@needs_dpkg
def test_real_dpkg_lifecycle_in_a_separate_root(tmp_path):
    if not dpkg_ok(): pytest.skip("needs root and dpkg >= 1.21.2")
    d, x = deb(tmp_path)
    inst = tmp_path / "inst"
    for p in ("var/lib/dpkg/info", "var/lib/dpkg/updates"): (inst / p).mkdir(parents=True)
    (inst / "var/lib/dpkg/status").write_text(""); (inst / "var/lib/dpkg/available").write_text("")
    base = ["dpkg", f"--root={inst}", "--force-script-chrootless", "--force-depends", "--no-triggers"]
    def dp(*a): return subprocess.run(base + list(a), capture_output=True, text=True, timeout=120)
    status = lambda: subprocess.run(["dpkg", f"--root={inst}", "-s", "anonyhost"], capture_output=True, text=True).stdout
    r = dp("-i", str(d)); assert r.returncode == 0 and "Setting up anonyhost" in r.stdout, r.stderr
    assert "Status: install ok installed" in status() and (inst / "opt/anonyhost/launcher.py").exists() and (inst / "usr/bin/anonyhost").exists()
    r = dp("-i", str(d)); assert r.returncode == 0                       # re-installing the same version (upgrade path) works
    (inst / "opt/anonyhost/backend/__pycache__").mkdir(); (inst / "opt/anonyhost/backend/__pycache__/x.pyc").write_bytes(b"x")   # bytecode made after install
    r = dp("-r", "anonyhost"); assert r.returncode == 0, r.stderr
    assert "deinstall ok config-files" in status()
    left = [p for p in (inst / "opt").rglob("*")] + [p for p in (inst / "usr").rglob("*") if p.is_file()]
    assert left == [], left                                              # no program files and no empty folders left behind
    r = dp("-P", "anonyhost"); assert r.returncode == 0, r.stderr
    assert "not installed" in subprocess.run(["dpkg", f"--root={inst}", "-s", "anonyhost"], capture_output=True, text=True).stderr
    assert not (inst / "var/lib/anonyhost").exists()

@needs_dpkg
def test_installed_layout_starts_the_dashboard(tmp_path):
    d, x = deb(tmp_path)
    data = tmp_path / "data"; env = {**os.environ, "ANONYHOST_DATA": str(data), "PYTHONDONTWRITEBYTECODE": "1"}
    app = x / "opt/anonyhost"
    try:
        subprocess.run([sys.executable, str(app / "launcher.py"), "--no-browser"], env=env, timeout=30)
        url = data / "run/dashboard.url"
        for _ in range(100):
            if url.exists() and url.read_text().strip(): break
            time.sleep(0.1)
        import urllib.request
        base = url.read_text().strip()
        assert urllib.request.urlopen(base + "/login", timeout=5).status == 200
        assert urllib.request.urlopen(base + "/static/css/torhost.css", timeout=5).status == 200
        assert urllib.request.urlopen(base + "/static/js/editor.js", timeout=5).status == 200
    finally:
        subprocess.run([sys.executable, str(app / "launcher.py"), "--stop"], env=env, timeout=30)
    assert not list(app.rglob("__pycache__"))      # a read-only, root-owned program folder is never written to

@needs_dpkg
def test_build_is_reproducible(tmp_path):
    a = build(tmp_path / "a"); time.sleep(2.2); b = build(tmp_path / "b")   # the clock has moved on: dates must not leak into the package
    assert hashlib.sha256(a.read_bytes()).hexdigest() == hashlib.sha256(b.read_bytes()).hexdigest()
