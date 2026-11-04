import os, shutil, subprocess, webbrowser
from pathlib import Path

def find_tor_browser(custom=None):
    home = Path.home()
    cands = [custom] if custom else []
    cands += [home / ".local/share/torbrowser/tbb/x86_64/tor-browser/Browser/start-tor-browser",
              home / "tor-browser/Browser/start-tor-browser", "/opt/tor-browser/Browser/start-tor-browser"]
    cands += [shutil.which(n) for n in ("torbrowser-launcher", "tor-browser", "start-tor-browser")]
    for c in cands:
        if c and Path(c).is_file() and os.access(c, os.X_OK):
            return str(c)
    return None

def open_in_tor_browser(exe, url):
    """Argument list, no shell; detached so closing AnonyHost doesn't close the browser."""
    subprocess.Popen([exe, url], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                     stderr=subprocess.DEVNULL, start_new_session=True)

APP_BROWSERS = ("google-chrome-stable", "google-chrome", "chromium", "chromium-browser", "brave-browser", "microsoft-edge")

def open_window(url, profile):
    """Open the dashboard in its own app-style window (Chromium family); else the default browser."""
    if os.geteuid() != 0:  # Chromium refuses to run as root without --no-sandbox, which we don't use
        for name in APP_BROWSERS:
            exe = shutil.which(name)
            if not exe:
                continue
            args = [exe, f"--app={url}", "--no-first-run", "--no-default-browser-check", "--window-size=1280,860"]
            if not os.path.realpath(exe).startswith("/snap"):  # snap builds can't use a profile in hidden dirs
                args.append(f"--user-data-dir={profile}")
            try:
                subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
                return "window"
            except OSError:
                continue
    webbrowser.open(url)
    return "browser"
