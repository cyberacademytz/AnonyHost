# AnonyHost - DarkWeb Hosting Tool
Host a website as a Tor v3 onion service from your own PC: no public IP, domain or port forwarding. Static sites, PHP, Node.js and Python apps are supported.

**Status:** Ubuntu/Debian only. Windows or other OS environment are NOT implemented yet.
<img width="1920" height="1044" alt="Dashboard" src="https://github.com/user-attachments/assets/a3878061-55e5-452e-b9e1-6bf5290a9d73" />


## Static and dynamic websites
Upload a ZIP in the dashboard. AnonyHost looks at the top level of the ZIP (or inside one single folder) and picks the type:

| Type | Detected by | Needs |
| --- | --- | --- |
| Static | `index.html` | nothing |
| PHP | `index.php` (or other `*.php` and no `index.html`) | `sudo apt install php-fpm` |
| Node.js | `package.json` with `scripts.start`, or `server.js` / `app.js` / `index.js` / `main.js` | `sudo apt install nodejs npm` |
| Python | `app.py` / `server.py` / `main.py` and no `index.html` | python3 (`requirements.txt` is installed into a private virtualenv) |

- **PHP** runs in a private php-fpm owned by AnonyHost (loopback/unix socket only, `open_basedir` limited to the website folder). Unknown URLs fall back to `index.php`, so front-controller frameworks work. Sessions and uploads use private folders in the data directory.
- **Node.js and Python** apps must listen on `127.0.0.1` and the port in the `PORT` environment variable (`HOST` is also set). Nginx proxies the onion service to the app (WebSockets work). `npm install --omit=dev` runs once if `node_modules` is missing, and `requirements.txt` is installed on first start and whenever it changes (both download from the normal internet, not through Tor).
- Override detection with an optional `anonyhost.json` at the top of the site: `{"runtime": "node", "start": "node dist/server.js"}` (`runtime` is `static`, `php`, `node` or `python`; `start` is run without a shell).
- Press **Restart site** (Dashboard, Website or Files page) after changing a Node.js/Python app. Tor stays up, so the address stays online.
- The app's output is in the **Site app** log, PHP errors in **PHP-FPM**.

## Automatic problem handling
AnonyHost finds and fixes common hosting problems for static, PHP, Node.js and Python sites. It is on by default (**Settings > Startup > Fix problems automatically**). Everything it does is written to the **Auto-fix** log and shown on the **Health** page.

**When you press Start**
- A busy hosting port is replaced by the next free one (the onion address does not change). Nothing else is ever stopped or killed.
- Leftover process files and sockets from a crash are cleaned up. A stale PHP-FPM socket or wrong Tor folder permissions are repaired and the start is retried.
- Python apps: a missing well-known package (Flask, Django, requests, FastAPI, ...) is installed into a private virtualenv; a script that only defines a Flask or FastAPI `app` is started with that framework's own server; Django projects (`manage.py`) are detected.
- Node.js apps: a missing module triggers `npm install`, then a retry.
- An app that ignores `PORT` and listens on its own port is detected and used anyway. If it listens on all interfaces (reachable from your local network, outside Tor) the Health page warns you.
- If the app still cannot start, the error shows the cause in plain words (for example "Python module 'x' is missing").

**What needs you**
- Installing system packages (Tor, nginx, php-fpm, nodejs, npm, PHP extensions) needs administrator rights. The **Health** page offers an Install button that opens your system's password prompt (pkexec). Only a fixed list of package names can be installed. If no prompt is available it shows the `sudo apt install ...` command instead.
- Errors in your own code (a syntax error, a missing file) are explained but cannot be fixed for you.
- Installing Python packages and `npm install` download from the normal internet, not through Tor.

## License
AnonyHost is free software, licensed under the **GNU General Public License, version 3 or (at your option) any later version** (GPL-3.0-or-later). The full text is in the `LICENSE` file.

Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)

This program comes with **no warranty**. You may use, study, change and share it. If you distribute a changed version, you must offer its source code under the same license. Every source file carries an SPDX notice (`SPDX-License-Identifier: GPL-3.0-or-later`).

Bundled third-party work: the **Cutive Mono** font (`frontend/static/fonts/`) is Copyright 2012 The Cutive Project Authors and is licensed under the SIL Open Font License 1.1 (the text is in `frontend/static/fonts/OFL.txt`). Tor, nginx, Flask and the other programs AnonyHost uses are installed separately and keep their own licenses.

## Limits and security notes
- Website limit: 1 GB (upload and extracted). ZIPs are validated (no path traversal/symlinks) and files are stored without the executable bit.
- **Dynamic sites run code on your computer** as your user (PHP is restricted to the site folder, Node.js and Python are not). Such code could read your data folder, including the onion keys, so only deploy code you trust. Static sites execute nothing.
- A dynamic site's own requests to the internet (API calls, fetching URLs) go out from your real IP, not through Tor. Nginx never forwards visitor addresses to your app.
- The dashboard listens on 127.0.0.1 only and is never exposed through the onion service. Tor does not guarantee anonymity against application-level leaks in your site.
