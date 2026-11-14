# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
import shutil, subprocess
from datetime import datetime
from pathlib import Path
from . import process_manager as pm
from .runtime import Runtime

PHP_PARAMS = """            fastcgi_param QUERY_STRING $query_string;
            fastcgi_param REQUEST_METHOD $request_method;
            fastcgi_param CONTENT_TYPE $content_type;
            fastcgi_param CONTENT_LENGTH $content_length;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param REQUEST_URI $request_uri;
            fastcgi_param DOCUMENT_URI $document_uri;
            fastcgi_param DOCUMENT_ROOT $document_root;
            fastcgi_param SERVER_PROTOCOL $server_protocol;
            fastcgi_param REQUEST_SCHEME $scheme;
            fastcgi_param GATEWAY_INTERFACE CGI/1.1;
            fastcgi_param SERVER_NAME $host;
            fastcgi_param REDIRECT_STATUS 200;
            fastcgi_param HTTP_PROXY "";"""

DOWN_PAGE = """        error_page 502 503 504 @anonyhost_down;
        location @anonyhost_down {
            default_type text/html;
            add_header Retry-After 5 always;
            return 503 '<!doctype html><meta charset="utf-8"><meta http-equiv="refresh" content="6"><title>Restarting</title><body style="font-family:monospace;background:#000;color:#0f0;padding:3em"><h1>Restarting...</h1><p>This site is starting up again. This page refreshes by itself.</p>';
        }
"""

def _locations(b, kind, up, local_host=False):
    """The nginx location blocks for each kind of site. Nothing here forwards visitor addresses."""
    if kind == "php":
        return f"""        index index.php index.html;
        client_max_body_size 64m;
{DOWN_PAGE}        location ~ /\\. {{ deny all; }}
        location = /anonyhost.json {{ deny all; }}
        location / {{ try_files $uri $uri/ /index.php?$query_string; }}
        location ~ \\.php$ {{
            try_files $uri =404;
{PHP_PARAMS}
            fastcgi_pass unix:{up['sock']};
            fastcgi_read_timeout 60s;
        }}
"""
    if kind in ("node", "python"):
        host = f"127.0.0.1:{int(up['app_port'])}" if local_host else "$host"  # some frameworks reject unknown host names
        fwd = "            proxy_set_header X-Forwarded-Host $host;\n" if local_host else ""
        return f"""        client_max_body_size 64m;
{DOWN_PAGE}        location / {{
            proxy_pass http://127.0.0.1:{int(up['app_port'])};
            proxy_http_version 1.1;
            proxy_set_header Host {host};
{fwd}
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection $connection_upgrade;
            proxy_read_timeout 60s;
        }}
"""
    return """        index index.html;
        location ~ /\\. { deny all; }
        location / {
            limit_except GET HEAD { deny all; }
            try_files $uri $uri/ =404;
        }
"""

def nginx_conf(base, port, kind="static", upstream=None, local_host=False):
    b = Path(base)
    tmp = lambda n: f"{b}/run/{n}_temp"
    return f"""worker_processes 1;
daemon on;
pid {b}/run/nginx.pid;
error_log {b}/logs/nginx-error.log warn;
events {{ worker_connections 256; }}
http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    access_log off;
    server_tokens off;
    map $http_upgrade $connection_upgrade {{ default upgrade; '' close; }}
    client_body_temp_path {tmp('body')};
    proxy_temp_path {tmp('proxy')};
    fastcgi_temp_path {tmp('fastcgi')};
    uwsgi_temp_path {tmp('uwsgi')};
    scgi_temp_path {tmp('scgi')};
    server {{
        listen 127.0.0.1:{int(port)};
        server_name _;
        root {b}/site;
        autoindex off;
{_locations(b, kind, upstream or {}, local_host)}    }}
}}
"""

class NginxManager:
    """Runs a private, unprivileged nginx instance bound to loopback only, plus the site's runtime (PHP-FPM, Node or Python app)."""
    def __init__(self, base, port):
        self.base, self.port = Path(base), int(port)
        self.pid, self.conf = self.base / "run/nginx.pid", self.base / "nginx.conf"
        self.rt = Runtime(self.base)

    def running(self):
        return pm.alive(self.pid, "nginx")

    def _cmd(self, *args):
        exe = shutil.which("nginx")
        if not exe:
            raise pm.ServiceError("Nginx is not installed. Run scripts/install_linux.sh first.")
        return subprocess.run([exe, "-c", str(self.conf), "-p", str(self.base), *args],
                              capture_output=True, text=True, timeout=20)

    def start(self):
        if self.running():
            return
        kind = self.rt.kind()
        if not kind:
            raise pm.ServiceError("No website deployed yet. Upload a ZIP first.")
        up = self.rt.start(self.port)
        try:
            self.conf.write_text(nginx_conf(self.base, self.port, kind, up, (self.base / "proxy_local_host").exists()))
            t = self._cmd("-t")
            if t.returncode:
                raise pm.ServiceError("Nginx configuration error: " + t.stderr[-300:])
            try:  # a marker lets the health check ignore errors from before this start
                with open(self.base / "logs/nginx-error.log", "a") as lf:
                    lf.write(f"--- nginx starting {datetime.now():%Y-%m-%d %H:%M:%S} ---\n")
            except OSError:
                pass
            r = self._cmd()
            if r.returncode or not pm.wait_for_pid(self.pid, "nginx"):
                raise pm.ServiceError(f"Nginx failed to start (is port {self.port} already in use?): " + r.stderr[-300:])
            pm.set_want(self.base)
        except Exception:
            self.rt.stop()
            raise

    def stop(self):
        pm.clear_want(self.base)
        pm.terminate(self.pid, "nginx")
        self.rt.stop()
