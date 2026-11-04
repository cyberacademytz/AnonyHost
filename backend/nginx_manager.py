import shutil, subprocess
from pathlib import Path
from . import process_manager as pm

def nginx_conf(base, port):
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
    client_body_temp_path {tmp('body')};
    proxy_temp_path {tmp('proxy')};
    fastcgi_temp_path {tmp('fastcgi')};
    uwsgi_temp_path {tmp('uwsgi')};
    scgi_temp_path {tmp('scgi')};
    server {{
        listen 127.0.0.1:{int(port)};
        server_name _;
        root {b}/site;
        index index.html;
        autoindex off;
        location ~ /\\. {{ deny all; }}
        location / {{
            limit_except GET HEAD {{ deny all; }}
            try_files $uri $uri/ =404;
        }}
    }}
}}
"""

class NginxManager:
    """Runs a private, unprivileged nginx instance bound to loopback only."""
    def __init__(self, base, port):
        self.base, self.port = Path(base), int(port)
        self.pid, self.conf = self.base / "run/nginx.pid", self.base / "nginx.conf"

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
        if not (self.base / "site/index.html").exists():
            raise pm.ServiceError("No website deployed yet. Upload a ZIP first.")
        self.conf.write_text(nginx_conf(self.base, self.port))
        t = self._cmd("-t")
        if t.returncode:
            raise pm.ServiceError("Nginx configuration error: " + t.stderr[-300:])
        r = self._cmd()
        if r.returncode or not pm.wait_for_pid(self.pid, "nginx"):
            raise pm.ServiceError(f"Nginx failed to start (is port {self.port} already in use?): " + r.stderr[-300:])

    def stop(self):
        pm.terminate(self.pid, "nginx")
