import shutil, sys
from .process_manager import ServiceError

def os_release(path="/etc/os-release"):
    data = {}
    try:
        for line in open(path):
            if "=" in line:
                k, v = line.strip().split("=", 1)
                data[k] = v.strip('"')
    except OSError:
        pass
    return data

def check_platform(path="/etc/os-release"):
    if not sys.platform.startswith("linux"):
        raise ServiceError("TorHost currently supports Ubuntu and Debian only. Windows support is not implemented yet.")
    d = os_release(path)
    ids = {d.get("ID", ""), *d.get("ID_LIKE", "").split()}
    if not ids & {"ubuntu", "debian"}:
        raise ServiceError(f"Unsupported Linux distribution '{d.get('ID', 'unknown')}'. Ubuntu or Debian is required.")
    return d

def missing_deps():
    return [n for n in ("tor", "nginx") if not shutil.which(n)]
