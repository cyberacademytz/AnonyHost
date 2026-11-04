import base64, re, secrets, zipfile, zlib
from pathlib import Path

ONION_RE = re.compile(r"^[a-z2-7]{56}\.onion$")

class UnsafeArchive(Exception):
    pass

def valid_onion(addr):
    return bool(ONION_RE.match((addr or "").strip()))

def safe_join(root, rel):
    root = Path(root).resolve()
    p = (root / rel).resolve()
    if p != root and root not in p.parents:
        raise ValueError("Path escapes the website directory")
    return p

def safe_extract(zip_path, dest, max_bytes=1024**3, max_files=50000):
    """Validate the whole archive first, then extract with a streamed size cap."""
    try:
        _extract(zip_path, Path(dest), max_bytes, max_files)
    except (OSError, ValueError, RuntimeError, NotImplementedError, zlib.error) as e:
        raise UnsafeArchive(f"Could not extract the ZIP ({type(e).__name__}: {str(e)[:120]}). It may be encrypted, "
                            "use an unsupported compression method, or contain conflicting file names.") from e

def _extract(zip_path, dest, max_bytes, max_files):
    with zipfile.ZipFile(zip_path) as z:
        infos = [i for i in z.infolist() if not i.filename.startswith("__MACOSX/")]
        if len(infos) > max_files:
            raise UnsafeArchive("Archive contains too many files.")
        names = [i.filename.replace("\\", "/") for i in infos]
        total = 0
        for i, n in zip(infos, names):
            if n.startswith("/") or ".." in Path(n).parts or re.match(r"^[A-Za-z]:", n) or "\x00" in n:
                raise UnsafeArchive(f"Unsafe path in archive: {i.filename!r}")
            if (i.external_attr >> 16) & 0o170000 == 0o120000:
                raise UnsafeArchive(f"Symlinks are not allowed: {i.filename!r}")
            total += i.file_size
            if total > max_bytes:
                raise UnsafeArchive("Archive is too large when extracted.")
        strip = ""
        if "index.html" not in names:  # accept a ZIP of a single folder that contains index.html
            tops = {n.split("/")[0] for n in names}
            if len(tops) == 1 and f"{next(iter(tops))}/index.html" in names:
                strip = next(iter(tops)) + "/"
            else:
                raise UnsafeArchive("The ZIP must contain index.html at its top level (or inside one single folder).")
        dest.mkdir(parents=True, exist_ok=True)
        written = 0
        for i, n in zip(infos, names):
            rel = n[len(strip):]
            if not rel:
                continue
            target = safe_join(dest, rel)
            if rel.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with z.open(i) as src, open(target, "wb") as out:
                while chunk := src.read(65536):
                    written += len(chunk)
                    if written > max_bytes:
                        raise UnsafeArchive("Archive is too large when extracted.")
                    out.write(chunk)
            target.chmod(0o644)  # never executable

def new_recovery_key():
    """100-bit key shown once to the user, e.g. ABCDE-FGHIJ-KLMNO-PQRST."""
    raw = base64.b32encode(secrets.token_bytes(13)).decode()[:20]
    return "-".join(raw[i:i + 5] for i in range(0, 20, 5))

def norm_key(s):
    return re.sub(r"[^A-Z2-7]", "", (s or "").upper())
