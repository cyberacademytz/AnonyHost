# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Licensing: GPL-3.0-or-later for the program (holder www.tca.ac.tz), OFL-1.1 for the bundled font."""
import glob, re, shutil, subprocess
from pathlib import Path
import pytest
ROOT = Path(__file__).parent.parent
HOLDER = "www.tca.ac.tz (https://www.tca.ac.tz)"

def sources():
    pats = ["app.py", "launcher.py", "backend/*.py", "config/*.py", "tests/*.py", "tests/js/*.js", "frontend/static/js/*.js", "frontend/static/css/*.css",
            "scripts/*", "packaging/debian/anonyhost", "packaging/debian/anonyhost-stop", "packaging/debian/system-services.sh",
            "packaging/debian/postinst", "packaging/debian/prerm", "packaging/debian/postrm"]
    out = []
    for p in pats:
        out += [Path(f) for f in glob.glob(str(ROOT / p))]
    return sorted(set(f for f in out if f.is_file()))

def test_license_file_is_the_official_gpl3_text():
    t = (ROOT / "LICENSE").read_text()
    assert "GNU GENERAL PUBLIC LICENSE" in t and "Version 3, 29 June 2007" in t and "END OF TERMS AND CONDITIONS" in t
    ref = Path("/usr/share/common-licenses/GPL-3")
    if ref.exists():
        assert t == ref.read_text()                      # an exact copy of the official text, not retyped

def test_every_source_file_carries_the_notice():
    files = sources(); assert len(files) > 35
    missing = []
    for f in files:
        head = f.read_text(errors="replace")[:700]
        if "SPDX-License-Identifier: GPL-3.0-or-later" not in head or f"Copyright (C) 2026 {HOLDER}" not in head or "WITHOUT ANY WARRANTY" not in head:
            missing.append(str(f.relative_to(ROOT)))
    assert missing == []

def test_no_file_claims_a_different_license():
    for f in sources():
        ids = re.findall(r"(?m)^\s*(?:#|//|/\*)\s*SPDX-License-Identifier: (\S+)", f.read_text(errors="replace"))  # real header comments only
        assert set(ids) <= {"GPL-3.0-or-later"}, f

def test_shebang_stays_on_the_first_line():
    for f in sources():
        t = f.read_text(errors="replace")
        if "#!" in t[:200]:
            assert t.startswith("#!"), f           # inserting the notice must never push the shebang down

def test_font_license_ships_with_the_font():
    d = ROOT / "frontend/static/fonts"
    t = (d / "OFL.txt").read_text()
    assert (d / "cutive-mono.woff2").exists()
    assert t.startswith("Copyright 2012 The Cutive Project Authors") and "SIL Open Font License, Version 1.1" in t
    for clause in ("PERMISSION & CONDITIONS", "TERMINATION", "DISCLAIMER", "5) The Font Software, modified or unmodified"):
        assert clause in t

def test_readme_states_the_license():
    r = (ROOT / "README.md").read_text()
    assert "## License" in r and "GPL-3.0-or-later" in r and f"Copyright (C) 2026 {HOLDER}" in r and "OFL.txt" in r

@pytest.mark.skipif(not shutil.which("dpkg-deb"), reason="dpkg-deb not installed")
def test_debian_copyright_names_both_licenses(tmp_path):
    out = tmp_path / "o"
    assert subprocess.run(["bash", str(ROOT / "scripts/build_deb.sh"), str(out)], capture_output=True).returncode == 0
    deb = next(out.glob("*.deb"))
    c = subprocess.run(["bash", "-c", f"dpkg-deb --fsys-tarfile '{deb}' | tar -xO ./usr/share/doc/anonyhost/copyright"], capture_output=True, text=True).stdout
    assert f"Copyright: 2026 {HOLDER}" in c and "License: GPL-3+" in c and "/usr/share/common-licenses/GPL-3" in c
    assert "License: OFL-1.1" in c and "SIL OPEN FONT LICENSE Version 1.1" in c and "THE FONT SOFTWARE IS PROVIDED" in c
    assert "@OFL_TEXT@" not in c and "All-rights-reserved" not in c and "No open-source license" not in c
    files = subprocess.run(["dpkg-deb", "-c", str(deb)], capture_output=True, text=True).stdout
    assert "frontend/static/fonts/OFL.txt" in files           # the font's license is installed next to the font
