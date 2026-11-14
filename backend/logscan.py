# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 www.tca.ac.tz (https://www.tca.ac.tz)
# AnonyHost is free software under the GNU General Public License, version 3 or (at your option) any later version.
# It comes WITHOUT ANY WARRANTY. See the LICENSE file.
"""Recognises well-known hosting problems in log text. Pure functions: text in, findings out."""
import re

# PHP extension packages (apt) by the name of a missing function, class or driver
PHP_FUNC_PKG = [(r"^(mysqli|mysql)", "php-mysql"), (r"^curl", "php-curl"), (r"^mb_", "php-mbstring"), (r"^(gd|image)", "php-gd"),
                (r"^(simplexml|dom|xml|libxml|xsl)", "php-xml"), (r"^zip", "php-zip"), (r"^sqlite", "php-sqlite3"), (r"^(pg_|pgsql)", "php-pgsql"),
                (r"^(intl|numfmt|collator|idn_)", "php-intl"), (r"^bc(add|sub|mul|div|mod|pow|sqrt|comp)", "php-bcmath")]
PHP_CLASS_PKG = {"ZipArchive": "php-zip", "DOMDocument": "php-xml", "SimpleXMLElement": "php-xml", "XMLWriter": "php-xml", "XMLReader": "php-xml",
                 "mysqli": "php-mysql", "IntlDateFormatter": "php-intl", "NumberFormatter": "php-intl", "Collator": "php-intl",
                 "Imagick": "php-imagick", "SQLite3": "php-sqlite3"}

def php_pkg_for_function(name):
    for rx, pkg in PHP_FUNC_PKG:
        if re.match(rx, name, re.I):
            return pkg
    return None

def _uniq(items):
    seen, out = set(), []
    for i in items:
        if i not in seen:
            seen.add(i); out.append(i)
    return out

def classify(source, text):
    """source: 'app' (Node.js/Python), 'php', 'nginx' or 'tor'. Returns a list of dicts:
    code, level (error|warn), title, detail, fix (a Doctor fix id or None) and optional pkgs / module."""
    hits = []
    def add(code, level, title, detail, fix=None, **kw):
        hits.append({"code": code, "level": level, "title": title, "detail": detail, "fix": fix, **kw})
    text = text or ""

    if source == "app":
        for mod in _uniq(re.findall(r"ModuleNotFoundError: No module named '([\w.]+)'", text)):
            add("py_module", "error", f"Python module '{mod}' is missing",
                "Add it to a requirements.txt in your ZIP. For well-known packages AnonyHost can install it for you.", "pip_install", module=mod)
        for mod in _uniq(re.findall(r"Cannot find module '([^']+)'", text)):
            local = mod.startswith((".", "/"))
            add("node_module", "error", f"Node.js module '{mod}' is missing",
                "A file your code requires is not in the ZIP." if local else "Its package is not installed. AnonyHost can run npm install for you (package.json must list it).",
                None if local else "npm_install", module=mod)
        if re.search(r"EADDRINUSE|Address already in use|\[Errno 98\]", text):
            add("app_port_in_use", "error", "Your app uses a fixed port that is already taken",
                "Listen on the port in the PORT environment variable instead (process.env.PORT in Node.js, os.environ['PORT'] in Python).")
        if re.search(r"DisallowedHost|Invalid HTTP_HOST header", text):
            add("host_header", "error", "Your app rejects the .onion address as a host name",
                "AnonyHost can send a local Host header instead. With DEBUG off, Django also needs the onion address in ALLOWED_HOSTS.", "host_header_local")
        m = re.findall(r"^\s*((?:Syntax|Indentation|Tab)Error: .+)$", text, re.M)
        if m:
            add("app_syntax", "error", "Your app has a syntax error", m[-1][:200])
        if re.search(r"sqlite3\.OperationalError: (unable to open database|attempt to write a readonly)", text):
            add("app_db_perm", "error", "Your app cannot open or write its SQLite database",
                "The database file or its folder is not writable. AnonyHost can repair the file permissions.", "fix_perms")
        if re.search(r"PermissionError|EACCES", text):
            add("app_permission", "warn", "Your app hit a permission error",
                "It tried to use a file or port it is not allowed to. Ports below 1024 need the PORT variable; files need to stay inside your site folder.", "fix_perms")
        if re.search(r"TemplateNotFound|ENOENT: no such file", text):
            add("app_missing_file", "error", "Your app cannot find one of its files", "Check that the file is inside the ZIP and the path is relative to your site folder.")
        if not hits:
            last = re.findall(r"^\s*((?:[\w.]+)?(?:Error|Exception)(?::| ).*)$", text, re.M)
            if last:
                add("app_error", "error", "Your app reported an error", last[-1][:240])

    elif source == "php":
        for msg, path, line in re.findall(r"PHP Parse error:\s+(.+?) in (\S+) on line (\d+)", text)[-2:]:
            add("php_parse", "error", "A PHP file has a syntax error", f"{msg} ({path.rsplit('/', 1)[-1]}, line {line})")
        for fn in _uniq(re.findall(r"Call to undefined function (\w+)\(", text)):
            pkg = php_pkg_for_function(fn)
            if pkg:
                add("php_ext", "error", f"The PHP extension for {fn}() is not installed", f"Installing {pkg} adds it.", "install", pkgs=[pkg])
            else:
                add("php_function", "error", f"PHP function {fn}() does not exist", "Check the spelling, or whether a library your code needs is missing.")
        for cls in _uniq(re.findall(r'Class "([\w\\]+)" not found', text)):
            pkg = PHP_CLASS_PKG.get(cls)
            if pkg:
                add("php_ext", "error", f"The PHP extension providing {cls} is not installed", f"Installing {pkg} adds it.", "install", pkgs=[pkg])
            else:
                add("php_class", "error", f"PHP class {cls} was not found",
                    "If your project uses Composer, include the vendor/ folder in the ZIP (run composer install first).")
        if re.search(r"could not find driver", text):
            add("php_driver", "error", "No PHP database driver is installed", "Installing php-mysql and php-sqlite3 adds the common ones.", "install", pkgs=["php-mysql", "php-sqlite3"])
        if re.search(r"SQLSTATE\[HY000\] \[2002\]|Connection refused.*(mysql|3306)|mysqli::__construct", text, re.I):
            add("php_db_conn", "error", "Your PHP code cannot reach a database server",
                "There is no database server on this computer unless you run one. SQLite needs none.")
        if re.search(r"Allowed memory size of \d+ bytes exhausted", text):
            add("php_memory", "warn", "A PHP script ran out of memory", "Reduce what the script loads at once (large files or images).")
        if re.search(r"Maximum execution time of \d+ seconds exceeded", text):
            add("php_timeout", "warn", "A PHP script ran too long", "Make the script faster or split the work.")
        if re.search(r"Permission denied", text):
            add("php_perm", "error", "PHP cannot read or write a file", "AnonyHost can repair the permissions inside your site folder.", "fix_perms")
        if not hits:
            fat = re.findall(r"PHP Fatal error:\s+(.+)", text)
            if fat:
                add("php_fatal", "error", "A PHP script stopped with a fatal error", fat[-1][:240])

    elif source == "nginx":
        if re.search(r"\(13: Permission denied\)", text):
            add("nginx_perm", "error", "Nginx cannot read some of your site files", "AnonyHost can repair the file permissions.", "fix_perms")
        if re.search(r"connect\(\) failed .*upstream|upstream prematurely closed|no live upstreams|connect\(\) to unix:.*failed", text):
            add("upstream_down", "error", "Nginx cannot reach your app", "The app or PHP-FPM stopped answering. Restarting the site usually fixes it.", "restart_site")
        if re.search(r"bind\(\) to .* failed \(98: Address already in use\)", text):
            add("nginx_bind", "error", "The hosting port is already in use", "AnonyHost can switch to a free port.", "port_free")
        if re.search(r'open\(\) "/etc/nginx/mime\.types" failed', text):
            add("nginx_mime", "error", "Nginx's mime.types file is missing", "Installing nginx-common restores it.", "install", pkgs=["nginx-common"])
        if re.search(r"client intended to send too large body", text):
            add("too_large", "warn", "A visitor tried to upload more than 64 MB", "Uploads are limited to 64 MB on dynamic sites.")
        if re.search(r"directory index of .* is forbidden", text):
            add("no_index", "warn", "A folder on your site has no index file", "Add an index.html (or index.php) to that folder.")

    elif source == "tor":
        if re.search(r"[Cc]lock skew|clock jumped|[Yy]our system clock", text):
            add("tor_clock", "error", "Your computer's clock looks wrong, so Tor cannot connect",
                "Turn on automatic time: sudo timedatectl set-ntp true (and check the date and time zone).")
        if re.search(r"Problem bootstrapping|Network is unreachable|No route to host|Could not connect to .*directory", text):
            add("tor_network", "warn", "Tor cannot reach the Tor network",
                "Check your internet connection, VPN, proxy or firewall. Restarting Tor can help after the connection is back.", "restart_tor")
        if re.search(r"Permissions on directory .* (are|is) too permissive|is not private", text):
            add("tor_perm", "error", "Tor's data folder permissions are too open", "AnonyHost can repair them.", "fix_perms")
        if re.search(r"Could not bind to .*Address already in use", text):
            add("tor_bind", "error", "Tor cannot open a port it needs", "Another Tor is probably running with the same settings. Stop it and restart.")
    for h in hits:
        h["id"] = f"{source}.{h['code']}"
        h["source"] = source
    return hits
