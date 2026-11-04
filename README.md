# AnonyHost - DarkWeb Hosting Tool
Host a website as a Tor v3 onion service from your own PC: no public IP, domain or port forwarding.

**Status:** Ubuntu/Debian only. Windows, dynamic runtimes (Node/PHP/Flask/Django), file manager, log viewer and key backup are NOT implemented yet.

## Linux
- Install: `./scripts/install_linux.sh` (asks before using sudo; installs tor + nginx)
- Control panel (like XAMPP's): Applications menu -> AnonyHost Control Panel, or `anonyhost-panel`. Start/stop/restart the dashboard, Nginx and Tor, live status, logs, settings. Closing the panel does not stop hosting.
- Dashboard only: Applications menu -> AnonyHost Dashboard, or `anonyhost`, or `anonyhost` in a terminal. The terminal returns immediately and stays silent (log: `~/.local/share/anonyhost/logs/launcher.log`); the dashboard opens in its own window if Chromium, Chrome, Brave or Edge is installed (`sudo apt install chromium`), otherwise in your default browser. Use `--foreground` to keep it attached for debugging. First launch asks you to create an admin account.
- Stop dashboard + website: `anonyhost --stop-all` (`--stop` keeps the website running), or "Quit AnonyHost" in the dashboard.
- Forgot password: click "Forgot password?" on the login page and enter the recovery key shown when you created the account (Settings can make a new one). Lost the key too: Control Panel -> Reset account (or `anonyhost --reset-password`). Your website and onion address are kept.
- Reset: Settings -> Reset (restore defaults, or factory reset), or `anonyhost --factory-reset` (add `--delete-keys` to also delete the onion address). Backups are never deleted.
- Uninstall: `~/.local/share/anonyhost-app/scripts/uninstall_linux.sh` (asks before deleting data).
- Data (website, onion keys, logs): `~/.local/share/anonyhost`. Losing `onion-service/` loses your .onion address.

## Limits and security notes
- Website limit: 1 GB (upload and extracted). ZIPs are validated (no path traversal/symlinks), nothing uploaded is executed.
- The dashboard listens on 127.0.0.1 only and is never exposed through the onion service. Tor does not guarantee anonymity against application-level leaks in your site.
