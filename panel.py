#!/usr/bin/env python3
"""AnonyHost Control Panel: start/stop/restart, status, logs and settings in a small desktop window."""
import os, queue, re, subprocess, sys, threading
from pathlib import Path
try:
    import tkinter as tk
    from tkinter import filedialog, font as tkfont, messagebox, ttk
except ImportError:
    sys.exit("The control panel needs Tk: sudo apt install python3-tk")
from backend import process_manager as pm
from backend.browser import find_tor_browser, open_in_tor_browser, open_window
from backend.control import ERR, LOGS, WARN, Control
from config.settings import load_settings, save_settings

BG, PANEL, FG, MUT, OK, BAD, WARNC, CY, LINE = "#000000", "#06120a", "#e6ffee", "#8fd3a1", "#00ff41", "#ff2a2a", "#ffb000", "#19e6ff", "#13a835"
ROOT = Path(__file__).resolve().parent

class Panel:
    def __init__(self):
        self.c, self.q, self.busy, self.stamp = Control(), queue.Queue(), set(), None
        r = self.r = tk.Tk(); r.title("AnonyHost Control Panel"); r.configure(bg=BG); r.geometry("920x740"); r.minsize(780, 620)
        fam = next((f for f in ("Cutive Mono", "DejaVu Sans Mono", "Liberation Mono") if f in tkfont.families()), "TkFixedFont")
        self.f, self.fb = (fam, 11), (fam, 11, "bold")
        try:
            icon = tk.PhotoImage(file=str(ROOT / "frontend/static/images/icon.png")); r.iconphoto(True, icon)
            self.icon, self.logo = icon, icon.subsample(4)
        except tk.TclError:
            self.logo = None
        st = ttk.Style(); st.theme_use("clam")
        st.configure("TCombobox", fieldbackground=PANEL, background=PANEL, foreground=FG, arrowcolor=OK, bordercolor=LINE, selectbackground=PANEL, selectforeground=FG)
        st.map("TCombobox", fieldbackground=[("readonly", PANEL)], foreground=[("readonly", FG)])
        self.build(); self.refresh(); self.pump(); self.logs_tick()

    def btn(self, parent, text, cmd, color=OK):
        return tk.Button(parent, text=text, command=cmd, font=self.f, bg=PANEL, fg=color, activebackground=color, activeforeground="#000",
                         relief="flat", bd=0, highlightthickness=1, highlightbackground=color, highlightcolor=color, padx=14, pady=6,
                         cursor="hand2", disabledforeground="#3d5a45")

    def entry(self, parent, var, **kw):
        return tk.Entry(parent, textvariable=var, font=self.f, bg=PANEL, fg=FG, insertbackground=OK, relief="flat",
                        highlightthickness=1, highlightbackground=LINE, **kw)

    def build(self):
        r = self.r
        head = tk.Frame(r, bg=BG); head.pack(fill="x", padx=16, pady=(14, 6))
        if self.logo:
            tk.Label(head, image=self.logo, bg=BG).pack(side="left", padx=(0, 12))
        t = tk.Frame(head, bg=BG); t.pack(side="left")
        tk.Label(t, text="AnonyHost - DarkWeb Hosting Tool", font=(self.f[0], 18, "bold"), bg=BG, fg=OK).pack(anchor="w")
        tk.Label(t, text="Host any website on the Dark Web without a public IP, domain, or rented server.", font=(self.f[0], 10), bg=BG, fg=CY).pack(anchor="w")
        self.overall = tk.Label(head, font=(self.f[0], 16, "bold"), bg=BG); self.overall.pack(side="right")
        box = tk.Frame(r, bg=PANEL, highlightthickness=1, highlightbackground=LINE); box.pack(fill="x", padx=16, pady=8)
        self.rows = {}
        for i, (key, name) in enumerate((("dash", "AnonyHost Dashboard"), ("web", "Website (Nginx)"), ("tor", "Tor / Onion service"))):
            dot = tk.Canvas(box, width=16, height=16, bg=PANEL, highlightthickness=0); oval = dot.create_oval(2, 2, 14, 14, fill="#555", outline="")
            dot.grid(row=i, column=0, padx=(14, 8), pady=10)
            tk.Label(box, text=name, font=self.fb, bg=PANEL, fg=FG, width=22, anchor="w").grid(row=i, column=1, sticky="w")
            det = tk.Label(box, font=self.f, bg=PANEL, fg=MUT, anchor="w"); det.grid(row=i, column=2, sticky="we", padx=8)
            b = self.btn(box, "Start", lambda k=key: self.toggle(k)); b.grid(row=i, column=3, padx=14, pady=6)
            self.rows[key] = (dot, oval, det, b)
        box.columnconfigure(2, weight=1)
        o = tk.Frame(r, bg=BG); o.pack(fill="x", padx=16)
        tk.Label(o, text="Onion address", font=self.f, bg=BG, fg=MUT).pack(side="left")
        self.onion = tk.StringVar(value="not created yet")
        tk.Entry(o, textvariable=self.onion, state="readonly", font=self.f, readonlybackground=PANEL, fg=CY, relief="flat",
                 highlightthickness=1, highlightbackground=LINE).pack(side="left", fill="x", expand=True, padx=8, ipady=4)
        self.btn(o, "Copy", self.copy_onion).pack(side="left", padx=(0, 6)); self.btn(o, "Open in Tor Browser", self.open_tb, CY).pack(side="left")
        bar = tk.Frame(r, bg=BG); bar.pack(fill="x", padx=16, pady=10)
        for text, cmd, col in (("Start all", self.start_all, OK), ("Stop all", self.stop_all, BAD), ("Restart all", self.restart_all, WARNC),
                               ("Open dashboard", self.open_dash, CY), ("Settings", self.settings, MUT),
                               ("Reset account", self.reset_account, MUT)):
            self.btn(bar, text, cmd, col).pack(side="left", padx=(0, 8))
        lf = tk.Frame(r, bg=BG); lf.pack(fill="both", expand=True, padx=16)
        top = tk.Frame(lf, bg=BG); top.pack(fill="x")
        tk.Label(top, text="Logs", font=self.fb, bg=BG, fg=OK).pack(side="left")
        self.which = tk.StringVar(value=list(LOGS)[0])
        ttk.Combobox(top, textvariable=self.which, values=list(LOGS), state="readonly", width=14).pack(side="left", padx=8)
        self.needle = tk.StringVar(); self.entry(top, self.needle).pack(side="left", fill="x", expand=True, padx=8, ipady=3)
        self.errs = tk.BooleanVar()
        tk.Checkbutton(top, text="Errors only", variable=self.errs, font=self.f, bg=BG, fg=FG, selectcolor=PANEL,
                       activebackground=BG, activeforeground=OK).pack(side="left")
        tw = tk.Frame(lf, bg=LINE); tw.pack(fill="both", expand=True, pady=(6, 0))
        self.txt = tk.Text(tw, font=(self.f[0], 10), bg="#020a04", fg=FG, relief="flat", wrap="none", state="disabled", height=10)
        sb = tk.Scrollbar(tw, command=self.txt.yview); self.txt.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y"); self.txt.pack(fill="both", expand=True)
        self.txt.tag_configure("err", foreground=BAD); self.txt.tag_configure("warn", foreground=WARNC); self.txt.tag_configure("mut", foreground=MUT)
        tk.Label(r, text="Closing this window does not stop your website.   Author: www.tca.ac.tz", font=(self.f[0], 9), bg=BG, fg=MUT).pack(pady=6)

    # ---- status ----
    def update_view(self):
        s = self.s = self.c.status(); lock = "all" in self.busy
        def row(k, on, detail, color):
            dot, oval, det, b = self.rows[k]; col = BAD if on else OK
            dot.itemconfigure(oval, fill=color if on else "#555"); det.configure(text=detail)
            b.configure(text="Stop" if on else "Start", fg=col, highlightbackground=col, highlightcolor=col, activebackground=col,
                        state="disabled" if lock or k in self.busy else "normal")
        row("dash", s["dash"], (s["dash_url"] or "running") if s["dash"] else "stopped", OK)
        row("web", s["web"], f"127.0.0.1:{s['port']}" if s["web"] else ("stopped" if s["site"] else "stopped - no website deployed yet"), OK)
        boot = s["boot"]
        row("tor", s["tor"], ("onion service online" if boot >= 100 else f"bootstrapping {boot}%") if s["tor"] else "stopped", OK if boot >= 100 else WARNC)
        n = sum((s["dash"], s["web"], s["tor"]))
        self.overall.configure(text="RUNNING" if n == 3 else "STOPPED" if n == 0 else "PARTIAL", fg=OK if n == 3 else BAD if n == 0 else WARNC)
        self.onion.set(s["onion"] or "not created yet")

    def refresh(self):
        self.update_view(); self.r.after(1500, self.refresh)

    def pump(self):  # run UI work queued by worker threads
        try:
            while True:
                self.q.get_nowait()()
        except queue.Empty:
            pass
        self.r.after(100, self.pump)

    def run(self, key, fn):
        if key in self.busy or "all" in self.busy:
            return
        self.busy.add(key); self.update_view()
        def work():
            err = None
            try:
                fn()
            except (pm.ServiceError, OSError, subprocess.SubprocessError) as e:
                err = str(e)
            def fin():
                self.busy.discard(key); self.update_view()
                if err:
                    messagebox.showerror("AnonyHost", err)
            self.q.put(fin)
        threading.Thread(target=work, daemon=True).start()

    # ---- actions ----
    def ensure_port(self):
        """True if the hosting port is usable; otherwise ask the user how to fix it."""
        c = self.c
        if c.web.running() or pm.port_free(c.port):
            return True
        o, alt = pm.port_owner(c.port), next((p for p in range(c.port + 1, c.port + 50) if pm.port_free(p)), None)
        what = f"{o['name']} (PID {o['pid']})" if o else "another program"
        a = messagebox.askyesnocancel("Port in use", f"Port {c.port} is already used by {what}.\n\nYes: stop that program and continue\n"
                                      f"No: use port {alt} instead\nCancel: do nothing")
        if a is None:
            return False
        try:
            if a:
                if not o or o["pid"] == os.getpid():
                    raise pm.ServiceError("I can't safely identify that program. Choose No to use another port.")
                pm.stop_listener(o["pid"], c.port)
            elif alt:
                c.set_port(alt)
            else:
                raise pm.ServiceError("No free port found nearby.")
        except pm.ServiceError as e:
            messagebox.showerror("AnonyHost", str(e)); return False
        return True

    def toggle(self, k):
        on, c = self.s[k], self.c
        if k == "dash":
            self.run("dash", c.stop_dashboard if on else c.start_dashboard)
        elif k == "web":
            if on: self.run("web", c.web.stop)
            elif self.ensure_port(): self.run("web", c.start_web)
        else:
            self.run("tor", c.tor.stop if on else c.start_tor)

    def _start(self):
        c = self.c
        c.start_dashboard()
        if load_settings(c.base).get("panel_open_dashboard", True) and c.dash_url():
            open_window(c.dash_url(), c.base / "window-profile")
        if c.has_site():
            c.start_web(); c.start_tor()
        else:
            self.q.put(lambda: messagebox.showinfo("AnonyHost", "The dashboard is running. Deploy a website there to start hosting."))

    def _stop(self):
        self.c.stop_hosting(); self.c.stop_dashboard()

    def start_all(self):
        if self.c.has_site() and not self.ensure_port(): return
        self.run("all", self._start)

    def stop_all(self):
        self.run("all", self._stop)

    def restart_all(self):
        if self.c.has_site() and not self.ensure_port(): return
        self.run("all", lambda: (self._stop(), self._start()))

    def open_dash(self):
        if not self.s["dash"]:
            return messagebox.showinfo("AnonyHost", "The dashboard is not running. Press Start first.")
        open_window(self.s["dash_url"], self.c.base / "window-profile")

    def copy_onion(self):
        if self.s["onion"]:
            self.r.clipboard_clear(); self.r.clipboard_append(self.s["onion"])

    def open_tb(self):
        if not self.s["onion"]:
            return messagebox.showinfo("AnonyHost", "No onion address yet. Start hosting first.")
        exe = find_tor_browser(load_settings(self.c.base).get("tor_browser") or None)
        if not exe:
            return messagebox.showinfo("AnonyHost", "Tor Browser was not found.\nInstall it: sudo apt install torbrowser-launcher\n"
                                       "or from torproject.org/download, then set its path in Settings.")
        open_in_tor_browser(exe, f"http://{self.s['onion']}/")

    def reset_account(self):
        if messagebox.askyesno("Reset account", "Remove the administrator account?\n\nYour website and onion address are kept. "
                               "You will create a new account the next time you open the dashboard."):
            self.c.reset_account(); messagebox.showinfo("AnonyHost", "Done. Open the dashboard to create a new account.")

    def settings(self):
        c = self.c; cfg = load_settings(c.base)
        d = tk.Toplevel(self.r); d.title("Settings"); d.configure(bg=BG); d.transient(self.r); d.grab_set()
        port, tb = tk.StringVar(value=str(c.port)), tk.StringVar(value=cfg.get("tor_browser", ""))
        auto, opn = tk.BooleanVar(value=bool(cfg.get("autostart"))), tk.BooleanVar(value=cfg.get("panel_open_dashboard", True))
        tk.Label(d, text="Hosting port", font=self.f, bg=BG, fg=FG).grid(row=0, column=0, sticky="w", padx=14, pady=8)
        self.entry(d, port, width=34).grid(row=0, column=1, sticky="we", padx=6, ipady=3)
        tk.Label(d, text="Tor Browser path", font=self.f, bg=BG, fg=FG).grid(row=1, column=0, sticky="w", padx=14, pady=8)
        self.entry(d, tb, width=34).grid(row=1, column=1, sticky="we", padx=6, ipady=3)
        self.btn(d, "Browse", lambda: tb.set(filedialog.askopenfilename(parent=d) or tb.get()), MUT).grid(row=1, column=2, padx=8)
        for i, (t, v) in enumerate((("Start hosting automatically when AnonyHost starts", auto), ("Open the dashboard window on 'Start all'", opn)), 2):
            tk.Checkbutton(d, text=t, variable=v, font=self.f, bg=BG, fg=FG, selectcolor=PANEL, activebackground=BG,
                           activeforeground=OK).grid(row=i, column=0, columnspan=3, sticky="w", padx=12)
        def save():
            try:
                p = int(port.get()); assert 1024 <= p <= 65535
            except (ValueError, AssertionError):
                return messagebox.showerror("Settings", "Port must be a number from 1024 to 65535.", parent=d)
            if p != c.port and (c.web.running() or c.tor.running()):
                return messagebox.showerror("Settings", "Stop hosting before changing the port.", parent=d)
            t = tb.get().strip()
            if t and not (Path(t).is_file() and os.access(t, os.X_OK)):
                return messagebox.showerror("Settings", "Tor Browser path is not an executable file.", parent=d)
            save_settings(c.base, port=p, tor_browser=t, autostart=auto.get(), panel_open_dashboard=opn.get())
            c.sync_settings(); d.destroy()
        row = tk.Frame(d, bg=BG); row.grid(row=4, column=0, columnspan=3, pady=12)
        self.btn(row, "Save", save).pack(side="left", padx=6); self.btn(row, "Cancel", d.destroy, MUT).pack(side="left")

    # ---- logs ----
    def logs_tick(self):
        c, name = self.c, self.which.get()
        stamp = (name, c.log_stamp(name), self.needle.get(), self.errs.get())
        if stamp != self.stamp:
            self.stamp = stamp
            atend = self.txt.yview()[1] > 0.98
            self.txt.configure(state="normal"); self.txt.delete("1.0", "end")
            lines = c.read_log(name, self.needle.get(), self.errs.get())
            if not lines:
                self.txt.insert("end", "(no entries)", "mut")
            for l in lines:
                self.txt.insert("end", l + "\n", "warn" if WARN.search(l) else "err" if ERR.search(l) else "")
            self.txt.configure(state="disabled")
            if atend: self.txt.see("end")
        self.r.after(1000, self.logs_tick)

if __name__ == "__main__":
    Panel().r.mainloop()
