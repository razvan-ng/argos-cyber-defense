"""Pestanya d'Auditoria de Xarxa: escaneig amb Nmap per modalitats i traçat de ruta.

Les quatre modalitats (descobriment d'hosts, ports oberts, serveis i versions, i vulnerabilitats amb
els scripts NSE) són les de l'script escaneig.py de Mouhammed Oualy, a través del mòdul comú
core/nmap_modes.py. Els resultats passen a la sessió d'auditoria, de manera que el Tauler, la
pestanya Vulnerabilitats, els Informes i els Expedients els fan servir com la resta.
"""
import threading
from tkinter import messagebox, ttk

import customtkinter as ctk

from core.nmap_modes import (
    ALL_PORTS, MODES, NmapModeError, library_available, normalize_ports, scan, summary_lines, validate_target,
)
from core.traceroute_tool import TracerouteRunner
from gui.theme import COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_PRIMARY_DARK, COLOR_SUCCESS
from gui.widgets.log_console import LogConsole

PORT_MODE_QUICK = "Ports habituals (ràpid)"
PORT_MODE_FULL = "Tots els ports (-p-, lent)"
PORT_MODE_CUSTOM = "Ports personalitzats"
MODE_LABELS = [f"{number}. {label}" for number, label in MODES.items()]


class NetworkTab(ctk.CTkFrame):
    def __init__(self, master, app_state, on_hosts_changed=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.on_hosts_changed = on_hosts_changed
        self.tracer = TracerouteRunner()
        self._build_ui()

    def _build_ui(self):
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(controls, text="Objectiu (IP / rang / subxarxa CIDR):", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, padx=8, pady=8, sticky="w"
        )
        self.target_entry = ctk.CTkEntry(controls, width=200, placeholder_text="ex. 192.168.1.0/24")
        self.target_entry.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        self.target_entry.bind("<Return>", lambda _e: self._run_scan())

        ctk.CTkLabel(controls, text="Modalitat:", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=2, padx=(16, 4), pady=8, sticky="w"
        )
        self.mode_var = ctk.StringVar(value=MODE_LABELS[0])
        ctk.CTkOptionMenu(controls, values=MODE_LABELS, variable=self.mode_var, width=330, dynamic_resizing=False,
                          command=lambda _v: self._on_mode_changed()).grid(row=0, column=3, padx=4, pady=8, sticky="w")

        self.scan_btn = ctk.CTkButton(controls, text="Escaneja", width=110, command=self._run_scan,
                                      fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.scan_btn.grid(row=0, column=4, padx=8, pady=8)
        self.trace_btn = ctk.CTkButton(controls, text="Traçat de Ruta", width=120, command=self._run_traceroute)
        self.trace_btn.grid(row=0, column=5, padx=(0, 8), pady=8)

        ctk.CTkLabel(controls, text="Ports:").grid(row=1, column=0, padx=8, pady=(0, 8), sticky="w")
        self.port_mode_var = ctk.StringVar(value=PORT_MODE_QUICK)
        self.port_mode_menu = ctk.CTkOptionMenu(
            controls, values=[PORT_MODE_QUICK, PORT_MODE_FULL, PORT_MODE_CUSTOM],
            variable=self.port_mode_var, command=self._on_port_mode_changed, width=200,
        )
        self.port_mode_menu.grid(row=1, column=1, padx=8, pady=(0, 8), sticky="w")
        self.custom_ports_entry = ctk.CTkEntry(controls, width=200, placeholder_text="ex. 22,80,443,8000-8100")
        self.custom_ports_entry.grid(row=1, column=3, padx=4, pady=(0, 8), sticky="w")
        self.custom_ports_entry.configure(state="disabled")

        self.udp_var = ctk.BooleanVar(value=False)
        self.udp_check = ctk.CTkCheckBox(controls, text="Incloure UDP (-sU, lent)", variable=self.udp_var)
        self.udp_check.grid(row=2, column=1, padx=8, pady=(0, 8), sticky="w")
        self.os_detect_var = ctk.BooleanVar(value=False)
        self.os_check = ctk.CTkCheckBox(controls, text="Detecció de SO (-O)", variable=self.os_detect_var)
        self.os_check.grid(row=2, column=3, padx=4, pady=(0, 8), sticky="w")
        self.sudo_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Usar sudo (cal per a -O i -sU)", variable=self.sudo_var).grid(
            row=2, column=4, columnspan=2, padx=8, pady=(0, 8), sticky="w"
        )

        self.progress = ctk.CTkProgressBar(self, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)

        # Amb wraplength el text llarg salta de línia en lloc d'eixamplar tota la finestra
        self.status_label = ctk.CTkLabel(self, text="Preparat.", anchor="w", justify="left", wraplength=1100)
        self.status_label.pack(side="bottom", fill="x", padx=12, pady=(0, 8))

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=6)
        body.grid_columnconfigure(0, weight=1)
        body.grid_rowconfigure(0, weight=2)
        body.grid_rowconfigure(1, weight=1)

        tree_frame = ctk.CTkFrame(body)
        tree_frame.grid(row=0, column=0, sticky="nsew")
        hint = ctk.CTkLabel(
            tree_frame, text="Consell: fes doble clic sobre un equip per copiar la seva IP al camp d'objectiu.",
            text_color="#5B6472", anchor="w",
        )
        hint.pack(side="bottom", fill="x", padx=8, pady=(0, 4))

        columns = ("ip", "hostname", "mac", "os", "services", "vulns")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=8)
        headings = {"ip": "IP", "hostname": "Nom d'Host", "mac": "MAC", "os": "Sistema Operatiu",
                    "services": "Serveis Oberts", "vulns": "Vulnerab."}
        widths = {"ip": 120, "hostname": 140, "mac": 130, "os": 140, "services": 420, "vulns": 80}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], stretch=col == "services")
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", self._on_row_double_click)

        self.log_console = LogConsole(body)
        self.log_console.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        if not library_available():
            self.scan_btn.configure(state="disabled")
            self._set_status("Falta la llibreria python-nmap. Instal·leu-la amb ./install_dependencies.sh o amb "
                             "«venv/bin/pip install python-nmap» i reinicieu SentinelX.", COLOR_DANGER)
        self._on_mode_changed()

    # ------------------------------------------------------------------ #
    def _mode(self):
        return int(self.mode_var.get().split(".", 1)[0])

    def _on_mode_changed(self):
        """La modalitat 1 no escaneja ports: s'hi desactiven les opcions de ports."""
        state = "disabled" if self._mode() == 1 else "normal"
        for widget in (self.port_mode_menu, self.udp_check, self.os_check):
            widget.configure(state=state)
        self._on_port_mode_changed(None)

    def _on_port_mode_changed(self, _value):
        custom = self.port_mode_var.get() == PORT_MODE_CUSTOM and self._mode() != 1
        self.custom_ports_entry.configure(state="normal" if custom else "disabled")

    def _on_row_double_click(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        if values:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, values[0])

    def _set_status(self, text, color=None):
        self.status_label.configure(text=text, text_color=color or COLOR_PRIMARY_DARK)

    def _set_running(self, running, message=""):
        state = "disabled" if running else "normal"
        for btn in (self.scan_btn, self.trace_btn):
            btn.configure(state=state)
        if running:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self._set_status(message or "Execució en curs...")
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(0)

    def _log(self, message):
        self.after(0, lambda: self.log_console.log(message))

    def _ports(self):
        mode = self.port_mode_var.get()
        if mode == PORT_MODE_FULL:
            return ALL_PORTS
        if mode == PORT_MODE_CUSTOM:
            ports = self.custom_ports_entry.get().strip()
            if not ports:
                raise NmapModeError("Especifica els ports a escanejar (ex. 22,80,443).")
            return ports
        return ""

    # ------------------------------------------------------------------ #
    # Escaneig per modalitats (core/nmap_modes.py)
    # ------------------------------------------------------------------ #
    def _run_scan(self):
        mode = self._mode()
        try:
            target = validate_target(self.target_entry.get())
            ports = normalize_ports(self._ports()) if mode != 1 else ""
        except NmapModeError as exc:
            self._set_status(str(exc), COLOR_DANGER)
            return
        udp = self.udp_var.get() and mode != 1
        os_detect = self.os_detect_var.get() and mode != 1

        if self.app_state.safe_mode and (mode == 4 or ports == ALL_PORTS or udp):
            motius = []
            if mode == 4:
                motius.append("executar els scripts de vulnerabilitats de nmap, que interactuen amb els serveis")
            if ports == ALL_PORTS:
                motius.append("escanejar TOTS els ports")
            if udp:
                motius.append("fer un escaneig UDP")
            if not messagebox.askyesno(
                "Confirmació requerida (Mode Segur)",
                f"Estàs a punt de {' i '.join(motius)} sobre {target}, una operació més lenta i intrusiva. "
                "Fes-ho només si tens autorització per auditar-lo. Amb el Mode Segur activat (pestanya Tauler) "
                "cal confirmar-ho explícitament. Vols continuar?",
            ):
                return

        self.app_state.session.target = target
        self.log_console.clear()
        self._log(f"Modalitat {MODES[mode].lower()}: {target}" + (f", ports {ports}" if ports else ""))
        self._set_running(True, f"Escanejant {target} ({MODES[mode].lower()})... "
                          + ("Els scripts de vulnerabilitats poden trigar uns minuts." if mode == 4 else ""))

        def worker():
            try:
                result = scan(mode, target, ports, os_detect=os_detect, udp=udp, sudo=self.sudo_var.get())
            except NmapModeError as exc:
                message = str(exc)
                self.after(0, lambda: self._scan_failed(message))
                return
            except Exception as exc:  # noqa: BLE001 - un error inesperat no ha de bloquejar la pestanya
                message = f"Error inesperat en escanejar: {exc}"
                self.after(0, lambda: self._scan_failed(message))
                return
            self.after(0, lambda: self._scan_done(mode, result))

        threading.Thread(target=worker, daemon=True).start()

    def _scan_failed(self, message):
        self._set_running(False)
        self.log_console.log(f"Error: {message}")
        self._set_status(message, COLOR_DANGER)

    def _scan_done(self, mode, result):
        self._set_running(False)
        self.log_console.log(f"[*] Comanda: {result['command']} ({result['elapsed']:.0f} s)")
        for line in result["lines"]:
            self.log_console.log(line)
        hosts = result["hosts"]
        if mode == 4:  # resum: els CVE de més puntuació de cada servei
            for line in summary_lines(hosts):
                self.log_console.log(line)
        if mode == 1:
            self.app_state.set_hosts(hosts)  # el descobriment substitueix la llista d'equips
        else:
            self.app_state.merge_scan(hosts)
        self._refresh_tree()
        if self.on_hosts_changed:
            self.on_hosts_changed()
        ports = sum(len(h.services) for h in hosts)
        summary = {1: f"{len(hosts)} host(s) actiu(s).", 2: f"{ports} port(s) obert(s) en {len(hosts)} host(s).",
                   3: f"{ports} servei(s) identificat(s) en {len(hosts)} host(s).",
                   4: f"{len(result['findings'])} vulnerabilitat(s) coneguda(es) segons els scripts NSE en {ports} "
                      "servei(s); s'han afegit a l'auditoria (Tauler, Informes i Expedients). Cal verificar-les."}
        self._set_status(f"Escaneig acabat: {summary[mode]}", COLOR_SUCCESS)

    # ------------------------------------------------------------------ #
    def _run_traceroute(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Falta objectiu", "Introdueix un host per traçar la ruta.")
            return
        self._set_running(True, f"Traçant la ruta cap a {target}...")
        self.log_console.clear()
        self._log(f"Traçant ruta cap a {target}...")

        def on_result(hops):
            self.app_state.set_traceroute(hops)

        def on_done(code):
            self.after(0, lambda: (self._set_running(False), self._set_status("Preparat.")))
            self._log(f"Traçat finalitzat (codi de sortida {code}).")

        self.tracer.trace(target, self._log, on_result, on_done)

    def sync_with_session(self):
        """Torna a mostrar la sessió actual (p. ex. després d'obrir un expedient del portal)."""
        target = self.app_state.session.target
        if target and self.target_entry.get().strip() != target:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, target)
        self._refresh_tree()

    def _refresh_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for host in self.app_state.session.hosts:
            services_str = ", ".join(
                f"{s.port}/{s.protocol} {s.service_name}" + (f" ({s.product} {s.version})".replace(" )", ")")
                                                             if s.product else "")
                for s in host.services
            ) or "-"
            vulns = sum(len(s.vulnerabilities) for s in host.services)
            self.tree.insert(
                "", "end",
                values=(host.ip, host.hostname or "-", host.mac or "-", host.os_guess or "Desconegut", services_str,
                        vulns or "-"),
            )
