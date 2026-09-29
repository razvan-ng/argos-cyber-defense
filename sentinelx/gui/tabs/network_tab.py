"""Pestanya d'Auditoria de Xarxa Avançada: descobriment, escaneig i traçat."""
from tkinter import messagebox, ttk

import customtkinter as ctk

from core.network_scanner import NetworkScanner
from core.traceroute_tool import TracerouteRunner
from gui.widgets.log_console import LogConsole

PORT_MODE_QUICK = "Ports habituals (ràpid)"
PORT_MODE_FULL = "Tots els ports (-p-, lent)"
PORT_MODE_CUSTOM = "Ports personalitzats"


class NetworkTab(ctk.CTkFrame):
    def __init__(self, master, app_state, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.scanner = NetworkScanner()
        self.tracer = TracerouteRunner()
        self._build_ui()

    def _build_ui(self):
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(controls, text="Objectiu (IP / Subxarxa CIDR):", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, padx=8, pady=8, sticky="w"
        )
        self.target_entry = ctk.CTkEntry(controls, width=200, placeholder_text="ex. 192.168.1.0/24")
        self.target_entry.grid(row=0, column=1, padx=8, pady=8)

        self.sweep_btn = ctk.CTkButton(controls, text="Descobriment d'Equips (Ping Sweep)", command=self._run_sweep)
        self.sweep_btn.grid(row=0, column=2, padx=8, pady=8)

        self.scan_btn = ctk.CTkButton(controls, text="Escaneig de Ports i Serveis", command=self._run_port_scan)
        self.scan_btn.grid(row=0, column=3, padx=8, pady=8)

        self.trace_btn = ctk.CTkButton(controls, text="Traçat de Ruta", command=self._run_traceroute)
        self.trace_btn.grid(row=0, column=4, padx=8, pady=8)

        ctk.CTkLabel(controls, text="Abast de l'escaneig:").grid(row=1, column=0, padx=8, pady=(0, 8), sticky="w")
        self.port_mode_var = ctk.StringVar(value=PORT_MODE_QUICK)
        self.port_mode_menu = ctk.CTkOptionMenu(
            controls, values=[PORT_MODE_QUICK, PORT_MODE_FULL, PORT_MODE_CUSTOM],
            variable=self.port_mode_var, command=self._on_port_mode_changed, width=190,
        )
        self.port_mode_menu.grid(row=1, column=1, padx=8, pady=(0, 8), sticky="w")

        self.custom_ports_entry = ctk.CTkEntry(controls, width=140, placeholder_text="ex. 22,80,443,8000-8100")
        self.custom_ports_entry.grid(row=1, column=2, padx=8, pady=(0, 8), sticky="w")
        self.custom_ports_entry.configure(state="disabled")

        self.udp_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Incloure escaneig UDP (-sU, més lent)", variable=self.udp_var).grid(
            row=1, column=3, padx=8, pady=(0, 8), sticky="w"
        )

        self.os_detect_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Detecció de Sistema Operatiu (-O)", variable=self.os_detect_var).grid(
            row=2, column=1, padx=8, pady=(0, 8), sticky="w"
        )
        self.sudo_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(controls, text="Usar sudo (requerit per a -O i -sU)", variable=self.sudo_var).grid(
            row=2, column=2, columnspan=2, padx=8, pady=(0, 8), sticky="w"
        )

        self.progress = ctk.CTkProgressBar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)

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

        columns = ("ip", "hostname", "mac", "os", "services")
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=10)
        headings = {"ip": "IP", "hostname": "Nom d'Host", "mac": "MAC", "os": "Sistema Operatiu", "services": "Serveis Oberts"}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=150)
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", self._on_row_double_click)

        self.log_console = LogConsole(body)
        self.log_console.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        self.status_label = ctk.CTkLabel(self, text="Preparat.", anchor="w")
        self.status_label.pack(fill="x", padx=12, pady=(0, 8))

    def _on_port_mode_changed(self, _value):
        if self.port_mode_var.get() == PORT_MODE_CUSTOM:
            self.custom_ports_entry.configure(state="normal")
        else:
            self.custom_ports_entry.configure(state="disabled")

    def _on_row_double_click(self, _event):
        selection = self.tree.selection()
        if not selection:
            return
        values = self.tree.item(selection[0], "values")
        if values:
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, values[0])

    def _set_running(self, running):
        state = "disabled" if running else "normal"
        for btn in (self.sweep_btn, self.scan_btn, self.trace_btn):
            btn.configure(state=state)
        if running:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)
        self.status_label.configure(text="Execució en curs..." if running else "Preparat.")

    def _log(self, message):
        self.after(0, lambda: self.log_console.log(message))

    def _run_sweep(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Falta objectiu", "Introdueix una IP o subxarxa (ex. 192.168.1.0/24).")
            return
        self.app_state.session.target = target
        self._set_running(True)
        self.log_console.clear()
        self._log(f"Iniciant descobriment d'equips a {target}...")

        def on_result(hosts):
            self.after(0, lambda: self._populate_hosts(hosts))

        def on_done(code):
            self.after(0, lambda: self._set_running(False))
            self._log(f"Descobriment finalitzat (codi de sortida {code}).")

        self.scanner.ping_sweep(target, self._log, on_result, on_done)

    def _run_port_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Falta objectiu", "Introdueix una IP o rang a escanejar.")
            return

        port_mode = self.port_mode_var.get()
        custom_ports = self.custom_ports_entry.get().strip() if port_mode == PORT_MODE_CUSTOM else ""
        if port_mode == PORT_MODE_CUSTOM and not custom_ports:
            messagebox.showwarning("Falten ports", "Especifica els ports a escanejar (ex. 22,80,443).")
            return
        full_ports = port_mode == PORT_MODE_FULL
        udp = self.udp_var.get()

        if self.app_state.safe_mode and (full_ports or udp):
            motiu = "un escaneig de TOTS els ports" if full_ports else "un escaneig UDP"
            if udp and full_ports:
                motiu = "un escaneig de tots els ports i UDP"
            if not messagebox.askyesno(
                "Confirmació requerida (Mode Segur)",
                f"Estàs a punt d'executar {motiu} sobre {target}, una operació més lenta i intrusiva. "
                "Amb el Mode Segur activat (pestanya Tauler) cal confirmar-ho explícitament. Vols continuar?",
            ):
                return

        self.app_state.session.target = target
        self._set_running(True)
        self.log_console.clear()
        self._log(f"Iniciant escaneig de ports i serveis sobre {target}...")

        def on_result(hosts):
            self.app_state.merge_hosts(hosts)
            self.after(0, self._refresh_tree)

        def on_done(code):
            self.after(0, lambda: self._set_running(False))
            self._log(f"Escaneig finalitzat (codi de sortida {code}).")

        self.scanner.port_scan(
            target, self._log, on_result, on_done,
            detect_os=self.os_detect_var.get(), use_sudo=self.sudo_var.get(),
            full_ports=full_ports, udp=udp, custom_ports=custom_ports,
        )

    def _run_traceroute(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Falta objectiu", "Introdueix un host per traçar la ruta.")
            return
        self._set_running(True)
        self.log_console.clear()
        self._log(f"Traçant ruta cap a {target}...")

        def on_result(hops):
            self.app_state.set_traceroute(hops)

        def on_done(code):
            self.after(0, lambda: self._set_running(False))
            self._log(f"Traçat finalitzat (codi de sortida {code}).")

        self.tracer.trace(target, self._log, on_result, on_done)

    def _populate_hosts(self, hosts):
        self.app_state.set_hosts(hosts)
        self._refresh_tree()

    def _refresh_tree(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for host in self.app_state.session.hosts:
            services_str = ", ".join(f"{s.port}/{s.protocol}" for s in host.services) or "-"
            self.tree.insert(
                "", "end",
                values=(host.ip, host.hostname or "-", host.mac or "-", host.os_guess or "Desconegut", services_str),
            )
