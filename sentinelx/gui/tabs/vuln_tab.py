"""Pestanya de Correlació de Vulnerabilitats, CVE i Explotabilitat.

Combina dos mètodes complementaris:
  - Anàlisi PASSIU: correlaciona els serveis/versions ja detectats a la
    pestanya de Xarxa amb el diccionari local de CVEs i, opcionalment, la NVD.
  - Escaneig ACTIU: executa els scripts de vulnerabilitats de nmap (NSE,
    --script vuln) directament contra un objectiu, que confirmen la troballa
    interactuant amb el servei real (molta més fiabilitat, també més lent).
"""
import threading
from tkinter import messagebox, ttk

import customtkinter as ctk

from core.network_scanner import NetworkScanner
from core.vuln_correlator import VulnerabilityCorrelator
from gui.theme import SEVERITY_COLORS
from gui.widgets.log_console import LogConsole


class VulnTab(ctk.CTkFrame):
    def __init__(self, master, app_state, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.scanner = NetworkScanner()
        self._all_rows = []
        self._build_ui()

    def _build_ui(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(top, text="Correlació de Vulnerabilitats i CVE", font=("Segoe UI", 14, "bold")).grid(
            row=0, column=0, columnspan=2, padx=8, pady=(8, 4), sticky="w"
        )
        self.online_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(top, text="Consultar NVD API (en línia)", variable=self.online_var).grid(
            row=0, column=2, padx=8, pady=(8, 4), sticky="w"
        )
        self.run_btn = ctk.CTkButton(top, text="Analitzar Serveis Detectats (Passiu)", command=self._run_analysis)
        self.run_btn.grid(row=0, column=3, padx=8, pady=(8, 4))

        ctk.CTkLabel(top, text="Objectiu per a l'escaneig actiu NSE:").grid(
            row=1, column=0, padx=8, pady=(0, 8), sticky="w"
        )
        self.nse_target_entry = ctk.CTkEntry(top, width=180, placeholder_text="ex. 192.168.1.10")
        self.nse_target_entry.grid(row=1, column=1, padx=8, pady=(0, 8), sticky="w")
        self.nse_sudo_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(top, text="Usar sudo", variable=self.nse_sudo_var).grid(
            row=1, column=2, padx=8, pady=(0, 8), sticky="w"
        )
        self.nse_btn = ctk.CTkButton(
            top, text="Escaneig Actiu NSE (nmap --script vuln)", command=self._run_nse_scan,
            fg_color="#7B0000", hover_color="#5C0000",
        )
        self.nse_btn.grid(row=1, column=3, padx=8, pady=(0, 8))

        filter_frame = ctk.CTkFrame(self, fg_color="transparent")
        filter_frame.pack(fill="x", padx=12, pady=(0, 4))
        ctk.CTkLabel(filter_frame, text="Filtrar resultats:").pack(side="left", padx=(0, 6))
        self.filter_entry = ctk.CTkEntry(filter_frame, width=280, placeholder_text="IP, servei, CVE, gravetat o text...")
        self.filter_entry.pack(side="left")
        self.filter_entry.bind("<KeyRelease>", lambda _e: self._apply_filter())
        ctk.CTkButton(filter_frame, text="Netejar filtre", width=110, command=self._clear_filter).pack(side="left", padx=8)

        self.progress = ctk.CTkProgressBar(self, mode="indeterminate")
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=12, pady=6)

        columns = ("severity", "host", "service", "cve", "exploit", "description")
        self.tree = ttk.Treeview(body, columns=columns, show="headings", height=14)
        headings = {
            "severity": "Gravetat", "host": "Equip", "service": "Servei",
            "cve": "CVE", "exploit": "Exploit", "description": "Descripció",
        }
        widths = {"severity": 90, "host": 130, "service": 190, "cve": 140, "exploit": 90, "description": 300}
        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col])
        self.tree.pack(fill="both", expand=True, padx=4, pady=(4, 0))

        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

        self.log_console = LogConsole(self, height=140)
        self.log_console.pack(fill="both", expand=False, padx=12, pady=(6, 12))

    def _set_running(self, running):
        state = "disabled" if running else "normal"
        self.run_btn.configure(state=state)
        self.nse_btn.configure(state=state)
        if running:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)

    # ------------------------------------------------------------------ #
    # Anàlisi passiu (correlació per versió)
    # ------------------------------------------------------------------ #
    def _run_analysis(self):
        hosts = self.app_state.session.hosts
        if not hosts:
            messagebox.showinfo(
                "Sense dades",
                "Primer cal executar un escaneig de xarxa a la pestanya 'Auditoria de Xarxa'.",
            )
            return

        self._set_running(True)
        self.log_console.clear()
        self.log_console.log("Iniciant correlació passiva de vulnerabilitats...")
        self._all_rows.clear()
        for row in self.tree.get_children():
            self.tree.delete(row)

        threading.Thread(target=self._analyze_worker, args=(hosts, self.online_var.get()), daemon=True).start()

    def _analyze_worker(self, hosts, use_online):
        correlator = VulnerabilityCorrelator(use_online=use_online)
        total_findings = 0
        for host in hosts:
            for service in host.services:
                self.after(
                    0,
                    lambda h=host, s=service: self.log_console.log(
                        f"Analitzant {h.ip}:{s.port} ({s.product or s.service_name} {s.version})..."
                    ),
                )
                findings = correlator.correlate_service(
                    service, on_log=lambda m: self.after(0, lambda msg=m: self.log_console.log(msg))
                )
                service.vulnerabilities = findings
                total_findings += len(findings)
                for vuln in findings:
                    self.after(0, lambda h=host, s=service, v=vuln: self._insert_finding(h.ip, s, v))

        self.after(0, lambda: self.log_console.log(f"Anàlisi finalitzada. {total_findings} troballa(es) detectada(es)."))
        self.after(0, lambda: self._set_running(False))

    def _insert_finding(self, ip, service, vuln):
        service_label = f"{service.port}/{service.protocol} {service.product or service.service_name}"
        exploit_text = "SÍ ⚠" if vuln.exploit_available else "No"
        self._add_row((vuln.severity.value, ip, service_label, vuln.cve_id, exploit_text, vuln.description[:140]))

    # ------------------------------------------------------------------ #
    # Escaneig actiu (NSE --script vuln)
    # ------------------------------------------------------------------ #
    def _run_nse_scan(self):
        target = self.nse_target_entry.get().strip() or self.app_state.session.target
        if not target:
            messagebox.showwarning(
                "Falta objectiu",
                "Introdueix una IP/host, o escaneja primer un objectiu a la pestanya 'Auditoria de Xarxa'.",
            )
            return
        if not self.nse_target_entry.get().strip():
            self.nse_target_entry.insert(0, target)

        if self.app_state.safe_mode and not messagebox.askyesno(
            "Confirmació requerida (Mode Segur)",
            f"L'escaneig actiu amb scripts NSE interactua directament amb els serveis de {target} "
            "i pot trigar diversos minuts. Amb el Mode Segur activat (pestanya Tauler) cal confirmar-ho "
            "explícitament. Vols continuar?",
        ):
            return

        self._set_running(True)
        self.log_console.clear()
        self.log_console.log(
            f"Iniciant escaneig ACTIU de vulnerabilitats (nmap --script vuln) sobre {target}. "
            "Pot trigar diversos minuts segons el nombre de ports oberts..."
        )

        def on_output(line):
            self.after(0, lambda: self.log_console.log(line))

        def on_result(findings):
            self.after(0, lambda: self._handle_nse_findings(findings))

        def on_done(code):
            self.after(0, lambda: self._set_running(False))
            self.after(0, lambda: self.log_console.log(f"Escaneig NSE finalitzat (codi de sortida {code})."))

        self.scanner.vuln_scan(target, on_output, on_result, on_done, use_sudo=self.nse_sudo_var.get())

    def _handle_nse_findings(self, findings):
        if not findings:
            self.log_console.log("Els scripts NSE no han confirmat cap vulnerabilitat activa sobre aquest objectiu.")
            return
        for finding in findings:
            vuln = VulnerabilityCorrelator.vulnerability_from_nse_finding(finding)
            ip = finding["ip"]
            self.app_state.add_finding_by_ip_port(ip, finding["port"], finding["protocol"], vuln)
            service_label = f"{finding['port_label']} (NSE: {finding['script_id']})"
            self._add_row((vuln.severity.value, ip, service_label, vuln.cve_id, "No", vuln.description[:140]))
        self.log_console.log(f"S'han afegit {len(findings)} troballa(es) confirmada(es) activament per NSE.")

    # ------------------------------------------------------------------ #
    # Taula de resultats + filtre
    # ------------------------------------------------------------------ #
    def _add_row(self, values):
        self._all_rows.append(values)
        if self._matches_filter(values):
            self.tree.insert("", "end", values=values, tags=(values[0],))

    def _matches_filter(self, values):
        query = self.filter_entry.get().strip().lower()
        if not query:
            return True
        return any(query in str(v).lower() for v in values)

    def _apply_filter(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        for values in self._all_rows:
            if self._matches_filter(values):
                self.tree.insert("", "end", values=values, tags=(values[0],))

    def _clear_filter(self):
        self.filter_entry.delete(0, "end")
        self._apply_filter()
