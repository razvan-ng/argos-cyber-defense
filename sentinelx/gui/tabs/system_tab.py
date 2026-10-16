"""Pestanya d'Auditoria de Sistema Local / Host."""
import threading
from tkinter import ttk

import customtkinter as ctk

from core.system_audit import SystemAuditor
from gui.theme import SEVERITY_COLORS
from gui.widgets.log_console import LogConsole


class SystemTab(ctk.CTkFrame):
    def __init__(self, master, app_state, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.auditor = SystemAuditor()
        self._build_ui()

    def _build_ui(self):
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=12, pady=(12, 6))
        ctk.CTkLabel(top, text="Auditoria de Sistema Local", font=("Segoe UI", 14, "bold")).pack(
            side="left", padx=8, pady=8
        )
        ctk.CTkButton(top, text="Actualitzar Dades", command=self._refresh).pack(side="left", padx=8)
        ctk.CTkButton(top, text="Comprovar Tallafocs (ufw)", command=self._check_firewall).pack(side="left", padx=8)

        self.subtabs = ctk.CTkTabview(self)
        self.subtabs.pack(fill="both", expand=True, padx=12, pady=6)
        tab_iface = self.subtabs.add("Interfícies")
        tab_conn = self.subtabs.add("Connexions")
        tab_proc = self.subtabs.add("Processos")
        tab_users = self.subtabs.add("Usuaris")
        tab_fw = self.subtabs.add("Tallafocs")
        tab_hardening = self.subtabs.add("Reforçament")

        self.iface_tree = self._make_tree(
            tab_iface, ("interface", "address", "netmask", "status"),
            {"interface": "Interfície", "address": "Adreça", "netmask": "Màscara", "status": "Estat"},
        )
        self.conn_tree = self._make_tree(
            tab_conn, ("laddr", "raddr", "status", "pid"),
            {"laddr": "Local", "raddr": "Remot", "status": "Estat", "pid": "PID"},
        )
        self.proc_tree = self._make_tree(
            tab_proc, ("pid", "name", "user", "cpu", "mem"),
            {"pid": "PID", "name": "Nom", "user": "Usuari", "cpu": "CPU %", "mem": "Mem %"},
        )
        self.users_tree = self._make_tree(
            tab_users, ("name", "terminal", "host"),
            {"name": "Usuari", "terminal": "Terminal", "host": "Origen"},
        )

        self.fw_console = LogConsole(tab_fw)
        self.fw_console.pack(fill="both", expand=True, padx=4, pady=4)

        self._build_hardening_tab(tab_hardening)

        self._refresh()

    @staticmethod
    def _make_tree(parent, columns, headings):
        tree = ttk.Treeview(parent, columns=columns, show="headings", height=12)
        for col in columns:
            tree.heading(col, text=headings[col])
            tree.column(col, width=130)
        tree.pack(fill="both", expand=True, padx=4, pady=4)
        return tree

    def _refresh(self):
        for tree in (self.iface_tree, self.conn_tree, self.proc_tree, self.users_tree):
            for row in tree.get_children():
                tree.delete(row)

        for iface in self.auditor.get_interfaces():
            for addr in iface["addresses"]:
                self.iface_tree.insert(
                    "", "end",
                    values=(iface["name"], addr["address"], addr["netmask"] or "-", "Activa" if iface["is_up"] else "Inactiva"),
                )

        for conn in self.auditor.get_connections():
            self.conn_tree.insert("", "end", values=(conn["laddr"] or "-", conn["raddr"] or "-", conn["status"], conn["pid"] or "-"))

        for proc in self.auditor.get_processes():
            self.proc_tree.insert(
                "", "end",
                values=(
                    proc.get("pid"), proc.get("name") or "-", proc.get("username") or "-",
                    round(proc.get("cpu_percent") or 0, 1), round(proc.get("memory_percent") or 0, 1),
                ),
            )

        for user in self.auditor.get_users():
            self.users_tree.insert("", "end", values=(user["name"], user["terminal"] or "-", user["host"] or "-"))

        self.app_state.set_local_system_info(self.auditor.get_platform_summary())

    def _check_firewall(self):
        self.fw_console.clear()
        self.fw_console.log("Comprovant l'estat del tallafocs (pot requerir contrasenya sudo)...")

        def on_output(line):
            self.after(0, lambda: self.fw_console.log(line))

        def on_done(code):
            self.after(0, lambda: self.fw_console.log(f"Comprovació finalitzada (codi de sortida {code})."))

        self.auditor.check_firewall_status(on_output, on_done)

    # ------------------------------------------------------------------ #
    # Reforçament (hardening)
    # ------------------------------------------------------------------ #
    def _build_hardening_tab(self, parent):
        info = ctk.CTkLabel(
            parent,
            text=(
                "Comprova actualitzacions pendents, binaris amb bit SUID/SGID, comptes addicionals "
                "amb privilegis de root i comptes sense contrasenya. Algunes comprovacions requereixen "
                "privilegis d'administrador per ser completes."
            ),
            wraplength=900, justify="left", anchor="w",
        )
        info.pack(fill="x", padx=8, pady=(8, 4))

        self.hardening_btn = ctk.CTkButton(
            parent, text="Executar Auditoria de Reforçament", command=self._run_hardening_audit
        )
        self.hardening_btn.pack(anchor="w", padx=8, pady=(0, 8))

        self.hardening_progress = ctk.CTkProgressBar(parent, mode="indeterminate")
        self.hardening_progress.pack(fill="x", padx=8, pady=(0, 8))
        self.hardening_progress.set(0)

        columns = ("severity", "description", "recommendation")
        self.hardening_tree = ttk.Treeview(parent, columns=columns, show="headings", height=10)
        headings = {"severity": "Gravetat", "description": "Descripció", "recommendation": "Recomanació"}
        widths = {"severity": 90, "description": 420, "recommendation": 420}
        for col in columns:
            self.hardening_tree.heading(col, text=headings[col])
            self.hardening_tree.column(col, width=widths[col])
        self.hardening_tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        for sev, color in SEVERITY_COLORS.items():
            self.hardening_tree.tag_configure(sev, foreground=color)

    def _run_hardening_audit(self):
        self.hardening_btn.configure(state="disabled")
        self.hardening_progress.start()
        for row in self.hardening_tree.get_children():
            self.hardening_tree.delete(row)

        threading.Thread(target=self._hardening_worker, daemon=True).start()

    def _hardening_worker(self):
        findings = self.auditor.run_hardening_audit()
        self.after(0, lambda: self._display_hardening_findings(findings))

    def _display_hardening_findings(self, findings):
        self.app_state.set_hardening_findings(findings)
        for vuln in findings:
            self.hardening_tree.insert(
                "", "end",
                values=(vuln.severity.value, vuln.description, vuln.recommendation),
                tags=(vuln.severity.value,),
            )
        self.hardening_progress.stop()
        self.hardening_progress.set(0)
        self.hardening_btn.configure(state="normal")
