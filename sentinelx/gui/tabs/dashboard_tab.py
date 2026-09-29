"""Pestanya 'Tauler': resum ràpid de l'estat de l'auditoria i accés directe a les

funcions principals. Pensada com a punt d'entrada de l'aplicació perquè un
usuari nou entengui d'un cop d'ull l'estat de l'auditoria i què fer a continuació.
"""
from tkinter import ttk

import customtkinter as ctk

from core.models import Severity
from gui.theme import APP_NAME, COMPANY_NAME, SEVERITY_COLORS

GUIDE_STEPS = [
    "1. Auditoria de Xarxa — descobreix equips actius i escaneja els seus ports i serveis.",
    "2. Vulnerabilitats i CVE — correlaciona els serveis detectats amb CVEs coneguts i, si cal, "
    "executa un escaneig actiu amb els scripts NSE de nmap per confirmar-les.",
    "3. Sistema Local — audita el propi equip: processos, connexions, tallafocs i reforçament "
    "(actualitzacions pendents, binaris SUID/SGID, comptes de risc).",
    "4. Informes — genera l'informe final (HTML, PDF, JSON o CSV) amb el resum executiu, la "
    "matriu de troballes i el pla de millora.",
]


class DashboardTab(ctk.CTkFrame):
    def __init__(self, master, app_state, switch_tab, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.switch_tab = switch_tab
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        ctk.CTkLabel(self, text=APP_NAME, font=("Segoe UI", 24, "bold")).pack(pady=(24, 0))
        ctk.CTkLabel(self, text=f"{COMPANY_NAME} — Panell de control de l'auditoria", text_color="#5B6472").pack(
            pady=(0, 16)
        )

        self.cards_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.cards_frame.pack(fill="x", padx=24, pady=(0, 8))
        self.card_hosts = self._make_card(self.cards_frame, "Equips Detectats", 0, "#0D2137")
        self.card_ports = self._make_card(self.cards_frame, "Ports Oberts", 1, "#0D2137")
        self.card_findings = self._make_card(self.cards_frame, "Troballes Totals", 2, "#1E88E5")
        self.card_critical = self._make_card(self.cards_frame, "Crítiques + Altes", 3, "#C62828")

        self.target_label = ctk.CTkLabel(self, text="", text_color="#5B6472")
        self.target_label.pack(pady=(4, 8))

        safe_mode_frame = ctk.CTkFrame(self, fg_color="transparent")
        safe_mode_frame.pack(pady=(0, 20))
        self.safe_mode_var = ctk.BooleanVar(value=self.app_state.safe_mode)
        ctk.CTkSwitch(
            safe_mode_frame, text="Mode Segur (recomanat)", variable=self.safe_mode_var,
            command=self._on_safe_mode_toggle,
        ).pack(side="left", padx=(0, 10))
        ctk.CTkLabel(
            safe_mode_frame,
            text="Amb el Mode Segur actiu, les accions més intrusives (escaneig complet de ports, "
            "UDP, scripts actius de vulnerabilitats) demanen confirmació explícita.",
            text_color="#5B6472", wraplength=560, justify="left",
        ).pack(side="left")

        priority_frame = ctk.CTkFrame(self)
        priority_frame.pack(fill="both", expand=True, padx=24, pady=(0, 16))
        ctk.CTkLabel(
            priority_frame, text="Prioritat de Remediació — Què cal arreglar primer?",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w", padx=16, pady=(14, 6))

        columns = ("severity", "location", "issue", "recommendation")
        self.priority_tree = ttk.Treeview(priority_frame, columns=columns, show="headings", height=6)
        headings = {
            "severity": "Gravetat", "location": "Ubicació", "issue": "Problema", "recommendation": "Recomanació",
        }
        widths = {"severity": 90, "location": 150, "issue": 280, "recommendation": 300}
        for col in columns:
            self.priority_tree.heading(col, text=headings[col])
            self.priority_tree.column(col, width=widths[col])
        self.priority_tree.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        for sev, color in SEVERITY_COLORS.items():
            self.priority_tree.tag_configure(sev, foreground=color)

        guide_frame = ctk.CTkFrame(self)
        guide_frame.pack(fill="x", padx=24, pady=(0, 16))
        ctk.CTkLabel(guide_frame, text="Primers Passos", font=("Segoe UI", 14, "bold")).pack(
            anchor="w", padx=16, pady=(14, 6)
        )
        for step in GUIDE_STEPS:
            ctk.CTkLabel(guide_frame, text=step, anchor="w", justify="left", wraplength=880).pack(
                fill="x", padx=16, pady=3
            )
        ctk.CTkLabel(guide_frame, text="", height=2).pack(pady=2)

        actions_frame = ctk.CTkFrame(self, fg_color="transparent")
        actions_frame.pack(pady=(0, 16))
        ctk.CTkButton(
            actions_frame, text="Anar a Auditoria de Xarxa", command=lambda: self.switch_tab("Auditoria de Xarxa")
        ).grid(row=0, column=0, padx=6)
        ctk.CTkButton(
            actions_frame, text="Anar a Vulnerabilitats", command=lambda: self.switch_tab("Vulnerabilitats i CVE")
        ).grid(row=0, column=1, padx=6)
        ctk.CTkButton(
            actions_frame, text="Anar a Sistema Local", command=lambda: self.switch_tab("Sistema Local")
        ).grid(row=0, column=2, padx=6)
        ctk.CTkButton(
            actions_frame, text="Generar Informe", command=lambda: self.switch_tab("Informes")
        ).grid(row=0, column=3, padx=6)
        ctk.CTkButton(
            actions_frame, text="Actualitzar Tauler", command=self.refresh,
            fg_color="#5B6472", hover_color="#3F4652",
        ).grid(row=0, column=4, padx=6)

    def _make_card(self, parent, title, column, color):
        parent.grid_columnconfigure(column, weight=1)
        card = ctk.CTkFrame(parent, border_width=2, border_color=color)
        card.grid(row=0, column=column, padx=8, sticky="nsew")
        value_label = ctk.CTkLabel(card, text="0", font=("Segoe UI", 30, "bold"))
        value_label.pack(pady=(18, 0))
        ctk.CTkLabel(card, text=title, text_color="#5B6472").pack(pady=(0, 18))
        card.value_label = value_label
        return card

    def refresh(self):
        stats = self.app_state.dashboard_stats()
        self.card_hosts.value_label.configure(text=str(stats["total_hosts"]))
        self.card_ports.value_label.configure(text=str(stats["total_open_ports"]))
        self.card_findings.value_label.configure(text=str(stats["total_findings"]))
        critical_high = stats["severity_counts"].get(Severity.CRITICAL, 0) + stats["severity_counts"].get(
            Severity.HIGH, 0
        )
        self.card_critical.value_label.configure(text=str(critical_high))
        target_text = stats["target"] or "Cap objectiu escanejat encara"
        self.target_label.configure(text=f"Objectiu actual de l'auditoria: {target_text}")

        for row in self.priority_tree.get_children():
            self.priority_tree.delete(row)
        top_findings = self.app_state.top_priority_findings(limit=8)
        if not top_findings:
            self.priority_tree.insert(
                "", "end",
                values=("-", "-", "Cap troballa encara. Executa un escaneig per començar.", "-"),
            )
        for vuln, location in top_findings:
            issue = vuln.description if vuln.cve_id == "N/A" else f"{vuln.cve_id} — {vuln.description}"
            self.priority_tree.insert(
                "", "end",
                values=(vuln.severity.value, location, issue[:120], vuln.recommendation[:120]),
                tags=(vuln.severity.value,),
            )

    def _on_safe_mode_toggle(self):
        self.app_state.safe_mode = self.safe_mode_var.get()
