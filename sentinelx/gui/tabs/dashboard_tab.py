"""Pestanya 'Tauler': resum ràpid de l'estat de l'auditoria i accés directe a les

funcions principals. Pensada com a punt d'entrada de l'aplicació perquè un
usuari nou entengui d'un cop d'ull l'estat de l'auditoria i què fer a continuació.
"""
import tkinter

import customtkinter as ctk

from core.models import Severity
from gui.theme import (
    APP_NAME, COLOR_ACCENT, COLOR_ACCENT_TEXT, COLOR_BACKGROUND, COLOR_BORDER, COLOR_DANGER, COLOR_PRIMARY,
    COLOR_PRIMARY_DARK, COLOR_SURFACE, COLOR_TAB_BAR, COLOR_TEXT_MUTED, COMPANY_NAME, FONT_BODY,
    FONT_DISPLAY_FAMILY, FONT_MONO_FAMILY, SEVERITY_COLORS, SEVERITY_TEXT_COLORS,
)

GUIDE_STEPS = [
    "1. Auditoria de Xarxa — descobreix equips actius i escaneja els seus ports i serveis.",
    "2. Vulnerabilitats i CVE — correlaciona els serveis detectats amb CVEs coneguts i, si cal, "
    "executa un escaneig actiu amb els scripts NSE de nmap per confirmar-les.",
    "3. Sistema Local — audita el propi equip: processos, connexions, tallafocs i reforçament "
    "(actualitzacions pendents, binaris SUID/SGID, comptes de risc).",
    "4. Informes — genera l'informe final (HTML, PDF, JSON o CSV) amb el resum executiu, la "
    "matriu de troballes i el pla de millora.",
]

# Text curt de l'etiqueta de gravetat quan la troballa no té puntuació CVSS
SEVERITY_SHORT = {"Crítica": "CRÍT", "Alta": "ALTA", "Mitjana": "MITJ", "Baixa": "BAIXA", "Informativa": "INFO"}


class DashboardTab(ctk.CTkFrame):
    def __init__(self, master, app_state, switch_tab, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.switch_tab = switch_tab
        self._severity_counts = {}
        self._build_ui()
        self.refresh()

    def _build_ui(self):
        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # Títol i objectiu actual
        head = ctk.CTkFrame(body, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(8, 14))
        ctk.CTkLabel(
            head, text=APP_NAME, font=(FONT_DISPLAY_FAMILY, 24, "bold"), text_color=COLOR_PRIMARY_DARK
        ).pack(anchor="w")
        ctk.CTkLabel(head, text=f"{COMPANY_NAME} — Panell de control de l'auditoria", text_color=COLOR_TEXT_MUTED).pack(
            anchor="w"
        )
        self.target_label = ctk.CTkLabel(head, text="", text_color=COLOR_ACCENT_TEXT, font=(FONT_BODY[0], 12, "bold"))
        self.target_label.pack(anchor="w", pady=(4, 0))

        # Targetes de resum
        self.cards_frame = ctk.CTkFrame(body, fg_color="transparent")
        self.cards_frame.pack(fill="x", padx=10, pady=(0, 16))
        self.card_hosts = self._make_card(self.cards_frame, "Equips Detectats", 0, COLOR_PRIMARY_DARK)
        self.card_ports = self._make_card(self.cards_frame, "Ports Oberts", 1, COLOR_PRIMARY)
        self.card_findings = self._make_card(self.cards_frame, "Troballes Totals", 2, COLOR_ACCENT)
        self.card_critical = self._make_card(self.cards_frame, "Crítiques + Altes", 3, COLOR_DANGER)

        # Barra de distribució de les troballes per gravetat
        severity_frame = ctk.CTkFrame(body, fg_color="transparent")
        severity_frame.pack(fill="x", padx=16, pady=(0, 16))
        self.severity_canvas = tkinter.Canvas(
            severity_frame, height=10, highlightthickness=0, bd=0, bg=COLOR_BACKGROUND
        )
        self.severity_canvas.pack(fill="x", pady=(0, 8))
        self.severity_canvas.bind("<Configure>", lambda _e: self._draw_severity_bar())
        legend = ctk.CTkFrame(severity_frame, fg_color="transparent")
        legend.pack(anchor="w")
        self.severity_legend = {}
        for sev in Severity:
            item = ctk.CTkFrame(legend, fg_color="transparent")
            item.pack(side="left", padx=(0, 16))
            ctk.CTkFrame(item, width=10, height=10, corner_radius=2, fg_color=SEVERITY_COLORS[sev.value]).pack(
                side="left", padx=(0, 6)
            )
            label = ctk.CTkLabel(item, text=f"{sev.value} 0", text_color=COLOR_TEXT_MUTED)
            label.pack(side="left")
            self.severity_legend[sev] = label

        # Mode Segur
        safe_mode_frame = ctk.CTkFrame(body, border_width=1, border_color=COLOR_BORDER)
        safe_mode_frame.pack(fill="x", padx=16, pady=(0, 16))
        self.safe_mode_var = ctk.BooleanVar(value=self.app_state.safe_mode)
        ctk.CTkSwitch(
            safe_mode_frame, text="Mode Segur (recomanat)", variable=self.safe_mode_var,
            command=self._on_safe_mode_toggle, font=(FONT_DISPLAY_FAMILY, 13, "bold"),
        ).pack(side="left", padx=(18, 12), pady=14)
        ctk.CTkLabel(
            safe_mode_frame,
            text="Amb el Mode Segur actiu, les accions més intrusives (escaneig complet de ports, "
            "UDP, scripts actius de vulnerabilitats) demanen confirmació explícita.",
            text_color=COLOR_TEXT_MUTED, wraplength=620, justify="left",
        ).pack(side="left", padx=(0, 18), pady=14)

        # Què cal arreglar primer?
        priority_frame = ctk.CTkFrame(body, fg_color="transparent")
        priority_frame.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkLabel(
            priority_frame, text="Prioritat de Remediació — Què cal arreglar primer?",
            font=(FONT_DISPLAY_FAMILY, 16, "bold"), text_color=COLOR_PRIMARY_DARK,
        ).pack(anchor="w", pady=(0, 8))
        self.priority_list = ctk.CTkFrame(priority_frame, fg_color="transparent")
        self.priority_list.pack(fill="x")

        # Primers passos
        guide_frame = ctk.CTkFrame(body, border_width=1, border_color=COLOR_BORDER)
        guide_frame.pack(fill="x", padx=16, pady=(0, 16))
        ctk.CTkLabel(
            guide_frame, text="Primers Passos", font=(FONT_DISPLAY_FAMILY, 15, "bold"), text_color=COLOR_PRIMARY_DARK
        ).pack(anchor="w", padx=18, pady=(14, 6))
        for step in GUIDE_STEPS:
            ctk.CTkLabel(
                guide_frame, text=step, anchor="w", justify="left", wraplength=880, text_color=COLOR_TEXT_MUTED
            ).pack(fill="x", padx=18, pady=3)
        ctk.CTkLabel(guide_frame, text="", height=2).pack(pady=2)

        # Accessos directes
        actions_frame = ctk.CTkFrame(body, fg_color="transparent")
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
            fg_color="transparent", border_width=1, border_color=COLOR_PRIMARY_DARK,
            text_color=COLOR_PRIMARY_DARK, hover_color=COLOR_TAB_BAR,
        ).grid(row=0, column=4, padx=6)

    def _make_card(self, parent, title, column, color):
        parent.grid_columnconfigure(column, weight=1, uniform="cards")
        card = ctk.CTkFrame(parent, border_width=1, border_color=COLOR_BORDER)
        card.grid(row=0, column=column, padx=6, sticky="nsew")
        # Petita franja de color que identifica la targeta
        ctk.CTkFrame(card, width=36, height=4, corner_radius=2, fg_color=color).pack(anchor="w", padx=18, pady=(16, 0))
        value_label = ctk.CTkLabel(
            card, text="0", font=(FONT_DISPLAY_FAMILY, 30, "bold"), text_color=COLOR_PRIMARY_DARK
        )
        value_label.pack(anchor="w", padx=18, pady=(6, 0))
        ctk.CTkLabel(card, text=title, text_color=COLOR_TEXT_MUTED).pack(anchor="w", padx=18, pady=(0, 16))
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

        self._severity_counts = stats["severity_counts"]
        for sev, label in self.severity_legend.items():
            label.configure(text=f"{sev.value} {self._severity_counts.get(sev, 0)}")
        self._draw_severity_bar()

        for row in self.priority_list.winfo_children():
            row.destroy()
        top_findings = self.app_state.top_priority_findings(limit=8)
        if not top_findings:
            empty = ctk.CTkFrame(self.priority_list, fg_color=COLOR_SURFACE, border_width=1, border_color=COLOR_BORDER)
            empty.pack(fill="x", pady=4)
            ctk.CTkLabel(
                empty, text="Cap troballa encara. Executa un escaneig per començar.", text_color=COLOR_TEXT_MUTED
            ).pack(anchor="w", padx=16, pady=14)
        for vuln, location in top_findings:
            self._add_priority_row(vuln, location)

    def _add_priority_row(self, vuln, location):
        """Fila de la llista 'Què cal arreglar primer?' amb l'estil de targeta."""
        severity = vuln.severity.value
        has_cve = vuln.cve_id != "N/A"
        title = vuln.cve_id if has_cve else vuln.description
        if vuln.exploit_available:
            title += "  ·  exploit públic conegut"
        detail = f"{vuln.description} — " if has_cve else ""
        if vuln.recommendation:
            detail += f"Recomanació: {vuln.recommendation}"
        if len(detail) > 160:
            detail = detail[:157] + "..."

        row = ctk.CTkFrame(self.priority_list, fg_color=COLOR_SURFACE, border_width=1, border_color=COLOR_BORDER)
        row.pack(fill="x", pady=4)
        row.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(
            row, text=self._score_text(vuln), width=58, height=30, corner_radius=6,
            fg_color=SEVERITY_COLORS.get(severity, COLOR_TEXT_MUTED),
            text_color=SEVERITY_TEXT_COLORS.get(severity, "#FFFFFF"),
            font=(FONT_MONO_FAMILY, 12, "bold"),
        ).grid(row=0, column=0, rowspan=2, padx=(14, 14), pady=12)
        ctk.CTkLabel(
            row, text=title[:110], font=(FONT_MONO_FAMILY if has_cve else FONT_BODY[0], 12, "bold"),
            text_color=COLOR_PRIMARY_DARK, anchor="w", justify="left", wraplength=640,
        ).grid(row=0, column=1, sticky="w", pady=(10, 0))
        ctk.CTkLabel(
            row, text=detail, text_color=COLOR_TEXT_MUTED, anchor="w", justify="left", wraplength=640,
        ).grid(row=1, column=1, sticky="w", pady=(0, 10))
        ctk.CTkLabel(
            row, text=location, font=(FONT_MONO_FAMILY, 11), text_color=COLOR_TEXT_MUTED,
        ).grid(row=0, column=2, rowspan=2, padx=(12, 18))

    @staticmethod
    def _score_text(vuln):
        """Puntuació CVSS amb un decimal o, si no en té, la gravetat abreujada."""
        try:
            return f"{float(vuln.cvss_score):.1f}"
        except (TypeError, ValueError):
            return SEVERITY_SHORT.get(vuln.severity.value, "-")

    def _draw_severity_bar(self):
        """Dibuixa la barra segmentada amb la proporció de troballes de cada gravetat."""
        canvas = self.severity_canvas
        canvas.delete("all")
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        if width <= 1 or height <= 1:
            return
        total = sum(self._severity_counts.values())
        if total == 0:
            canvas.create_rectangle(0, 0, width, height, fill=COLOR_TAB_BAR, width=0)
            return
        x = 0.0
        gap = 3
        for sev in Severity:
            count = self._severity_counts.get(sev, 0)
            if not count:
                continue
            segment = width * count / total
            canvas.create_rectangle(x, 0, max(x + 1, x + segment - gap), height, fill=SEVERITY_COLORS[sev.value], width=0)
            x += segment

    def _on_safe_mode_toggle(self):
        self.app_state.safe_mode = self.safe_mode_var.get()
