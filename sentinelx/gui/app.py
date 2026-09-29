"""Finestra principal de SentinelX Audit Suite."""
import sys
import tkinter

import customtkinter as ctk

from core.app_state import AppState
from gui.tabs.about_tab import AboutTab
from gui.tabs.dashboard_tab import DashboardTab
from gui.tabs.network_tab import NetworkTab
from gui.tabs.report_tab import ReportTab
from gui.tabs.system_tab import SystemTab
from gui.tabs.vuln_tab import VulnTab
from gui.theme import APP_NAME, COLOR_PRIMARY_DARK, COMPANY_NAME, apply_theme
from gui.theme import LOGO_ICON_ICO, LOGO_ICON_PNG, LOGO_SYMBOL_DARK, load_logo
from gui.widgets.dependency_dialog import DependencyDialog
from utils.resources import resource_path

TAB_DASHBOARD = "Tauler"


class SentinelXApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        apply_theme()
        self.title(f"{APP_NAME} — {COMPANY_NAME}")
        self.geometry("1200x760")
        self.minsize(1000, 640)
        self._set_window_icon()
        self.app_state = AppState()

        self._build_header()
        self._build_tabs()

        self.after(300, self._show_dependency_check)

    def _build_header(self):
        header = ctk.CTkFrame(self, height=56, fg_color=COLOR_PRIMARY_DARK, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        logo = load_logo(LOGO_SYMBOL_DARK, size=(46, 46))
        if logo:
            ctk.CTkLabel(header, text="", image=logo).pack(side="left", padx=(16, 0))
        ctk.CTkLabel(header, text=f"  {APP_NAME}", font=("Segoe UI", 18, "bold"), text_color="white").pack(
            side="left", padx=16
        )
        ctk.CTkLabel(header, text=f"{COMPANY_NAME}  ", font=("Segoe UI", 12), text_color="#9FB3C8").pack(
            side="right", padx=16
        )

    def _set_window_icon(self):
        """Icona de la finestra i de la barra de tasques amb el símbol d'Argos."""
        try:
            if sys.platform.startswith("win"):
                self.iconbitmap(resource_path(LOGO_ICON_ICO))
            else:
                self._icon_photo = tkinter.PhotoImage(file=resource_path(LOGO_ICON_PNG))
                self.iconphoto(True, self._icon_photo)
        except tkinter.TclError:
            pass  # si falta el fitxer, es manté la icona per defecte

    def _build_tabs(self):
        self.tabview = ctk.CTkTabview(self, command=self._on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=8, pady=8)

        tab_dashboard = self.tabview.add(TAB_DASHBOARD)
        tab_network = self.tabview.add("Auditoria de Xarxa")
        tab_system = self.tabview.add("Sistema Local")
        tab_vuln = self.tabview.add("Vulnerabilitats i CVE")
        tab_report = self.tabview.add("Informes")
        tab_about = self.tabview.add("Quant a / Crèdits")

        self.dashboard_tab = DashboardTab(tab_dashboard, self.app_state, switch_tab=self.tabview.set)
        self.dashboard_tab.pack(fill="both", expand=True)
        NetworkTab(tab_network, self.app_state).pack(fill="both", expand=True)
        SystemTab(tab_system, self.app_state).pack(fill="both", expand=True)
        VulnTab(tab_vuln, self.app_state).pack(fill="both", expand=True)
        ReportTab(tab_report, self.app_state).pack(fill="both", expand=True)
        AboutTab(tab_about).pack(fill="both", expand=True)

        self.tabview.set(TAB_DASHBOARD)

    def _on_tab_changed(self):
        if self.tabview.get() == TAB_DASHBOARD:
            self.dashboard_tab.refresh()

    def _show_dependency_check(self):
        DependencyDialog(self, on_continue=lambda: None)


def run():
    app = SentinelXApp()
    app.mainloop()
