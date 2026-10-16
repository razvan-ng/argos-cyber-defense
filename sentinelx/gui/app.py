"""Finestra principal de SentinelX Audit Suite."""
import sys
import threading
import tkinter
import webbrowser
from tkinter import messagebox

import customtkinter as ctk

from core.app_state import AppState
from core.updates import UpdateCheckError, check_latest
from gui.tabs.about_tab import AboutTab
from gui.tabs.dashboard_tab import DashboardTab
from gui.tabs.network_tab import NetworkTab
from gui.tabs.portal_tab import PortalTab
from gui.tabs.report_tab import ReportTab
from gui.tabs.system_tab import SystemTab
from gui.tabs.vuln_tab import VulnTab
from gui.theme import APP_NAME, APP_VERSION, COMPANY_NAME, apply_theme
from gui.theme import COLOR_ACCENT, COLOR_BACKGROUND, COLOR_HEADER, FONT_DISPLAY_FAMILY
from gui.theme import LOGO_ICON_ICO, LOGO_ICON_PNG, LOGO_SYMBOL_DARK, load_logo
from gui.widgets.dependency_dialog import DependencyDialog
from utils.resources import resource_path

TAB_DASHBOARD = "Tauler"
TAB_PORTAL = "Expedients"


class SentinelXApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        apply_theme()
        self.configure(fg_color=COLOR_BACKGROUND)
        self.title(f"{APP_NAME} — {COMPANY_NAME}")
        self.geometry("1200x760")
        self.minsize(1000, 640)
        self._set_window_icon()
        self.app_state = AppState()

        self._build_header()
        self._build_tabs()

        self.after(300, self._show_dependency_check)
        self.after(4000, self._check_updates)

    def _build_header(self):
        header = ctk.CTkFrame(self, height=60, fg_color=COLOR_HEADER, corner_radius=0)
        header.pack(fill="x", side="top")
        header.pack_propagate(False)
        logo = load_logo(LOGO_SYMBOL_DARK, size=(46, 46))
        if logo:
            ctk.CTkLabel(header, text="", image=logo).pack(side="left", padx=(16, 0))
        ctk.CTkLabel(
            header, text=f" {APP_NAME}", font=(FONT_DISPLAY_FAMILY, 19, "bold"), text_color="white"
        ).pack(side="left", padx=(8, 16))
        ctk.CTkLabel(
            header, text=f"{COMPANY_NAME.upper()}  ", font=(FONT_DISPLAY_FAMILY, 12, "bold"), text_color=COLOR_ACCENT
        ).pack(side="right", padx=16)
        ctk.CTkLabel(header, text=f"v{APP_VERSION}", font=(FONT_DISPLAY_FAMILY, 11), text_color="#8196AD").pack(side="left")
        # Línia d'accent en cian sota la capçalera, com a la web corporativa
        ctk.CTkFrame(self, height=3, fg_color=COLOR_ACCENT, corner_radius=0).pack(fill="x", side="top")

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
        self.tabview = ctk.CTkTabview(
            self, command=self._on_tab_changed, anchor="nw", fg_color=COLOR_BACKGROUND,
        )
        self.tabview.pack(fill="both", expand=True, padx=12, pady=(10, 8))

        tab_dashboard = self.tabview.add(TAB_DASHBOARD)
        tab_portal = self.tabview.add(TAB_PORTAL)
        tab_network = self.tabview.add("Auditoria de Xarxa")
        tab_system = self.tabview.add("Sistema Local")
        tab_vuln = self.tabview.add("Vulnerabilitats i CVE")
        tab_report = self.tabview.add("Informes")
        tab_about = self.tabview.add("Quant a / Crèdits")

        self.dashboard_tab = DashboardTab(tab_dashboard, self.app_state, switch_tab=self.switch_tab)
        self.dashboard_tab.pack(fill="both", expand=True)
        self.portal_tab = PortalTab(tab_portal, self.app_state, on_expedient_changed=self._on_expedient_changed)
        self.portal_tab.pack(fill="both", expand=True)
        self.network_tab = NetworkTab(tab_network, self.app_state)
        self.network_tab.pack(fill="both", expand=True)
        SystemTab(tab_system, self.app_state).pack(fill="both", expand=True)
        VulnTab(tab_vuln, self.app_state).pack(fill="both", expand=True)
        self.report_tab = ReportTab(tab_report, self.app_state, switch_tab=self.switch_tab)
        self.report_tab.pack(fill="both", expand=True)
        AboutTab(tab_about).pack(fill="both", expand=True)

        self.tabview.set(TAB_DASHBOARD)

    def switch_tab(self, name):
        self.tabview.set(name)
        self._on_tab_changed()

    def _on_tab_changed(self):
        current = self.tabview.get()
        if current == TAB_DASHBOARD:
            self.dashboard_tab.refresh()
        elif current == TAB_PORTAL:
            self.portal_tab.refresh()

    def _on_expedient_changed(self):
        """Quan s'obre o es tanca un expedient, les altres pestanyes mostren la sessió nova."""
        self.network_tab.sync_with_session()
        self.report_tab.set_target(self.app_state.session.target)
        self.dashboard_tab.refresh()

    def _show_dependency_check(self):
        DependencyDialog(self, on_continue=lambda: None)

    def _check_updates(self):
        """Comprova en segon pla si hi ha una versió nova de SentinelX a GitHub."""
        def worker():
            try:
                info = check_latest(APP_VERSION)
            except UpdateCheckError:
                return  # sense connexió o encara sense versions publicades: no cal molestar
            if info["newer"]:
                self.after(0, lambda: self._notify_update(info))

        threading.Thread(target=worker, daemon=True).start()

    def _notify_update(self, info):
        if messagebox.askyesno(
            "Versió nova de SentinelX",
            f"Hi ha disponible SentinelX {info['latest']} (teniu la {APP_VERSION}).\n\nVoleu obrir la pàgina de descàrrega?",
        ):
            webbrowser.open(info["url"])


def run():
    app = SentinelXApp()
    app.mainloop()
