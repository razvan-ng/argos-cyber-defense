"""Pestanya 'Quant a / Crèdits': identitat corporativa, equip de desenvolupament

i un diagnòstic persistent de l'estat de les eines del sistema (accessible en
qualsevol moment, no només en arrencar l'aplicació).
"""
import threading
import webbrowser

import customtkinter as ctk

from core.dependency_check import run_health_check, run_optional_check
from core.updates import RELEASES_PAGE, UpdateCheckError, check_latest
from gui.theme import APP_NAME, APP_VERSION, COMPANY_NAME, COPYRIGHT, PROJECT_LABEL
from gui.theme import LOGO_HORIZONTAL, load_logo

TEAM_MEMBERS = [
    "Razvan-Andrei Nastasa Ghitau",
    "Lluc Sarrà Masdeu",
    "Mouhammed Oualy",
]


class AboutTab(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self._build_ui()

    def _build_ui(self):
        container = ctk.CTkScrollableFrame(self, fg_color="transparent")
        container.pack(padx=40, pady=20, fill="both", expand=True)

        logo = load_logo(LOGO_HORIZONTAL, size=(300, 108))
        if logo:
            ctk.CTkLabel(container, text="", image=logo).pack(pady=(20, 0))
        ctk.CTkLabel(container, text=APP_NAME, font=("Segoe UI", 26, "bold")).pack(pady=(20, 4))
        ctk.CTkLabel(container, text=f"Desenvolupat per {COMPANY_NAME}", font=("Segoe UI", 14)).pack(pady=(0, 4))
        ctk.CTkLabel(container, text=f"Versió {APP_VERSION}", text_color="#5B6472").pack(pady=(0, 6))
        update_row = ctk.CTkFrame(container, fg_color="transparent")
        update_row.pack(pady=(0, 24))
        self.update_btn = ctk.CTkButton(update_row, text="Comprova si hi ha versions noves", command=self._check_updates)
        self.update_btn.pack(side="left", padx=6)
        ctk.CTkButton(update_row, text="Versions a GitHub", command=lambda: webbrowser.open(RELEASES_PAGE),
                      fg_color="transparent", border_width=1, border_color="#0B1F3A", text_color="#0B1F3A").pack(side="left", padx=6)
        self.update_label = ctk.CTkLabel(container, text="", text_color="#5B6472")
        self.update_label.pack(pady=(0, 8))

        ctk.CTkLabel(container, text=PROJECT_LABEL, wraplength=560, justify="center").pack(pady=(0, 24))

        ctk.CTkLabel(container, text="Equip de Desenvolupament", font=("Segoe UI", 16, "bold")).pack(pady=(8, 8))
        for member in TEAM_MEMBERS:
            ctk.CTkLabel(container, text=f"•  {member}", font=("Segoe UI", 13)).pack(pady=2)

        ctk.CTkLabel(container, text="Estat del Sistema (Diagnòstic)", font=("Segoe UI", 16, "bold")).pack(
            pady=(28, 8)
        )
        ctk.CTkLabel(
            container,
            text="Comprovació de les eines externes de què depèn SentinelX, disponible en qualsevol moment.",
            text_color="#5B6472",
        ).pack(pady=(0, 8))
        self.status_frame = ctk.CTkFrame(container)
        self.status_frame.pack(fill="x", padx=20, pady=(0, 8))
        ctk.CTkButton(container, text="Tornar a comprovar", command=self._refresh_health).pack(pady=(0, 24))

        ctk.CTkLabel(
            container,
            text=(
                "Avís legal: aquesta eina ha d'utilitzar-se exclusivament sobre xarxes i sistemes "
                "per als quals es disposi d'autorització expressa i per escrit. L'ús no autoritzat "
                "sobre sistemes de tercers pot constituir un delicte."
            ),
            wraplength=560,
            justify="center",
            text_color="#C62828",
        ).pack(pady=(8, 8))
        ctk.CTkLabel(container, text=f"© {COPYRIGHT}", text_color="#9AA5B1").pack(pady=(4, 20))

        self._refresh_health()

    def _check_updates(self):
        self.update_btn.configure(state="disabled")
        self.update_label.configure(text="Consultant GitHub...", text_color="#5B6472")

        def worker():
            try:
                info = check_latest(APP_VERSION)
                if info["newer"]:
                    text, color = f"Hi ha disponible la versió {info['latest']}. Descarregueu-la des de GitHub.", "#C62828"
                else:
                    text, color = f"Teniu la darrera versió ({APP_VERSION}).", "#2E7D32"
            except UpdateCheckError as exc:
                text, color = str(exc), "#5B6472"
            self.after(0, lambda: self._show_update(text, color))

        threading.Thread(target=worker, daemon=True).start()

    def _show_update(self, text, color):
        self.update_btn.configure(state="normal")
        self.update_label.configure(text=text, text_color=color)

    def _refresh_health(self):
        for widget in self.status_frame.winfo_children():
            widget.destroy()

        results, _ = run_health_check()
        optional_results, _ = run_optional_check()

        for tool, info in {**results, **optional_results}.items():
            color = "#2E7D32" if info["available"] else "#C62828"
            icon = "✓" if info["available"] else "✗"
            text = f"{icon}  {tool} — {info['description']}"
            ctk.CTkLabel(self.status_frame, text=text, text_color=color, anchor="w", justify="left").pack(
                fill="x", padx=12, pady=3
            )
