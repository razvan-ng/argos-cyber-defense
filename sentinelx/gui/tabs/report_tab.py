"""Pestanya del Generador d'Informes i Pla de Millora."""
import os
import webbrowser
from tkinter import filedialog, messagebox

import customtkinter as ctk

from core.report_generator import ReportGenerator
from core.session_io import compare_sessions, load_session, save_session
from gui.theme import APP_NAME, COMPANY_NAME
from gui.widgets.diff_dialog import DiffDialog


class ReportTab(ctk.CTkFrame):
    def __init__(self, master, app_state, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self._build_ui()

    def _build_ui(self):
        frame = ctk.CTkFrame(self)
        frame.pack(padx=24, pady=24, fill="both", expand=True)

        ctk.CTkLabel(frame, text="Generador d'Informes d'Auditoria", font=("Segoe UI", 16, "bold")).pack(pady=(24, 8))
        ctk.CTkLabel(
            frame,
            text="Genera un informe complet amb resum executiu, inventari d'equips, matriu de\n"
            "troballes amb els seus codis CVE, reforçament del sistema local i un pla de millora.",
            justify="center",
        ).pack(pady=(0, 20))

        ctk.CTkLabel(frame, text="Objectiu de l'auditoria (nom/descripció):").pack(pady=(0, 4))
        self.target_entry = ctk.CTkEntry(frame, width=420, placeholder_text="ex. Xarxa interna 192.168.1.0/24")
        self.target_entry.pack(pady=(0, 20))

        export_frame = ctk.CTkFrame(frame, fg_color="transparent")
        export_frame.pack(pady=8)
        ctk.CTkLabel(export_frame, text="Exportar informe:", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, columnspan=4, pady=(0, 8)
        )
        ctk.CTkButton(export_frame, text="HTML", command=self._export_html, width=100).grid(row=1, column=0, padx=6)
        ctk.CTkButton(export_frame, text="PDF", command=self._export_pdf, width=100).grid(row=1, column=1, padx=6)
        ctk.CTkButton(export_frame, text="JSON", command=self._export_json, width=100).grid(row=1, column=2, padx=6)
        ctk.CTkButton(export_frame, text="CSV", command=self._export_csv, width=100).grid(row=1, column=3, padx=6)

        session_frame = ctk.CTkFrame(frame, fg_color="transparent")
        session_frame.pack(pady=(24, 8))
        ctk.CTkLabel(session_frame, text="Sessió d'auditoria:", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, columnspan=3, pady=(0, 8)
        )
        ctk.CTkButton(session_frame, text="Guardar Sessió", command=self._save_session, width=150).grid(
            row=1, column=0, padx=6
        )
        ctk.CTkButton(session_frame, text="Carregar Sessió", command=self._load_session, width=150).grid(
            row=1, column=1, padx=6
        )
        ctk.CTkButton(
            session_frame, text="Comparar amb Baseline", command=self._compare_baseline, width=170,
            fg_color="#5B6472", hover_color="#3F4652",
        ).grid(row=1, column=2, padx=6)

        self.status_label = ctk.CTkLabel(frame, text="", text_color="#2E7D32", wraplength=560)
        self.status_label.pack(pady=(20, 0))

    def _get_generator(self):
        target = self.target_entry.get().strip()
        if target:
            self.app_state.session.target = target
        return ReportGenerator(self.app_state.session, COMPANY_NAME, APP_NAME)

    def _set_status(self, text, color="#2E7D32"):
        self.status_label.configure(text=text, text_color=color)

    # ------------------------------------------------------------------ #
    # Exportació d'informes
    # ------------------------------------------------------------------ #
    def _export_html(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".html", filetypes=[("Fitxer HTML", "*.html")], initialfile="informe_auditoria.html"
        )
        if not path:
            return
        try:
            self._get_generator().generate_html(path)
            self._set_status(f"Informe HTML generat correctament: {path}")
            if messagebox.askyesno("Obrir informe", "Vols obrir l'informe generat ara mateix?"):
                webbrowser.open(f"file://{os.path.abspath(path)}")
        except OSError as exc:
            messagebox.showerror("Error", f"No s'ha pogut generar l'informe: {exc}")

    def _export_pdf(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("Fitxer PDF", "*.pdf")], initialfile="informe_auditoria.pdf"
        )
        if not path:
            return
        try:
            self._get_generator().generate_pdf(path)
            self._set_status(f"Informe PDF generat correctament: {path}")
        except Exception as exc:  # noqa: BLE001 - errors de generació de PDF es mostren a l'usuari
            messagebox.showerror("Error", f"No s'ha pogut generar l'informe: {exc}")

    def _export_json(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("Fitxer JSON", "*.json")], initialfile="informe_auditoria.json"
        )
        if not path:
            return
        try:
            self._get_generator().generate_json(path)
            self._set_status(f"Informe JSON generat correctament: {path}")
        except OSError as exc:
            messagebox.showerror("Error", f"No s'ha pogut generar l'informe: {exc}")

    def _export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv", filetypes=[("Fitxer CSV", "*.csv")], initialfile="troballes_auditoria.csv"
        )
        if not path:
            return
        try:
            self._get_generator().generate_csv(path)
            self._set_status(f"Fitxer CSV generat correctament: {path}")
        except OSError as exc:
            messagebox.showerror("Error", f"No s'ha pogut generar el fitxer CSV: {exc}")

    # ------------------------------------------------------------------ #
    # Sessió d'auditoria (guardar / carregar / comparar)
    # ------------------------------------------------------------------ #
    def _save_session(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".json", filetypes=[("Sessió SentinelX", "*.json")], initialfile="sessio_auditoria.json"
        )
        if not path:
            return
        try:
            save_session(self.app_state.session, path)
            self._set_status(f"Sessió d'auditoria guardada: {path}")
        except OSError as exc:
            messagebox.showerror("Error", f"No s'ha pogut guardar la sessió: {exc}")

    def _load_session(self):
        path = filedialog.askopenfilename(filetypes=[("Sessió SentinelX", "*.json")])
        if not path:
            return
        try:
            session = load_session(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Error", f"No s'ha pogut carregar la sessió: {exc}")
            return
        if not messagebox.askyesno(
            "Carregar sessió",
            "Això substituirà les dades de l'auditoria actual (equips, vulnerabilitats, reforçament) "
            "per les del fitxer carregat. Vols continuar?",
        ):
            return
        self.app_state.load_session(session)
        self.target_entry.delete(0, "end")
        self.target_entry.insert(0, session.target)
        self._set_status(f"Sessió carregada correctament des de: {path}")

    def _compare_baseline(self):
        path = filedialog.askopenfilename(filetypes=[("Sessió SentinelX", "*.json")])
        if not path:
            return
        try:
            baseline = load_session(path)
        except (OSError, ValueError) as exc:
            messagebox.showerror("Error", f"No s'ha pogut carregar la sessió base (baseline): {exc}")
            return
        diff = compare_sessions(self.app_state.session, baseline)
        DiffDialog(self, diff, baseline_target=baseline.target or path)
