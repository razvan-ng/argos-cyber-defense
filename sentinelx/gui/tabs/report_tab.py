"""Pestanya del Generador d'Informes i Pla de Millora."""
import os
import threading
import webbrowser
from tkinter import filedialog, messagebox
from urllib.parse import urlparse

import customtkinter as ctk

from core.ai_assistant import AIAssistant, AIError, Anonymizer, delete_api_key, load_config, mask_key, save_config
from core.report_generator import ReportGenerator
from core.session_io import compare_sessions, load_session, save_session
from gui.theme import (
    APP_NAME, APP_VERSION, COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_BORDER, COLOR_DANGER, COLOR_PRIMARY_DARK,
    COLOR_SUCCESS, COLOR_TEXT_MUTED, COMPANY_NAME, PORTAL_URL,
)
from gui.widgets.diff_dialog import DiffDialog


class ReportTab(ctk.CTkFrame):
    def __init__(self, master, app_state, switch_tab=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.switch_tab = switch_tab
        self._build_ui()

    def _build_ui(self):
        # Desplaçable perquè tots els blocs hi càpiguen també amb la finestra a la mida mínima
        frame = ctk.CTkScrollableFrame(self)
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

        self._build_ai_section(frame)

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

        portal_frame = ctk.CTkFrame(frame, fg_color="transparent")
        portal_frame.pack(pady=(24, 8))
        portal_host = urlparse(PORTAL_URL).hostname or PORTAL_URL
        ctk.CTkLabel(portal_frame, text=f"Portal de clients ({portal_host}):", font=("Segoe UI", 12, "bold")).pack(
            pady=(0, 8)
        )
        ctk.CTkButton(
            portal_frame, text="Desa o publica a l'expedient", command=self._open_portal_tab, width=260,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK,
        ).pack()
        ctk.CTkLabel(
            portal_frame,
            text="Desa els resultats a l'expedient del client des de la pestanya Expedients:\n"
            "el client els consultarà a l'Àrea de clients quan es publiquin.",
            text_color="#5B6472", justify="center",
        ).pack(pady=(6, 0))

        self.status_label = ctk.CTkLabel(frame, text="", text_color="#2E7D32", wraplength=560)
        self.status_label.pack(pady=(20, 0))

    # ------------------------------------------------------------------ #
    # Assistent d'IA (Google Gemini): informe senzill per a l'empresa
    # ------------------------------------------------------------------ #
    def _build_ai_section(self, parent):
        outline = {"fg_color": "transparent", "border_width": 1, "border_color": COLOR_PRIMARY_DARK,
                   "text_color": COLOR_PRIMARY_DARK}
        card = ctk.CTkFrame(parent, border_width=1, border_color=COLOR_BORDER)
        card.pack(pady=(24, 8), padx=20, fill="x")
        ctk.CTkLabel(card, text="Informe senzill per a l'empresa (assistent d'IA)", font=("Segoe UI", 13, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(anchor="w", padx=16, pady=(12, 2))
        ctk.CTkLabel(
            card, text="La IA (Google Gemini o, si no està disponible, la de Cloudflare) redacta un informe sense "
            "tecnicismes per a la direcció de l'empresa (nivell de risc, riscos principals, què cal fer i glossari) i, "
            "a la pestanya Vulnerabilitats, tradueix les descripcions al català i explica cada troballa.", text_color=COLOR_TEXT_MUTED, wraplength=640,
            justify="left",
        ).pack(anchor="w", padx=16)

        key_row = ctk.CTkFrame(card, fg_color="transparent")
        key_row.pack(fill="x", padx=16, pady=(10, 2))
        ctk.CTkLabel(key_row, text="Clau de Gemini:").pack(side="left")
        self.ai_key_entry = ctk.CTkEntry(key_row, width=260, show="•", placeholder_text="Enganxeu aquí la clau de l'API")
        self.ai_key_entry.pack(side="left", padx=8)
        ctk.CTkButton(key_row, text="Desa", width=70, command=self._save_ai_key).pack(side="left")
        self.ai_check_btn = ctk.CTkButton(key_row, text="Comprova", width=90, command=self._check_ai, **outline)
        self.ai_check_btn.pack(side="left", padx=8)
        ctk.CTkButton(key_row, text="Esborra", width=80, command=self._delete_ai_key, **outline).pack(side="left")

        self.anonymize_var = ctk.BooleanVar(value=load_config()["anonymize"])
        ctk.CTkCheckBox(card, text="Amaga les IP i els noms dels equips quan s'envien les dades a la IA",
                        variable=self.anonymize_var, command=lambda: save_config(anonymize=self.anonymize_var.get())
                        ).pack(anchor="w", padx=16, pady=(8, 2))
        self.ai_status = ctk.CTkLabel(card, text="", anchor="w", justify="left", wraplength=640)
        self.ai_status.pack(anchor="w", padx=16, pady=(2, 4))

        self.company_btn = ctk.CTkButton(
            card, text="Genera l'informe per a l'empresa (PDF)", width=300, command=self._export_company_report,
            fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK,
        )
        self.company_btn.pack(pady=(4, 14))
        self._refresh_ai_status()

    def _refresh_ai_status(self, text="", color=None):
        config = load_config()
        if text:
            self.ai_status.configure(text=text, text_color=color or COLOR_TEXT_MUTED)
        elif config["source"] == "argos":
            self.ai_status.configure(text="No cal cap clau: la IA es fa servir a través de l'API d'Argos. Si en "
                                     "teniu una de pròpia, la podeu desar aquí.", text_color=COLOR_TEXT_MUTED)
        elif config["api_key"]:
            origin = "variable d'entorn GEMINI_API_KEY" if config["source"] == "entorn" else "perfil de l'usuari, permisos 600"
            self.ai_status.configure(text=f"Clau desada ({mask_key(config['api_key'])}, {origin}). Model: {config['model']}.",
                                     text_color=COLOR_TEXT_MUTED)
        else:
            self.ai_status.configure(text="No hi ha cap clau. Creeu-ne una a https://aistudio.google.com/apikey: es desa "
                                     "al perfil de l'usuari, mai al codi ni a l'expedient.", text_color=COLOR_DANGER)

    def _save_ai_key(self):
        key = self.ai_key_entry.get().strip()
        if not key:
            messagebox.showwarning("Falta la clau", "Enganxeu la clau de l'API de Gemini abans de desar-la.")
            return
        save_config(api_key=key)
        self.ai_key_entry.delete(0, "end")
        self._refresh_ai_status()
        self._check_ai()

    def _delete_ai_key(self):
        if messagebox.askyesno("Esborra la clau", "Voleu esborrar la clau de Gemini desada en aquest equip?"):
            delete_api_key()
            self._refresh_ai_status()

    def _check_ai(self):
        self.ai_check_btn.configure(state="disabled")
        self._refresh_ai_status("Comprovant la IA...")

        def worker():
            try:
                provider = AIAssistant().check()
                done = (f"La IA funciona: ha respost {provider}.", COLOR_SUCCESS)
            except AIError as exc:
                done = (str(exc), COLOR_DANGER)
            self.after(0, lambda: (self.ai_check_btn.configure(state="normal"), self._refresh_ai_status(*done)))

        threading.Thread(target=worker, daemon=True).start()

    def _export_company_report(self):
        if not self.app_state.has_results():
            messagebox.showinfo("Sense resultats", "Primer cal fer l'auditoria: no hi ha cap equip ni troballa.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".pdf", filetypes=[("Fitxer PDF", "*.pdf")], initialfile="informe_empresa.pdf"
        )
        if not path:
            return
        generator = self._get_generator()
        expedient = self.app_state.active_expedient or {}
        client = (expedient.get("empresa") or {}).get("nom", "")
        session, anonymize = self.app_state.session, self.anonymize_var.get()
        self.company_btn.configure(state="disabled", text="La IA està redactant l'informe...")
        self._refresh_ai_status("La IA està redactant l'informe senzill (pot trigar fins a un minut)...")

        def worker():
            try:
                report = AIAssistant().company_report(session, client, Anonymizer(session, enabled=anonymize))
                generator.generate_company_pdf(report, path, client)
            except AIError as exc:
                self.after(0, lambda msg=str(exc): self._company_report_done(None, msg))
                return
            except Exception as exc:  # noqa: BLE001 - p. ex. un error en escriure el PDF
                self.after(0, lambda msg=f"No s'ha pogut generar el PDF: {exc}": self._company_report_done(None, msg))
                return
            self.after(0, lambda: self._company_report_done(path, ""))

        threading.Thread(target=worker, daemon=True).start()

    def _company_report_done(self, path, error):
        self.company_btn.configure(state="normal", text="Genera l'informe per a l'empresa (PDF)")
        if error:
            self._refresh_ai_status(error, COLOR_DANGER)
            messagebox.showerror("Assistent d'IA", error)
            return
        self._refresh_ai_status(f"Informe per a l'empresa generat: {path}", COLOR_SUCCESS)
        self._set_status(f"Informe per a l'empresa generat: {path}")
        if messagebox.askyesno("Obrir informe", "Vols obrir l'informe generat ara mateix?"):
            webbrowser.open(f"file://{os.path.abspath(path)}")

    def set_target(self, target):
        self.target_entry.delete(0, "end")
        if target:
            self.target_entry.insert(0, target)

    def _get_generator(self):
        target = self.target_entry.get().strip()
        if target:
            self.app_state.session.target = target
        return ReportGenerator(self.app_state.session, COMPANY_NAME, APP_NAME, APP_VERSION)

    # ------------------------------------------------------------------ #
    # Portal de clients
    # ------------------------------------------------------------------ #
    def _open_portal_tab(self):
        self._get_generator()  # aplica l'objectiu escrit al camp de text
        if self.switch_tab:
            self.switch_tab("Expedients")

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
