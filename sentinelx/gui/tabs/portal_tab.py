"""Pestanya «Expedients»: connexió de SentinelX amb el portal de clients d'Argos.

Flux de treball:
  1. L'administrador inicia la sessió amb el seu usuari de la web (connexió directa) o obre el
     fitxer d'expedient descarregat del portal (mode fitxer, per a allotjaments com InfinityFree).
  2. Obre l'expedient de l'empresa: si ja té auditories, la darrera es fa servir com a referència
     i la sessió nova és una reauditoria amb el mateix objectiu.
  3. Mentre es fan els escaneigs, els resultats es desen automàticament a l'expedient com a
     esborrany (connexió directa) i es poden comparar amb l'auditoria anterior.
  4. En acabar, es publica per al client o s'exporta en un fitxer per pujar-lo al portal.
"""
import datetime
import hashlib
import json
import os
import tempfile
import threading
import tkinter
import webbrowser
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.expedient_io import ExpedientFileError, export_audit_file, load_expedient_file
from core.portal_client import (
    PortalAuthError, PortalBlockedError, PortalClient, PortalError, load_settings, save_settings,
)
from core.report_generator import ReportGenerator
from core.session_io import compare_sessions, session_from_report_data, session_to_dict
from gui.theme import (
    APP_NAME, APP_VERSION, COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_BORDER, COLOR_DANGER, COLOR_PRIMARY_DARK,
    COLOR_SUCCESS, COLOR_TEXT_MUTED, COMPANY_NAME, FONT_DISPLAY_FAMILY, PORTAL_URL,
)
from gui.widgets.diff_dialog import DiffDialog
from gui.widgets.log_console import LogConsole
from gui.widgets.portal_dialogs import LoginDialog, NewExpedientDialog

AUTO_SYNC_MS = 60_000
ALL_COMPANIES = "Totes les empreses"


class PortalTab(ctk.CTkFrame):
    def __init__(self, master, app_state, on_expedient_changed=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.on_expedient_changed = on_expedient_changed
        self.settings = load_settings()
        self.client = None
        self._companies = {}
        self._expedients = {}
        self._busy = False
        self._last_sync_hash = None
        self._build_ui()
        self.refresh()
        self.after(AUTO_SYNC_MS, self._auto_sync_tick)

    # ------------------------------------------------------------------ #
    # Interfície
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        body = ctk.CTkScrollableFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True)

        # 1. Connexió
        conn = ctk.CTkFrame(body, border_width=1, border_color=COLOR_BORDER)
        conn.pack(fill="x", padx=12, pady=(8, 10))
        conn.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(conn, text="Connexió amb el portal de clients", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).grid(row=0, column=0, columnspan=4, sticky="w", padx=16, pady=(12, 6))
        ctk.CTkLabel(conn, text="Adreça:").grid(row=1, column=0, sticky="w", padx=(16, 8), pady=4)
        self.url_entry = ctk.CTkEntry(conn)
        self.url_entry.grid(row=1, column=1, sticky="ew", pady=4)
        self.url_entry.insert(0, self.settings.get("url") or PORTAL_URL)
        self.login_btn = ctk.CTkButton(conn, text="Inicia la sessió", width=150, command=self._login,
                                       fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.login_btn.grid(row=1, column=2, padx=8, pady=4)
        self.logout_btn = ctk.CTkButton(conn, text="Tanca la sessió", width=130, command=self._logout,
                                        fg_color="transparent", border_width=1, border_color=COLOR_PRIMARY_DARK,
                                        text_color=COLOR_PRIMARY_DARK)
        self.logout_btn.grid(row=1, column=3, padx=(0, 16), pady=4)
        self.conn_status = ctk.CTkLabel(conn, text="", anchor="w", justify="left", wraplength=820)
        self.conn_status.grid(row=2, column=0, columnspan=4, sticky="w", padx=16, pady=(2, 4))
        file_row = ctk.CTkFrame(conn, fg_color="transparent")
        file_row.grid(row=3, column=0, columnspan=4, sticky="ew", padx=16, pady=(0, 12))
        ctk.CTkLabel(
            file_row, text="Sense connexió directa (p. ex. allotjament InfinityFree): descarregueu el fitxer "
            "de l'expedient des de la web i obriu-lo aquí.", text_color=COLOR_TEXT_MUTED, wraplength=600, justify="left",
        ).pack(side="left")
        ctk.CTkButton(file_row, text="Obre un fitxer d'expedient...", width=210, command=self._open_file).pack(side="right")

        # 2. Expedients del portal
        browse = ctk.CTkFrame(body, border_width=1, border_color=COLOR_BORDER)
        browse.pack(fill="x", padx=12, pady=(0, 10))
        head = ctk.CTkFrame(browse, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(12, 6))
        ctk.CTkLabel(head, text="Expedients", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(side="left")
        self.new_btn = ctk.CTkButton(head, text="Nou expedient...", width=140, command=self._new_expedient)
        self.new_btn.pack(side="right")
        self.refresh_btn = ctk.CTkButton(head, text="Actualitza", width=100, command=self._load_lists,
                                         fg_color="transparent", border_width=1, border_color=COLOR_PRIMARY_DARK,
                                         text_color=COLOR_PRIMARY_DARK)
        self.refresh_btn.pack(side="right", padx=8)
        self.company_menu = ctk.CTkOptionMenu(head, values=[ALL_COMPANIES], width=260, dynamic_resizing=False,
                                              command=lambda _v: self._load_expedients())
        self.company_menu.pack(side="right")

        columns = ("codi", "titol", "empresa", "estat", "auditories", "darrera")
        self.tree = ttk.Treeview(browse, columns=columns, show="headings", height=6, selectmode="browse")
        for col, text, width in (("codi", "Codi", 120), ("titol", "Expedient", 260), ("empresa", "Empresa", 190),
                                 ("estat", "Estat", 70), ("auditories", "Auditories", 80), ("darrera", "Darrera auditoria", 140)):
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="x", padx=16, pady=(0, 8))
        self.tree.bind("<Double-1>", lambda _e: self._open_selected())
        self.open_btn = ctk.CTkButton(browse, text="Obre l'expedient seleccionat", command=self._open_selected,
                                      fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.open_btn.pack(anchor="e", padx=16, pady=(0, 12))

        # 3. Expedient actiu
        active = ctk.CTkFrame(body, border_width=2, border_color=COLOR_ACCENT)
        active.pack(fill="x", padx=12, pady=(0, 10))
        ctk.CTkLabel(active, text="Expedient actiu", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(anchor="w", padx=16, pady=(12, 2))
        self.active_title = ctk.CTkLabel(active, text="", font=(FONT_DISPLAY_FAMILY, 14, "bold"), anchor="w", justify="left")
        self.active_title.pack(anchor="w", padx=16)
        self.active_info = ctk.CTkLabel(active, text="", text_color=COLOR_TEXT_MUTED, anchor="w", justify="left", wraplength=840)
        self.active_info.pack(anchor="w", padx=16, pady=(2, 8))

        options = ctk.CTkFrame(active, fg_color="transparent")
        options.pack(fill="x", padx=16)
        self.auto_var = ctk.BooleanVar(value=self.settings.get("sincronitzacio_automatica", True))
        ctk.CTkCheckBox(options, text="Desa automàticament els resultats a l'expedient (connexió directa)",
                        variable=self.auto_var, command=self._save_preferences).pack(side="left")
        self.pdf_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(options, text="Inclou l'informe PDF en desar o exportar", variable=self.pdf_var).pack(side="left", padx=16)

        actions = ctk.CTkFrame(active, fg_color="transparent")
        actions.pack(fill="x", padx=16, pady=(10, 14))
        self.compare_btn = ctk.CTkButton(actions, text="Compara amb l'auditoria anterior", command=self._compare)
        self.compare_btn.grid(row=0, column=0, padx=(0, 8), pady=4)
        self.save_btn = ctk.CTkButton(actions, text="Desa al portal ara", command=lambda: self._save(publish=False))
        self.save_btn.grid(row=0, column=1, padx=8, pady=4)
        self.publish_btn = ctk.CTkButton(actions, text="Publica per al client", command=lambda: self._save(publish=True),
                                         fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.publish_btn.grid(row=0, column=2, padx=8, pady=4)
        self.export_btn = ctk.CTkButton(actions, text="Exporta per al portal...", command=self._export_file)
        self.export_btn.grid(row=0, column=3, padx=8, pady=4)
        self.close_btn = ctk.CTkButton(actions, text="Tanca l'expedient", command=self._close_expedient,
                                       fg_color="transparent", border_width=1, border_color=COLOR_DANGER, text_color=COLOR_DANGER)
        self.close_btn.grid(row=0, column=4, padx=8, pady=4)

        self.progress = ctk.CTkProgressBar(body, mode="indeterminate", height=6)
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)
        self.log_console = LogConsole(body, height=150)
        self.log_console.pack(fill="x", padx=12, pady=(0, 12))

    # ------------------------------------------------------------------ #
    # Estat de la interfície
    # ------------------------------------------------------------------ #
    def refresh(self):
        connected = self.client is not None and self.client.logged_in
        if connected:
            user = self.client.user or {}
            until = self.client.expires_at[11:16] if self.client.expires_at else ""
            self.conn_status.configure(
                text=f"Connectat com a {user.get('nom', '')} ({user.get('email', '')})" + (f" · sessió fins a les {until}" if until else ""),
                text_color=COLOR_SUCCESS,
            )
        else:
            self.conn_status.configure(text="Sense sessió iniciada.", text_color=COLOR_TEXT_MUTED)
        self.login_btn.configure(state="disabled" if connected or self._busy else "normal")
        self.logout_btn.configure(state="normal" if connected and not self._busy else "disabled")
        for button in (self.new_btn, self.refresh_btn, self.open_btn):
            button.configure(state="normal" if connected and not self._busy else "disabled")
        self.company_menu.configure(state="normal" if connected else "disabled")
        self._refresh_active()

    def _refresh_active(self):
        expedient = self.app_state.active_expedient
        if not expedient:
            self.active_title.configure(text="Cap expedient obert", text_color=COLOR_TEXT_MUTED)
            self.active_info.configure(text="Obriu un expedient del portal per desar-hi l'auditoria o fer-ne la reauditoria.")
            for button in (self.compare_btn, self.save_btn, self.publish_btn, self.export_btn, self.close_btn):
                button.configure(state="disabled")
            return

        company = (expedient.get("empresa") or {}).get("nom", "")
        mode = "connexió directa" if self.app_state.portal_mode == "api" else "mode fitxer"
        self.active_title.configure(text=f"{expedient.get('codi', '')} · {expedient.get('titol', '')} · {company}",
                                    text_color=COLOR_PRIMARY_DARK)
        stats = self.app_state.dashboard_stats()
        lines = [f"Objectiu: {self.app_state.session.target or expedient.get('objectiu') or 'no definit'} · {mode}"]
        if self.app_state.baseline_session is not None:
            base_findings = sum(len(s.vulnerabilities) for h in self.app_state.baseline_session.hosts for s in h.services)
            lines.append(f"Reauditoria respecte de: «{self.app_state.baseline_title}» ({base_findings} troballes de xarxa)")
        else:
            lines.append("Auditoria inicial (l'expedient encara no tenia cap auditoria).")
        lines.append(f"Resultats actuals: {stats['total_hosts']} equips, {stats['total_findings']} troballes"
                     + (f" · esborrany al portal #{self.app_state.portal_draft_id}" if self.app_state.portal_draft_id else ""))
        self.active_info.configure(text="\n".join(lines))

        api_ready = self.app_state.portal_mode == "api" and self.client is not None and self.client.logged_in
        has_results = self.app_state.has_results()
        idle = not self._busy
        self.compare_btn.configure(state="normal" if self.app_state.baseline_session is not None and has_results and idle else "disabled")
        self.save_btn.configure(state="normal" if api_ready and has_results and idle else "disabled")
        self.publish_btn.configure(state="normal" if api_ready and has_results and idle else "disabled")
        self.export_btn.configure(state="normal" if has_results and idle else "disabled")
        self.close_btn.configure(state="normal" if idle else "disabled")

    def _set_busy(self, busy):
        self._busy = busy
        if busy:
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.set(0)
        self.refresh()

    def _ui(self, callback):
        try:
            self.after(0, callback)
        except (RuntimeError, tkinter.TclError):
            pass

    def _log(self, message):
        self.log_console.log(message)

    def _run(self, description, task, on_success, quiet=False):
        """Executa una crida al portal en un fil i en mostra el resultat o l'error."""
        if self._busy:
            return
        self._set_busy(True)
        if not quiet:
            self._log(description)

        def worker():
            try:
                result = task()
            except PortalError as exc:
                self._ui(lambda e=exc: self._on_error(e, quiet))
                return
            except Exception as exc:  # noqa: BLE001 - qualsevol error inesperat es mostra a l'usuari
                self._ui(lambda e=exc: self._on_error(PortalError(f"Error inesperat: {e}"), quiet))
                return
            self._ui(lambda: self._finish(on_success, result))

        threading.Thread(target=worker, daemon=True).start()

    def _finish(self, callback, result):
        self._set_busy(False)
        callback(result)

    def _on_error(self, exc, quiet=False):
        self._set_busy(False)
        self._log(f"[ERROR] {exc}")
        if isinstance(exc, PortalAuthError) and self.client is not None:
            self.client.token = ""
            self.refresh()
            if not quiet:
                messagebox.showwarning("Sessió caducada", f"{exc}\n\nTorneu a iniciar la sessió.", parent=self)
            return
        if not quiet:
            title = "Connexió no permesa" if isinstance(exc, PortalBlockedError) else "Error del portal"
            messagebox.showerror(title, str(exc), parent=self)

    def _save_preferences(self):
        self.settings["sincronitzacio_automatica"] = bool(self.auto_var.get())
        try:
            save_settings(self.settings)
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # Sessió
    # ------------------------------------------------------------------ #
    def _login(self):
        try:
            client = PortalClient(self.url_entry.get(), user_agent=f"SentinelX/{APP_VERSION}")
        except PortalError as exc:
            messagebox.showerror("Adreça no vàlida", str(exc), parent=self)
            return
        LoginDialog(self, client, email=self.settings.get("email", ""), on_success=self._on_logged_in)

    def _on_logged_in(self, client, email):
        self.client = client
        self.settings.update({"url": client.base_url, "email": email})
        self._save_preferences()
        self._log(f"Sessió iniciada a {client.base_url} com a {(client.user or {}).get('nom', email)}.")
        if self.app_state.active_expedient and self.app_state.portal_mode == "fitxer":
            self.app_state.portal_mode = "api"
            self._log("L'expedient obert des de fitxer ara es desarà directament al portal.")
        self.refresh()
        self._load_lists()

    def _logout(self):
        client = self.client

        def done(_result):
            self.client = None
            self._log("Sessió tancada.")
            self.tree.delete(*self.tree.get_children())
            self.refresh()

        self._run("Tancant la sessió...", lambda: client.logout(), done)

    # ------------------------------------------------------------------ #
    # Empreses i expedients
    # ------------------------------------------------------------------ #
    def _selected_company_id(self):
        return self._companies.get(self.company_menu.get())

    def _load_lists(self):
        client = self.client

        def task():
            return client.list_companies(), client.list_expedients()

        def done(result):
            companies, expedients = result
            self._companies = {f"{c['nom']} (#{c['id']})": c["id"] for c in companies}
            current = self.company_menu.get()
            self.company_menu.configure(values=[ALL_COMPANIES] + list(self._companies))
            if current not in self._companies:
                self.company_menu.set(ALL_COMPANIES)
            self._fill_tree(expedients if self._selected_company_id() is None
                            else [e for e in expedients if e["empresa"]["id"] == self._selected_company_id()])
            self._log(f"{len(companies)} empresa(es) i {len(expedients)} expedient(s) al portal.")

        self._run("Carregant les empreses i els expedients del portal...", task, done)

    def _load_expedients(self):
        if self.client is None:
            return
        client = self.client
        company_id = self._selected_company_id()
        self._run("Carregant els expedients...", lambda: client.list_expedients(company_id=company_id), self._fill_tree, quiet=True)

    def _fill_tree(self, expedients):
        self.tree.delete(*self.tree.get_children())
        self._expedients = {}
        for expedient in expedients:
            item = self.tree.insert("", "end", values=(
                expedient["codi"], expedient["titol"], expedient["empresa"]["nom"],
                "Obert" if expedient["estat"] == "obert" else "Tancat", expedient["n_auditories"],
                (expedient.get("darrera_auditoria") or "")[:16] or "—",
            ))
            self._expedients[item] = expedient

    def _new_expedient(self):
        if not self._companies:
            messagebox.showinfo("Sense empreses", "Primer cal crear l'empresa client a la web (Administració → Empreses).", parent=self)
            return
        companies = [{"id": cid, "nom": label.rsplit(" (#", 1)[0]} for label, cid in self._companies.items()]
        NewExpedientDialog(self, self.client, companies, company_id=self._selected_company_id(),
                           target=self.app_state.session.target, on_created=self._on_expedient_created)

    def _on_expedient_created(self, expedient):
        self._log(f"Expedient {expedient['codi']} creat per a {expedient['empresa']['nom']}.")
        self._load_lists()
        if messagebox.askyesno("Expedient creat", f"S'ha creat l'expedient {expedient['codi']}. Voleu obrir-lo ara?", parent=self):
            self._activate(expedient, None, "", "api")

    def _open_selected(self):
        selection = self.tree.selection()
        if not selection:
            messagebox.showinfo("Cap expedient seleccionat", "Seleccioneu un expedient de la llista.", parent=self)
            return
        summary = self._expedients.get(selection[0])
        client = self.client

        def task():
            detail = client.get_expedient(summary["id"])
            audits = detail.get("auditories") or []
            if not audits:
                return detail, None, ""
            report = client.get_report(audits[-1]["id"])
            return detail, session_from_report_data(report.get("dades") or {}), report.get("titol", "")

        self._run(f"Obrint l'expedient {summary['codi']}...", task, lambda r: self._activate(r[0], r[1], r[2], "api"))

    def _open_file(self):
        path = filedialog.askopenfilename(
            title="Obre un fitxer d'expedient", filetypes=[("Expedient del portal", "*.json"), ("Tots els fitxers", "*.*")],
        )
        if not path:
            return
        try:
            info = load_expedient_file(path)
        except ExpedientFileError as exc:
            messagebox.showerror("Fitxer no vàlid", str(exc), parent=self)
            return
        if info["portal"] and not self.url_entry.get().strip():
            self.url_entry.insert(0, info["portal"])
        mode = "api" if self.client is not None and self.client.logged_in else "fitxer"
        self._activate(info["expedient"], info["baseline"], info["baseline_title"], mode)

    def _activate(self, expedient, baseline, baseline_title, mode):
        keep = False
        if self.app_state.has_results():
            answer = messagebox.askyesnocancel(
                "Resultats a la sessió actual",
                "Hi ha resultats d'escaneig a la sessió actual.\n\n"
                "Sí: associa'ls a aquest expedient.\n"
                "No: comença una auditoria nova (es descarten els resultats actuals).",
                parent=self,
            )
            if answer is None:
                return
            keep = answer
        self.app_state.open_expedient(expedient, baseline, baseline_title, mode, keep_results=keep)
        self._last_sync_hash = None
        kind = "reauditoria" if baseline is not None else "auditoria inicial"
        self._log(f"Expedient {expedient.get('codi')} obert ({kind}, {'connexió directa' if mode == 'api' else 'mode fitxer'}).")
        if baseline is not None:
            self._log("Feu els escaneigs i premeu «Compara amb l'auditoria anterior» per veure què s'ha corregit.")
        self.refresh()
        if self.on_expedient_changed:
            self.on_expedient_changed()

    def _close_expedient(self):
        if not messagebox.askyesno("Tanca l'expedient",
                                   "Es deixarà de treballar amb aquest expedient. Els resultats de la sessió es conserven. Voleu continuar?",
                                   parent=self):
            return
        code = (self.app_state.active_expedient or {}).get("codi", "")
        self.app_state.close_expedient()
        self._log(f"Expedient {code} tancat a SentinelX.")
        self.refresh()
        if self.on_expedient_changed:
            self.on_expedient_changed()

    # ------------------------------------------------------------------ #
    # Comparació, desament i exportació
    # ------------------------------------------------------------------ #
    def _compare(self):
        diff = compare_sessions(self.app_state.session, self.app_state.baseline_session)
        DiffDialog(self, diff, baseline_target=self.app_state.baseline_title)

    def _generator(self):
        return ReportGenerator(self.app_state.session, COMPANY_NAME, APP_NAME, APP_VERSION)

    def _default_title(self):
        expedient = self.app_state.active_expedient or {}
        kind = "Reauditoria" if self.app_state.baseline_session is not None else "Auditoria"
        return f"{kind} · {expedient.get('titol', 'infraestructura')} · {datetime.date.today().strftime('%d/%m/%Y')}"

    def _session_hash(self):
        data = json.dumps(session_to_dict(self.app_state.session), sort_keys=True, default=str)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()

    def _save(self, publish=False, quiet=False):
        expedient = self.app_state.active_expedient
        if not expedient or self.client is None or not self.client.logged_in:
            return
        if publish and not messagebox.askyesno(
            "Publica per al client",
            f"Es publicarà l'auditoria a l'expedient {expedient.get('codi')} i el client la podrà consultar "
            "a l'Àrea de clients. Recordeu revisar-ne abans les troballes. Voleu continuar?",
            parent=self,
        ):
            return
        client = self.client
        generator = self._generator()
        title = self._default_title()
        draft_id = self.app_state.portal_draft_id
        with_pdf = bool(self.pdf_var.get()) and not quiet
        session_hash = self._session_hash()

        def task():
            report_data = generator.build_report_data()
            pdf_bytes = self._build_pdf(generator) if with_pdf else None
            try:
                return client.save_audit(expedient["id"], report_data, title, publish, pdf_bytes, report_id=draft_id)
            except PortalError as exc:
                # L'esborrany s'ha publicat o esborrat des de la web: se'n crea un de nou
                if draft_id and ("publicat" in str(exc) or "no correspon" in str(exc)):
                    return client.save_audit(expedient["id"], report_data, title, publish, pdf_bytes)
                raise

        def done(result):
            report = result.get("informe") or {}
            self.app_state.portal_draft_id = None if publish else report.get("id")
            self._last_sync_hash = session_hash
            now = datetime.datetime.now().strftime("%H:%M")
            self._log(f"{'Publicada' if publish else 'Desada'} a l'expedient (informe #{report.get('id')}) a les {now}.")
            self.refresh()
            if publish:
                url = report.get("url_admin") or report.get("url_client")
                if url and messagebox.askyesno("Auditoria publicada", f"{result.get('missatge', '')}\n\nVoleu obrir-la al navegador?", parent=self):
                    webbrowser.open(url)

        self._run("Desant l'auditoria al portal..." if not publish else "Publicant l'auditoria...", task, done, quiet=quiet)

    def _auto_sync_tick(self):
        try:
            if (self.auto_var.get() and not self._busy and self.app_state.active_expedient
                    and self.app_state.portal_mode == "api" and self.client is not None and self.client.logged_in
                    and self.app_state.has_results() and self._session_hash() != self._last_sync_hash):
                self._save(publish=False, quiet=True)
        finally:
            self.after(AUTO_SYNC_MS, self._auto_sync_tick)

    def _export_file(self):
        expedient = self.app_state.active_expedient or {}
        default = f"auditoria-{(expedient.get('codi') or 'sentinelx').lower()}-{datetime.date.today():%Y%m%d}.json"
        path = filedialog.asksaveasfilename(
            title="Exporta l'auditoria per al portal", defaultextension=".json", initialfile=default,
            filetypes=[("Auditoria per al portal", "*.json")],
        )
        if not path:
            return
        generator = self._generator()
        title = self._default_title()
        with_pdf = bool(self.pdf_var.get())

        def task():
            pdf_bytes = self._build_pdf(generator) if with_pdf else None
            return export_audit_file(path, expedient, generator.build_report_data(), title, pdf_bytes)

        def done(saved_path):
            self._log(f"Auditoria exportada a {saved_path}.")
            messagebox.showinfo(
                "Auditoria exportada",
                f"S'ha desat el fitxer:\n{saved_path}\n\nPugeu-lo a la web: Administració → Informes → Puja una auditoria. "
                "Quedarà vinculat a l'expedient automàticament.",
                parent=self,
            )

        self._run("Exportant l'auditoria...", task, done)

    @staticmethod
    def _build_pdf(generator):
        """Genera l'informe en PDF en un fitxer temporal i en retorna el contingut (o None sense ReportLab)."""
        fd, path = tempfile.mkstemp(suffix=".pdf", prefix="sentinelx_")
        os.close(fd)
        try:
            generator.generate_pdf(path)
            with open(path, "rb") as f:
                return f.read()
        except ImportError:
            return None
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
