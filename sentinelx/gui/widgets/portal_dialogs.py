"""Diàlegs de la pestanya Expedients: inici de sessió al portal i creació d'expedients."""
import socket
import threading
import tkinter

import customtkinter as ctk

from core.portal_client import PortalBlockedError, PortalError
from gui.theme import (
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_PRIMARY_DARK, COLOR_TEXT_MUTED, FONT_DISPLAY_FAMILY,
)


class _PortalDialog(ctk.CTkToplevel):
    """Base comuna: finestra modal i execució de tasques en un fil sense bloquejar la interfície."""

    def __init__(self, master, title, geometry):
        super().__init__(master)
        self.title(title)
        self.geometry(geometry)
        self.resizable(False, False)
        self.transient(master.winfo_toplevel())
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(150, self._grab)

    def _grab(self):
        try:
            self.grab_set()
        except tkinter.TclError:
            pass

    def _ui(self, callback):
        try:
            self.after(0, callback)
        except (RuntimeError, tkinter.TclError):
            pass  # la finestra ja s'ha tancat

    def _run(self, task, on_success, on_error):
        def worker():
            try:
                result = task()
            except PortalError as exc:
                self._ui(lambda e=exc: on_error(e))
                return
            self._ui(lambda: on_success(result))

        threading.Thread(target=worker, daemon=True).start()

    def _close(self):
        try:
            self.grab_release()
        except tkinter.TclError:
            pass
        self.destroy()


class LoginDialog(_PortalDialog):
    """Inici de sessió amb un usuari administrador de la web."""

    def __init__(self, master, client, email="", on_success=None):
        super().__init__(master, "Inicia la sessió al portal", "460x440")
        self.client = client
        self.on_success = on_success

        ctk.CTkLabel(self, text="Inicia la sessió al portal", font=(FONT_DISPLAY_FAMILY, 18, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(anchor="w", padx=24, pady=(20, 2))
        ctk.CTkLabel(self, text=f"Feu servir el vostre usuari administrador de {client.base_url}.",
                     text_color=COLOR_TEXT_MUTED, wraplength=400, justify="left").pack(anchor="w", padx=24, pady=(0, 14))

        ctk.CTkLabel(self, text="Correu electrònic").pack(anchor="w", padx=24)
        self.email_entry = ctk.CTkEntry(self, width=410)
        self.email_entry.pack(padx=24, pady=(2, 10))
        self.email_entry.insert(0, email)
        ctk.CTkLabel(self, text="Contrasenya").pack(anchor="w", padx=24)
        self.password_entry = ctk.CTkEntry(self, width=410, show="•")
        self.password_entry.pack(padx=24, pady=(2, 10))
        ctk.CTkLabel(self, text="Nom d'aquest equip (apareix al registre del portal)").pack(anchor="w", padx=24)
        self.device_entry = ctk.CTkEntry(self, width=410)
        self.device_entry.pack(padx=24, pady=(2, 10))
        self.device_entry.insert(0, socket.gethostname())

        self.status = ctk.CTkLabel(self, text="", text_color=COLOR_DANGER, wraplength=410, justify="left")
        self.status.pack(anchor="w", padx=24, pady=(2, 6))
        self.login_btn = ctk.CTkButton(self, text="Inicia la sessió", command=self._submit, width=410,
                                       fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.login_btn.pack(padx=24, pady=(4, 16))

        self.bind("<Return>", lambda _e: self._submit())
        (self.password_entry if email else self.email_entry).focus_set()

    def _submit(self):
        email = self.email_entry.get().strip()
        password = self.password_entry.get()
        if not email or not password:
            self.status.configure(text="Escriviu el correu i la contrasenya.")
            return
        self.login_btn.configure(state="disabled", text="Connectant...")
        self.status.configure(text="")
        device = self.device_entry.get().strip()
        self._run(lambda: self.client.login(email, password, device), self._on_logged_in, self._on_error)

    def _on_logged_in(self, _result):
        self._close()
        if self.on_success:
            self.on_success(self.client, self.email_entry.get().strip())

    def _on_error(self, exc):
        self.login_btn.configure(state="normal", text="Inicia la sessió")
        self.password_entry.delete(0, "end")
        message = str(exc)
        if isinstance(exc, PortalBlockedError):
            message += "\n\nTanqueu aquesta finestra i feu servir «Obre un fitxer d'expedient»."
        self.status.configure(text=message)


class NewExpedientDialog(_PortalDialog):
    """Creació d'un expedient nou al portal per a una empresa client."""

    def __init__(self, master, client, companies, company_id=None, target="", on_created=None):
        super().__init__(master, "Nou expedient", "500x500")
        self.client = client
        self.on_created = on_created
        self.companies = {f"{c['nom']} (#{c['id']})": c["id"] for c in companies}

        ctk.CTkLabel(self, text="Nou expedient d'auditoria", font=(FONT_DISPLAY_FAMILY, 18, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(anchor="w", padx=24, pady=(20, 2))
        ctk.CTkLabel(self, text="L'expedient agruparà l'auditoria inicial i les reauditories d'aquest encàrrec.",
                     text_color=COLOR_TEXT_MUTED, wraplength=450, justify="left").pack(anchor="w", padx=24, pady=(0, 14))

        ctk.CTkLabel(self, text="Empresa client").pack(anchor="w", padx=24)
        labels = list(self.companies) or ["(no hi ha cap empresa activa)"]
        self.company_menu = ctk.CTkOptionMenu(self, values=labels, width=450, dynamic_resizing=False)
        self.company_menu.pack(padx=24, pady=(2, 10))
        selected = next((label for label, cid in self.companies.items() if cid == company_id), labels[0])
        self.company_menu.set(selected)

        ctk.CTkLabel(self, text="Títol").pack(anchor="w", padx=24)
        self.title_entry = ctk.CTkEntry(self, width=450, placeholder_text="Auditoria de la xarxa interna")
        self.title_entry.pack(padx=24, pady=(2, 10))
        ctk.CTkLabel(self, text="Objectiu o abast").pack(anchor="w", padx=24)
        self.target_entry = ctk.CTkEntry(self, width=450, placeholder_text="192.168.1.0/24")
        self.target_entry.pack(padx=24, pady=(2, 10))
        if target:
            self.target_entry.insert(0, target)
        ctk.CTkLabel(self, text="Notes internes (opcional)").pack(anchor="w", padx=24)
        self.notes_entry = ctk.CTkEntry(self, width=450)
        self.notes_entry.pack(padx=24, pady=(2, 10))

        self.status = ctk.CTkLabel(self, text="", text_color=COLOR_DANGER, wraplength=450, justify="left")
        self.status.pack(anchor="w", padx=24, pady=(2, 6))
        self.create_btn = ctk.CTkButton(self, text="Crea l'expedient", command=self._submit, width=450,
                                        fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER, text_color=COLOR_PRIMARY_DARK)
        self.create_btn.pack(padx=24, pady=(4, 16))
        self.title_entry.focus_set()

    def _submit(self):
        company_id = self.companies.get(self.company_menu.get())
        title = self.title_entry.get().strip()
        if company_id is None:
            self.status.configure(text="Primer cal crear l'empresa client a la web (Administració → Empreses).")
            return
        if not title:
            self.status.configure(text="Escriviu el títol de l'expedient.")
            return
        self.create_btn.configure(state="disabled", text="Creant...")
        target = self.target_entry.get().strip()
        notes = self.notes_entry.get().strip()
        self._run(lambda: self.client.create_expedient(company_id, title, target, notes), self._on_created, self._on_error)

    def _on_created(self, expedient):
        self._close()
        if self.on_created:
            self.on_created(expedient)

    def _on_error(self, exc):
        self.create_btn.configure(state="normal", text="Crea l'expedient")
        self.status.configure(text=str(exc))
