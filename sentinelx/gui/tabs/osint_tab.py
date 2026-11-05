"""Pestanya «OSINT»: cerca d'informació pública d'un domini amb The Harvester.

Flux de treball (el mateix que l'opció 5 de shodan_recon.py):
  1. Es demana el domini objectiu i la font de dades (google, bing, linkedin o all).
  2. Opcionalment es tria un fitxer on desar els resultats (paràmetre -f, en XML i JSON).
  3. Es construeix la cadena de la comanda, que es mostra abans d'executar-la.
  4. S'executa amb subprocess i la sortida es mostra en temps real a la consola.
"""
import os
import re
from tkinter import filedialog, messagebox, ttk

import customtkinter as ctk

from core.harvester import (
    DEFAULT_LIMIT, DEFAULT_SOURCE, INSTALL_HINT, SOURCES, HarvesterError, build_command, check_source,
    command_name, find_executable, output_files, summarize, validate_domain,
)
from gui.theme import (
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_BORDER, COLOR_DANGER, COLOR_PRIMARY_DARK, COLOR_SUCCESS,
    COLOR_TEXT_MUTED, FONT_DISPLAY_FAMILY, FONT_MONO_FAMILY,
)
from gui.widgets.log_console import LogConsole
from utils.shell import CommandRunner

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
# Línies de resum de The Harvester, p. ex. «[*] Hosts found: 12»
_FOUND_RE = re.compile(r"^\[\*\]\s+(.+?)\s+found:\s*(\d+)", re.IGNORECASE)


class OsintTab(ctk.CTkFrame):
    def __init__(self, master, app_state, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.runner = CommandRunner()
        self._running = False
        self._found = []
        self._files = None
        self.executable = None
        self._build_ui()
        self._refresh_tool()
        self._update_command()

    # ------------------------------------------------------------------ #
    # Interfície
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        outline = {"fg_color": "transparent", "border_width": 1, "border_color": COLOR_PRIMARY_DARK,
                   "text_color": COLOR_PRIMARY_DARK}
        accent = {"fg_color": COLOR_ACCENT, "hover_color": COLOR_ACCENT_HOVER, "text_color": COLOR_PRIMARY_DARK}

        card = ctk.CTkFrame(self, border_width=1, border_color=COLOR_BORDER)
        card.pack(fill="x", padx=12, pady=(8, 6))
        card.grid_columnconfigure(4, weight=1)
        head = ctk.CTkFrame(card, fg_color="transparent")
        head.grid(row=0, column=0, columnspan=6, sticky="ew", padx=16, pady=(10, 2))
        ctk.CTkLabel(head, text="Cerca OSINT amb The Harvester", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(side="left")
        ctk.CTkLabel(head, text="   Correus, subdominis i IP a partir de fonts públiques: no s'escaneja l'objectiu.",
                     text_color=COLOR_TEXT_MUTED).pack(side="left")
        self.tool_label = ctk.CTkLabel(card, text="", anchor="w", justify="left", wraplength=1050)
        self.tool_label.grid(row=1, column=0, columnspan=6, sticky="w", padx=16, pady=(0, 6))

        ctk.CTkLabel(card, text="Domini objectiu:").grid(row=2, column=0, sticky="w", padx=(16, 8), pady=4)
        self.domain_entry = ctk.CTkEntry(card, width=220, placeholder_text="ex. iesebre.cat")
        self.domain_entry.grid(row=2, column=1, sticky="w", pady=4)
        self.domain_entry.bind("<KeyRelease>", lambda _e: self._update_command())
        self.domain_entry.bind("<Return>", lambda _e: self._run())
        ctk.CTkLabel(card, text="Font de dades:").grid(row=2, column=2, sticky="w", padx=(16, 8), pady=4)
        self.source_var = ctk.StringVar(value=DEFAULT_SOURCE)
        ctk.CTkOptionMenu(card, values=list(SOURCES), variable=self.source_var, width=140,
                          command=lambda _v: self._update_command()).grid(row=2, column=3, sticky="w", pady=4)

        self.save_var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(card, text="Desa els resultats en un fitxer (XML i JSON)", variable=self.save_var,
                        command=self._on_save_toggled).grid(row=3, column=0, columnspan=2, sticky="w",
                                                            padx=(16, 8), pady=4)
        self.file_entry = ctk.CTkEntry(card, placeholder_text="Nom o ruta del fitxer, sense extensió")
        self.file_entry.grid(row=3, column=2, columnspan=3, sticky="ew", padx=(16, 8), pady=4)
        self.file_entry.bind("<KeyRelease>", lambda _e: self._update_command())
        self.browse_btn = ctk.CTkButton(card, text="Tria...", width=80, command=self._browse, **outline)
        self.browse_btn.grid(row=3, column=5, sticky="w", padx=(0, 16), pady=4)

        # La comanda ocupa tota l'amplada perquè es vegi sencera, també amb rutes de fitxer llargues
        ctk.CTkLabel(card, text="Comanda:").grid(row=4, column=0, sticky="w", padx=(16, 8), pady=4)
        self.command_entry = ctk.CTkEntry(card, font=(FONT_MONO_FAMILY, 12))
        self.command_entry.grid(row=4, column=1, columnspan=5, sticky="ew", padx=(0, 16), pady=4)
        buttons = ctk.CTkFrame(card, fg_color="transparent")
        buttons.grid(row=5, column=0, columnspan=6, sticky="e", padx=16, pady=(4, 12))
        self.run_btn = ctk.CTkButton(buttons, text="Llança The Harvester", width=170, command=self._run, **accent)
        self.run_btn.pack(side="left")
        self.stop_btn = ctk.CTkButton(buttons, text="Atura", width=80, command=self._stop, state="disabled", **outline)
        self.stop_btn.pack(side="left", padx=(8, 0))
        self._on_save_toggled()

        self.progress = ctk.CTkProgressBar(self, mode="determinate", height=6)
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)

        self.status_label = ctk.CTkLabel(self, text="Preparat.", anchor="w")
        self.status_label.pack(side="bottom", fill="x", padx=12, pady=(2, 6))

        results = ctk.CTkFrame(self, fg_color="transparent")
        results.pack(fill="both", expand=True, padx=12)
        results.grid_columnconfigure(0, weight=1)
        results.grid_columnconfigure(1, weight=0, minsize=330)  # amplada fixa: no es mou en mostrar el resum
        results.grid_rowconfigure(0, weight=1)
        self.log_console = LogConsole(results)
        self.log_console.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        summary = ctk.CTkFrame(results)
        summary.grid(row=0, column=1, sticky="nsew")
        ctk.CTkLabel(summary, text="RESUM", text_color=COLOR_TEXT_MUTED,
                     font=(FONT_DISPLAY_FAMILY, 10, "bold")).pack(anchor="w", padx=10, pady=(8, 2))
        self.tree = ttk.Treeview(summary, columns=("tipus", "nombre"), show="headings", height=8, selectmode="none")
        self.tree.heading("tipus", text="Resultat")
        self.tree.heading("nombre", text="Nombre")
        self.tree.column("tipus", width=170, anchor="w")
        self.tree.column("nombre", width=70, anchor="e")
        self.tree.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.files_label = ctk.CTkLabel(summary, text="", anchor="w", justify="left", wraplength=310,
                                        text_color=COLOR_TEXT_MUTED)
        self.files_label.pack(fill="x", padx=10, pady=(0, 8))

    def _set_status(self, text, color=None):
        self.status_label.configure(text=text, text_color=color or COLOR_PRIMARY_DARK)

    def _refresh_tool(self):
        self.executable = find_executable()
        if self.executable:
            self.tool_label.configure(text=f"The Harvester: {self.executable}", text_color=COLOR_TEXT_MUTED)
        else:
            self.tool_label.configure(text=INSTALL_HINT, text_color=COLOR_DANGER)
        self.run_btn.configure(state="normal" if self.executable and not self._running else "disabled")

    def _on_save_toggled(self):
        state = "normal" if self.save_var.get() else "disabled"
        self.file_entry.configure(state=state)
        self.browse_btn.configure(state=state)
        self._update_command()

    def _browse(self):
        path = filedialog.asksaveasfilename(title="Desa els resultats de The Harvester", initialfile="resultats-osint",
                                            filetypes=[("XML i JSON", "*.xml *.json")])
        if path:
            self.file_entry.delete(0, "end")
            self.file_entry.insert(0, os.path.splitext(path)[0])
            self._update_command()

    def _filename(self):
        return self.file_entry.get().strip() if self.save_var.get() else ""

    def _update_command(self):
        """Mostra la cadena de la comanda tal com s'executarà."""
        domain = self.domain_entry.get().strip().lower() or "<domini>"
        command = build_command(domain, self.source_var.get(), self._filename(), DEFAULT_LIMIT,
                                command_name(self.executable) if self.executable else "theHarvester")
        self.command_entry.configure(state="normal")
        self.command_entry.delete(0, "end")
        self.command_entry.insert(0, command)
        self.command_entry.configure(state="readonly")

    # ------------------------------------------------------------------ #
    # Execució
    # ------------------------------------------------------------------ #
    def _run(self):
        if self._running:
            return
        self._refresh_tool()
        if not self.executable:
            messagebox.showwarning("Falta The Harvester", INSTALL_HINT)
            return
        try:
            domain = validate_domain(self.domain_entry.get())
            source = self.source_var.get()
            check_source(self.executable, source)
        except HarvesterError as exc:
            self._set_status(str(exc), COLOR_DANGER)
            return
        filename = self._filename()
        if self.save_var.get() and not filename:
            self._set_status("Escriviu el nom del fitxer o desmarqueu «Desa els resultats».", COLOR_DANGER)
            return

        command = build_command(domain, source, filename, DEFAULT_LIMIT, command_name(self.executable))
        self._found = []
        self._files = output_files(filename) if filename else None
        self.tree.delete(*self.tree.get_children())
        self.files_label.configure(text="")
        self.log_console.clear()
        self.log_console.log(f"[*] Iniciant escaneig sobre {domain} utilitzant {source}...")
        self.log_console.log(f"[*] Comanda: {command}")
        self._set_running(True)
        self._set_status(f"The Harvester està cercant informació de {domain} a «{source}»... "
                         "Amb «all» pot trigar uns minuts.")
        # Sortida sense memòria intermèdia perquè les línies arribin a la consola en temps real
        env = dict(os.environ, PYTHONUNBUFFERED="1", NO_COLOR="1")
        self.runner.run_async(command, self._on_output, self._on_done, env=env)

    def _on_output(self, line):
        line = _ANSI_RE.sub("", line).rstrip()
        match = _FOUND_RE.match(line.strip())
        if match:
            self._found.append((match.group(1), int(match.group(2))))
        if line.strip():
            self.after(0, lambda: self.log_console.log(line))

    def _on_done(self, code):
        self.after(0, lambda: self._finish(code))

    def _stop(self):
        self.runner.terminate()
        self.log_console.log("[*] Cerca aturada per l'usuari.")

    def _set_running(self, running):
        self._running = running
        self.run_btn.configure(state="disabled" if running else "normal")
        self.stop_btn.configure(state="normal" if running else "disabled")
        if running:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(0)

    def _finish(self, code):
        self._set_running(False)
        rows = [(label, count) for label, count, _first in summarize(self._files[1])] if self._files else []
        if not rows:  # sense fitxer: el resum surt de les línies «[*] ... found: N» de la sortida
            rows = self._found
        for label, count in rows:
            self.tree.insert("", "end", values=(label, count))
        if self._files and os.path.exists(self._files[1]):
            folder = os.path.dirname(os.path.abspath(self._files[1])).replace(os.path.expanduser("~"), "~", 1)
            names = "\n".join(os.path.basename(f) for f in self._files)
            self.files_label.configure(text=f"Desat a la carpeta {folder}\n{names}")
        self.log_console.log(f"[*] The Harvester ha acabat (codi de sortida {code}).")
        if code == 0:
            total = sum(count for _label, count in rows)
            self._set_status(f"Cerca acabada: {total} resultat(s) en total.", COLOR_SUCCESS)
        else:
            self._set_status(f"The Harvester ha acabat amb el codi {code}. Reviseu la consola.", COLOR_DANGER)
