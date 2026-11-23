"""Pestanya Auditoria SSH: configuració d'un servidor SSH amb ssh-audit.

Fa servir el mòdul core/ssh_audit.py, el mateix que l'script auditoria_ssh.py. Els resultats es
mostren en forma d'arbre (servidor, claus d'host, xifratge, MAC, intercanvi de claus, mètodes
d'autenticació i recomanacions) i passen a la sessió d'auditoria: les troballes s'afegeixen al
servei SSH de l'equip, de manera que el Tauler, els Informes i els Expedients les fan servir.
"""
import threading
from tkinter import messagebox, ttk

import customtkinter as ctk

from core.ssh_audit import FAIL, OK, STATE_LABELS, WARN, SshAuditError, install, is_available, run_audit
from core.ssh_audit import validate_host, validate_port
from gui.theme import COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_DANGER, COLOR_PRIMARY_DARK, COLOR_SUCCESS
from gui.theme import COLOR_TEXT_MUTED

STATE_COLORS = {FAIL: COLOR_DANGER, WARN: "#B7791F", OK: COLOR_SUCCESS}
NOTE_LABELS = {"fail": "Error", "warn": "Avís", "info": "Informació"}


class SshTab(ctk.CTkFrame):
    def __init__(self, master, app_state, on_hosts_changed=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.on_hosts_changed = on_hosts_changed
        self._build_ui()

    def _build_ui(self):
        controls = ctk.CTkFrame(self)
        controls.pack(fill="x", padx=12, pady=(12, 6))

        ctk.CTkLabel(controls, text="Servidor SSH (IP o nom):", font=("Segoe UI", 12, "bold")).grid(
            row=0, column=0, padx=8, pady=8, sticky="w")
        self.host_entry = ctk.CTkEntry(controls, width=220, placeholder_text="ex. 192.168.1.10")
        self.host_entry.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        self.host_entry.bind("<Return>", lambda _e: self._run_audit())
        ctk.CTkLabel(controls, text="Port:", font=("Segoe UI", 12, "bold")).grid(row=0, column=2, padx=(16, 4), pady=8)
        self.port_entry = ctk.CTkEntry(controls, width=70)
        self.port_entry.insert(0, "22")
        self.port_entry.grid(row=0, column=3, padx=4, pady=8, sticky="w")
        self.port_entry.bind("<Return>", lambda _e: self._run_audit())

        self.audit_btn = ctk.CTkButton(controls, text="Audita", width=110, command=self._run_audit,
                                       fg_color=COLOR_ACCENT, hover_color=COLOR_ACCENT_HOVER,
                                       text_color=COLOR_PRIMARY_DARK)
        self.audit_btn.grid(row=0, column=4, padx=8, pady=8)
        self.install_btn = ctk.CTkButton(controls, text="Instal·la ssh-audit", width=140, command=self._install)

        ctk.CTkLabel(controls, text="Auditoria desada:").grid(row=1, column=0, padx=8, pady=(0, 8), sticky="w")
        self.saved_var = ctk.StringVar(value="")
        self.saved_menu = ctk.CTkOptionMenu(controls, values=[""], variable=self.saved_var, width=220,
                                            command=lambda _v: self._show_selected())
        self.saved_menu.grid(row=1, column=1, padx=8, pady=(0, 8), sticky="w")

        self.progress = ctk.CTkProgressBar(self, mode="determinate")
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)
        self.status_label = ctk.CTkLabel(self, text="Preparat.", anchor="w", justify="left", wraplength=1100)
        self.status_label.pack(side="bottom", fill="x", padx=12, pady=(0, 8))

        tree_frame = ctk.CTkFrame(self)
        tree_frame.pack(fill="both", expand=True, padx=12, pady=6)
        self.tree = ttk.Treeview(tree_frame, columns=("estat", "detall"), show="tree headings")
        self.tree.heading("#0", text="Element")
        self.tree.heading("estat", text="Estat")
        self.tree.heading("detall", text="Detall")
        self.tree.column("#0", width=380, stretch=False)
        self.tree.column("estat", width=130, stretch=False)
        self.tree.column("detall", width=560, stretch=True)
        for state, color in STATE_COLORS.items():
            self.tree.tag_configure(state, foreground=color)
        self.tree.tag_configure("seccio", font=("Segoe UI", 11, "bold"))
        self.tree.tag_configure("nota", foreground=COLOR_TEXT_MUTED)
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y", pady=4)
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)

        self._update_install_state()

    # ------------------------------------------------------------------ #
    def _set_status(self, text, color=None):
        self.status_label.configure(text=text, text_color=color or COLOR_PRIMARY_DARK)

    def _set_running(self, running, message=""):
        state = "disabled" if running else "normal"
        self.audit_btn.configure(state=state)
        self.install_btn.configure(state=state)
        if running:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self._set_status(message)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(0)

    def _update_install_state(self):
        if is_available():
            self.install_btn.grid_forget()
            self.audit_btn.configure(state="normal")
        else:
            self.install_btn.grid(row=0, column=5, padx=(0, 8), pady=8)
            self.audit_btn.configure(state="disabled")
            self._set_status("ssh-audit no està instal·lat a l'entorn de SentinelX. Feu clic a «Instal·la "
                             "ssh-audit» o executeu ./install_dependencies.sh.", COLOR_DANGER)

    def _install(self):
        self._set_running(True, "Instal·lant ssh-audit amb pip a l'entorn de SentinelX...")

        def worker():
            try:
                message, color = install(), COLOR_SUCCESS
            except SshAuditError as exc:
                message, color = str(exc), COLOR_DANGER
            self.after(0, lambda: (self._set_running(False), self._update_install_state(),
                                   self._set_status(message, color)))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------ #
    def _run_audit(self):
        try:
            host = validate_host(self.host_entry.get())
            port = validate_port(self.port_entry.get())
        except SshAuditError as exc:
            self._set_status(str(exc), COLOR_DANGER)
            return
        if self.app_state.safe_mode and not messagebox.askyesno(
            "Confirmació requerida (Mode Segur)",
            f"ssh-audit obrirà diverses connexions a {host}:{port} per analitzar-ne la configuració i la "
            "limitació de connexions. Fes-ho només si tens autorització per auditar-lo. Vols continuar?",
        ):
            return
        self._set_running(True, f"Auditant {host}:{port} amb ssh-audit...")

        def worker():
            try:
                audit = run_audit(host, port)
            except SshAuditError as exc:
                message = str(exc)
                self.after(0, lambda: self._audit_failed(message))
                return
            except Exception as exc:  # noqa: BLE001 - un error inesperat no ha de bloquejar la pestanya
                message = f"Error inesperat en auditar: {exc}"
                self.after(0, lambda: self._audit_failed(message))
                return
            self.after(0, lambda: self._audit_done(audit))

        threading.Thread(target=worker, daemon=True).start()

    def _audit_failed(self, message):
        self._set_running(False)
        self._set_status(message, COLOR_DANGER)

    def _audit_done(self, audit):
        self._set_running(False)
        if not self.app_state.session.target:
            self.app_state.session.target = audit["host"]
        self.app_state.add_ssh_audit(audit)
        self._refresh_saved(audit["objectiu"])
        if self.on_hosts_changed:
            self.on_hosts_changed()
        summary = audit["resum"]
        self._set_status(f"Auditoria acabada: {summary['obsolets']} element(s) obsolet(s) o insegur(s), "
                         f"{summary['avisos']} avís(os) i {summary['correctes']} correcte(s). S'han afegit a "
                         "l'auditoria (Tauler, Informes i Expedients).",
                         COLOR_DANGER if summary["obsolets"] else COLOR_SUCCESS)

    # ------------------------------------------------------------------ #
    def sync_with_session(self):
        """Torna a mostrar les auditories de la sessió actual (p. ex. després d'obrir un expedient)."""
        audits = self.app_state.session.ssh_audits
        current = self.saved_var.get()
        if current not in [a["objectiu"] for a in audits]:
            current = audits[-1]["objectiu"] if audits else ""
        self._refresh_saved(current)

    def _refresh_saved(self, selected):
        names = [a["objectiu"] for a in self.app_state.session.ssh_audits]
        self.saved_menu.configure(values=names or [""])
        self.saved_var.set(selected)
        self._show_selected()

    def _show_selected(self):
        audit = next((a for a in self.app_state.session.ssh_audits if a["objectiu"] == self.saved_var.get()), None)
        self.tree.delete(*self.tree.get_children())
        if audit is not None:
            self._fill_tree(audit)

    def _fill_tree(self, audit):
        server = audit["servidor"]
        root = self.tree.insert("", "end", text=f"Servidor {audit['objectiu']}", values=("", server["banner"]),
                                open=True, tags=("seccio",))
        self.tree.insert(root, "end", text=f"Protocol SSH-{server['protocol']}",
                         values=(STATE_LABELS[server["estat_protocol"]], server["programari"]),
                         tags=(server["estat_protocol"],))
        if audit["compressio"]:
            self.tree.insert(root, "end", text="Compressió", values=("", ", ".join(audit["compressio"])))

        sections = [(c["nom"], c["elements"]) for c in audit["categories"]]
        sections.append(("Mètodes d'autenticació", audit["autenticacio"]["metodes"]))
        for title, items in sections:
            fails = sum(1 for i in items if i["estat"] == FAIL)
            label = f"{len(items)} element(s)" + (f", {fails} obsolet(s) o insegur(s)" if fails else "")
            node = self.tree.insert("", "end", text=title, values=("", label), open=True, tags=("seccio",))
            for item in items:
                child = self.tree.insert(node, "end", text=item["nom"],
                                         values=(STATE_LABELS[item["estat"]], item["detall"]), tags=(item["estat"],))
                for level in ("fail", "warn", "info"):
                    for note in (item.get("notes") or {}).get(level, []):
                        self.tree.insert(child, "end", text=NOTE_LABELS[level], values=("", note), tags=("nota",))
            if not items and title.startswith("Mètodes") and audit["autenticacio"]["error"]:
                self.tree.insert(node, "end", text="-", values=("", audit["autenticacio"]["error"]), tags=("nota",))

        if audit["cves"]:
            node = self.tree.insert("", "end", text="CVE", values=("", f"{len(audit['cves'])}"), open=True,
                                    tags=("seccio",))
            for cve in audit["cves"]:
                self.tree.insert(node, "end", text=cve["cve"], values=(f"CVSS {cve['cvss']}", cve["descripcio"]),
                                 tags=(FAIL,))
        if audit["recomanacions"]:
            node = self.tree.insert("", "end", text="Recomanacions d'ssh-audit",
                                    values=("", f"{len(audit['recomanacions'])}"), open=True, tags=("seccio",))
            for rec in audit["recomanacions"]:
                state = FAIL if rec["nivell"] == "critical" else WARN
                text = f"{rec['accio']} {rec['nom']}"
                self.tree.insert(node, "end", text=text, values=(rec["categoria"].upper(), rec["nota"]), tags=(state,))
        if audit["notes"]:
            node = self.tree.insert("", "end", text="Notes addicionals", values=("", ""), tags=("seccio",))
            for note in audit["notes"]:
                self.tree.insert(node, "end", text="", values=("", note), tags=("nota",))
