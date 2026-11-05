"""Pestanya «Reconeixement passiu»: consulta a Shodan abans dels escanejos actius.

Flux de treball:
  1. Es configura la clau de l'API de Shodan (es desa al perfil de l'usuari, mai al codi).
  2. Consulta d'host: IP, noms de domini, ports oberts i servei de cada port (banner grabbing).
  3. Cerca de serveis: equips d'Internet que tenen un producte o servei concret.
  4. «Afegeix a l'auditoria» passa l'equip consultat a la sessió, perquè les pestanyes de
     Vulnerabilitats, Informes i Expedients el tractin com la resta de resultats.
Cap consulta envia paquets a l'objectiu: les dades són les que Shodan ja té indexades.
"""
import threading
from tkinter import messagebox, ttk

import customtkinter as ctk

from core import argos_api
from core.shodan_intel import (
    SEARCH_LIMITS, SHODAN_STATE, ShodanError, ShodanRecon, available, delete_api_key, load_api_key, lookup_to_host, mask_key, save_api_key, service_label, validate_public_ip,
)
from gui.theme import (
    COLOR_ACCENT, COLOR_ACCENT_HOVER, COLOR_ACCENT_TEXT, COLOR_BORDER, COLOR_DANGER, COLOR_PRIMARY_DARK,
    COLOR_SUCCESS, COLOR_TEXT_MUTED, FONT_DISPLAY_FAMILY,
)
from gui.widgets.log_console import LogConsole

HOST_COLUMNS = [("port", "Port", 70), ("proto", "Protocol", 95), ("servei", "Servei", 110),
                ("producte", "Producte i versió", 220), ("banner", "Banner", 420)]
SEARCH_COLUMNS = [("ip", "Adreça IP", 140), ("port", "Port", 80), ("org", "Organització o ISP", 300),
                  ("producte", "Producte", 220), ("pais", "País", 150)]
SUMMARY_COLUMNS = [("faceta", "Resum per", 150), ("valor", "Valor", 420), ("nombre", "Resultats", 140)]
FACET_TITLES = {"port": "Port", "org": "Organització", "country": "País", "product": "Producte"}
LIMIT_LABELS = [f"{n} resultats" for n in SEARCH_LIMITS]


def _thousands(number):
    return f"{number:,}".replace(",", ".")


class ReconTab(ctk.CTkFrame):
    def __init__(self, master, app_state, on_hosts_changed=None, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.app_state = app_state
        self.on_hosts_changed = on_hosts_changed
        self._lookup = None
        self._busy = False
        self._build_ui()
        self._refresh_key_status()

    # ------------------------------------------------------------------ #
    # Interfície
    # ------------------------------------------------------------------ #
    def _build_ui(self):
        outline = {"fg_color": "transparent", "border_width": 1, "border_color": COLOR_PRIMARY_DARK,
                   "text_color": COLOR_PRIMARY_DARK}
        accent = {"fg_color": COLOR_ACCENT, "hover_color": COLOR_ACCENT_HOVER, "text_color": COLOR_PRIMARY_DARK}

        # 1. Clau de l'API
        key_card = ctk.CTkFrame(self, border_width=1, border_color=COLOR_BORDER)
        key_card.pack(fill="x", padx=12, pady=(8, 8))
        key_card.grid_columnconfigure(2, weight=1)
        ctk.CTkLabel(key_card, text="Clau de l'API de Shodan", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).grid(row=0, column=0, sticky="w", padx=(16, 12), pady=(10, 4))
        self.key_entry = ctk.CTkEntry(key_card, width=300, show="•", placeholder_text="Enganxeu aquí la clau de l'API")
        self.key_entry.grid(row=0, column=1, sticky="w", pady=(10, 4))
        buttons = ctk.CTkFrame(key_card, fg_color="transparent")
        buttons.grid(row=0, column=2, sticky="e", padx=(8, 16), pady=(10, 4))
        self.save_key_btn = ctk.CTkButton(buttons, text="Desa la clau", width=110, command=self._save_key)
        self.save_key_btn.pack(side="left")
        self.check_key_btn = ctk.CTkButton(buttons, text="Comprova el pla", width=130, command=self._check_key, **outline)
        self.check_key_btn.pack(side="left", padx=8)
        ctk.CTkButton(buttons, text="Esborra", width=80, command=self._delete_key, **outline).pack(side="left")
        self.key_status = ctk.CTkLabel(key_card, text="", anchor="w", justify="left", wraplength=1050)
        self.key_status.grid(row=1, column=0, columnspan=3, sticky="w", padx=16, pady=(0, 10))

        # 2. Consultes
        query_card = ctk.CTkFrame(self, border_width=1, border_color=COLOR_BORDER)
        query_card.pack(fill="x", padx=12, pady=(0, 6))
        head = ctk.CTkFrame(query_card, fg_color="transparent")
        head.grid(row=0, column=0, columnspan=5, sticky="ew", padx=16, pady=(10, 4))
        ctk.CTkLabel(head, text="Reconeixement passiu", font=(FONT_DISPLAY_FAMILY, 15, "bold"),
                     text_color=COLOR_PRIMARY_DARK).pack(side="left")
        ctk.CTkLabel(head, text="   Les dades són les que Shodan ja té indexades: no s'envia cap paquet a l'objectiu.",
                     text_color=COLOR_TEXT_MUTED).pack(side="left")

        ctk.CTkLabel(query_card, text="IP pública:").grid(row=1, column=0, sticky="w", padx=(16, 8), pady=4)
        self.ip_entry = ctk.CTkEntry(query_card, width=220, placeholder_text="ex. 45.33.32.156")
        self.ip_entry.grid(row=1, column=1, sticky="w", pady=4)
        self.ip_entry.bind("<Return>", lambda _e: self._run_lookup())
        self.lookup_btn = ctk.CTkButton(query_card, text="Consulta l'host", width=150, command=self._run_lookup, **accent)
        self.lookup_btn.grid(row=1, column=2, sticky="w", padx=8, pady=4)
        self.import_btn = ctk.CTkButton(query_card, text="Afegeix a l'auditoria", width=170, state="disabled",
                                        command=self._import_lookup, **outline)
        self.import_btn.grid(row=1, column=3, sticky="w", pady=4)

        ctk.CTkLabel(query_card, text="Servei o producte:").grid(row=2, column=0, sticky="w", padx=(16, 8), pady=(4, 12))
        self.query_entry = ctk.CTkEntry(query_card, width=220, placeholder_text="ex. proftpd, nginx, webcam")
        self.query_entry.grid(row=2, column=1, sticky="w", pady=(4, 12))
        self.query_entry.bind("<Return>", lambda _e: self._run_search())
        self.search_btn = ctk.CTkButton(query_card, text="Cerca a Shodan", width=150, command=self._run_search, **accent)
        self.search_btn.grid(row=2, column=2, sticky="w", padx=8, pady=(4, 12))
        self.limit_var = ctk.StringVar(value=LIMIT_LABELS[0])
        ctk.CTkOptionMenu(query_card, values=LIMIT_LABELS, variable=self.limit_var, width=170).grid(
            row=2, column=3, sticky="w", pady=(4, 12)
        )

        self.progress = ctk.CTkProgressBar(self, mode="determinate", height=6)
        self.progress.pack(fill="x", padx=12, pady=(0, 6))
        self.progress.set(0)

        # La línia d'estat es col·loca abans dels resultats perquè no quedi tallada en finestres baixes
        self.status_label = ctk.CTkLabel(self, text="Preparat.", anchor="w")
        self.status_label.pack(side="bottom", fill="x", padx=12, pady=(2, 6))

        # 3. Resultats
        results = ctk.CTkFrame(self, fg_color="transparent")
        results.pack(fill="both", expand=True, padx=12)
        results.grid_columnconfigure(0, weight=1)
        results.grid_rowconfigure(1, weight=1)  # la taula s'emporta l'espai; la consola té l'alçada fixa

        self.summary = ctk.CTkFrame(results, border_width=1, border_color=COLOR_BORDER)
        self.summary.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        self.summary.grid_columnconfigure((1, 3), weight=1)
        self._summary_values = {}
        fields = [("ip", "IP consultada"), ("org", "Organització o ISP"), ("hostnames", "Noms de domini"),
                  ("place", "Ubicació i SO"), ("ports", "Ports oberts"), ("updated", "Darrera actualització")]
        for index, (key, title) in enumerate(fields):
            row, col = divmod(index, 2)
            ctk.CTkLabel(self.summary, text=title.upper(), text_color=COLOR_TEXT_MUTED,
                         font=(FONT_DISPLAY_FAMILY, 10, "bold")).grid(row=row, column=col * 2, sticky="w",
                                                                      padx=(16, 10), pady=(6 if row == 0 else 0, 2))
            value = ctk.CTkLabel(self.summary, text="-", anchor="w", justify="left", wraplength=420,
                                 text_color=COLOR_PRIMARY_DARK, font=(FONT_DISPLAY_FAMILY, 12, "bold"))
            value.grid(row=row, column=col * 2 + 1, sticky="w", pady=(6 if row == 0 else 0, 2))
            self._summary_values[key] = value
        self.summary.grid_remove()  # es mostra amb la primera consulta d'host

        tree_frame = ctk.CTkFrame(results)
        tree_frame.grid(row=1, column=0, sticky="nsew")
        self.tree = ttk.Treeview(tree_frame, show="headings", height=6, selectmode="browse")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y", pady=4)
        self.tree.pack(fill="both", expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", self._on_row_double_click)
        self._set_columns(HOST_COLUMNS)

        self.log_console = LogConsole(results)
        self.log_console.textbox.configure(height=96)
        self.log_console.grid(row=2, column=0, sticky="nsew", pady=(6, 0))

        if not available():
            for btn in (self.lookup_btn, self.search_btn, self.check_key_btn):
                btn.configure(state="disabled")
            self._set_status("Falta la llibreria de Shodan. Instal·leu-la amb ./install_dependencies.sh "
                             "o amb «venv/bin/pip install shodan» i reinicieu SentinelX.", COLOR_DANGER)

    def _set_columns(self, columns):
        self.tree.delete(*self.tree.get_children())
        self.tree["columns"] = [c[0] for c in columns]
        for col, text, width in columns:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor="w", stretch=col in ("banner", "org", "valor"))
        self._columns = columns

    def _set_status(self, text, color=None):
        self.status_label.configure(text=text, text_color=color or COLOR_PRIMARY_DARK)

    def _log(self, message):
        self.log_console.log(message)

    # ------------------------------------------------------------------ #
    # Clau de l'API
    # ------------------------------------------------------------------ #
    def _refresh_key_status(self, extra=""):
        key, source = load_api_key()
        if source == "entorn":
            text = f"Es fa servir la clau de la variable d'entorn SHODAN_API_KEY ({mask_key(key)})."
        elif source == "fitxer":
            text = f"Clau desada al perfil de l'usuari ({mask_key(key)}, permisos 600)."
        elif argos_api.available():
            text = ("No cal cap clau: les consultes es fan a través de l'API d'Argos. Si en teniu una de pròpia "
                    "(https://account.shodan.io), la podeu desar aquí.")
        else:
            text = ("No hi ha cap clau configurada. Creeu un compte a https://account.shodan.io, copieu-hi "
                    "la clau de l'API i deseu-la aquí: no es guarda mai al codi ni a l'expedient.")
        ok = key or argos_api.available()
        self.key_status.configure(text=f"{text} {extra}".strip(), text_color=COLOR_TEXT_MUTED if ok else COLOR_DANGER)

    def _save_key(self):
        key = self.key_entry.get().strip()
        if not key:
            messagebox.showwarning("Falta la clau", "Enganxeu la clau de l'API de Shodan al camp abans de desar-la.")
            return
        save_api_key(key)
        self.key_entry.delete(0, "end")
        self._refresh_key_status()
        self._check_key()

    def _delete_key(self):
        if messagebox.askyesno("Esborra la clau", "Voleu esborrar la clau de Shodan desada en aquest equip?"):
            delete_api_key()
            self._refresh_key_status()

    def _check_key(self):
        def done(info):
            self._refresh_key_status(
                f"Pla «{info['plan']}»: {info['query_credits']} crèdits de consulta"
                + (" (la cerca de serveis mostrarà un resum agregat)." if not info["query_credits"] else ".")
            )
            self._log(f"Clau comprovada: pla {info['plan']}, {info['query_credits']} crèdits de consulta.")

        self._run(lambda recon: recon.account_info(), done, "Comprovant la clau a Shodan...")

    # ------------------------------------------------------------------ #
    # Consultes
    # ------------------------------------------------------------------ #
    def _run(self, work, on_success, message):
        """Executa una consulta a Shodan en un fil perquè la interfície no es bloquegi."""
        if self._busy:
            return
        key = self.key_entry.get().strip() or load_api_key()[0]
        try:
            recon = ShodanRecon(key)
        except ShodanError as exc:
            self._set_status(str(exc), COLOR_DANGER)
            return
        self._set_busy(True, message)

        def worker():
            try:
                result = work(recon)
            except ShodanError as exc:
                error = str(exc)
                self.after(0, lambda: self._on_error(error))
                return
            except Exception as exc:  # p. ex. una resposta inesperada: no ha de tancar l'aplicació
                error = f"Error inesperat en consultar Shodan: {exc}"
                self.after(0, lambda: self._on_error(error))
                return
            self.after(0, lambda: self._on_success(on_success, result))

        threading.Thread(target=worker, daemon=True).start()

    def _set_busy(self, busy, message=""):
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in (self.lookup_btn, self.search_btn, self.check_key_btn, self.save_key_btn):
            btn.configure(state=state)
        if busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start()
            self._set_status(message)
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate")
            self.progress.set(0)

    def _on_error(self, message):
        self._set_busy(False)
        self._set_status(message, COLOR_DANGER)
        self._log(f"Error: {message}")

    def _on_success(self, callback, result):
        self._set_busy(False)
        callback(result)

    def _run_lookup(self):
        try:
            ip = validate_public_ip(self.ip_entry.get())
        except ShodanError as exc:
            self._set_status(str(exc), COLOR_DANGER)
            return
        self.log_console.clear()
        self._log(f"Consultant a Shodan l'host {ip} (reconeixement passiu)...")
        self._run(lambda recon: recon.host_lookup(ip), self._show_lookup, f"Consultant {ip} a Shodan...")

    def _show_lookup(self, lookup):
        self._lookup = lookup
        self._set_columns(HOST_COLUMNS)
        self.summary.grid()
        place = f"{lookup['city']} ({lookup['country']})" if lookup["city"] else lookup["country"]
        if lookup["os"]:
            place = f"{place}, {lookup['os']}" if place else lookup["os"]
        values = {
            "ip": lookup["ip"],
            "org": " / ".join(dict.fromkeys(v for v in (lookup["org"], lookup["isp"]) if v)) or "-",
            "hostnames": ", ".join(lookup["hostnames"]) or "Cap domini associat",
            "place": place or "-",
            "ports": ", ".join(str(p) for p in lookup["ports"]) or "Cap",
            "updated": lookup["last_update"] or "-",
        }
        for key, value in values.items():
            self._summary_values[key].configure(text=value)

        for service in lookup["services"]:
            product = f"{service['product']} {service['version']}".strip()
            self.tree.insert("", "end", values=(service["port"], service["transport"], service["name"] or "-",
                                                product or "No identificat", service["banner"] or "-"))

        self._log(f"IP consultada: {lookup['ip']}")
        self._log(f"Noms de domini: {values['hostnames']}")
        self._log(f"Ports oberts: {values['ports']}")
        for service in lookup["services"]:
            self._log(f"Port {service['port']}/{service['transport']}: {service_label(service)}")
        if lookup["vulns"]:
            self._log(f"Shodan hi associa {len(lookup['vulns'])} CVE per la versió dels serveis (sense verificar): "
                      f"{', '.join(lookup['vulns'][:6])}{'...' if len(lookup['vulns']) > 6 else ''}")
        self.import_btn.configure(state="normal" if lookup["services"] else "disabled")
        self._set_status(f"{lookup['ip']}: {len(lookup['ports'])} port(s) obert(s) segons Shodan. "
                         "Podeu afegir-los a l'auditoria per correlacionar-ne les vulnerabilitats.", COLOR_SUCCESS)

    def _run_search(self):
        query = self.query_entry.get().strip()
        if not query:
            self._set_status("Escriviu el nom d'un servei o producte (p. ex. proftpd, nginx o webcam).", COLOR_DANGER)
            return
        limit = SEARCH_LIMITS[LIMIT_LABELS.index(self.limit_var.get())]
        self.log_console.clear()
        self._log(f"Cercant «{query}» a Shodan (primers {limit} resultats)...")
        self._run(lambda recon: recon.search(query, limit=limit), self._show_search, f"Cercant «{query}» a Shodan...")

    def _show_search(self, result):
        total = _thousands(result["total"])
        self.summary.grid_remove()
        if result["mode"] == "complet":
            self._set_columns(SEARCH_COLUMNS)
            for match in result["results"]:
                self.tree.insert("", "end", values=(
                    match["ip"], f"{match['port']}/{match['transport']}", match["org"] or match["isp"] or "No disponible",
                    match["product"] or "-", match["country"] or "-",
                ))
                self._log(f"{match['ip']}  port {match['port']}  {match['org'] or match['isp'] or 'organització no disponible'}")
            self._set_status(f"«{result['query']}»: {total} resultats a Shodan; se'n mostren {len(result['results'])}. "
                             "Doble clic sobre un resultat per consultar-ne l'host.", COLOR_SUCCESS)
        else:
            self._set_columns(SUMMARY_COLUMNS)
            for facet in FACET_TITLES:
                for item in result["facets"].get(facet, []):
                    self.tree.insert("", "end", values=(FACET_TITLES.get(facet, facet), item["value"],
                                                        _thousands(item["count"])))
            self._log(result["notice"])
            self._log("Es mostra el resum gratuït de Shodan (recompte per ports, organitzacions, països i productes).")
            self._set_status(f"«{result['query']}»: {total} resultats a Shodan. El pla de la clau no permet "
                             "llistar-los, i es mostra el resum agregat (detall a la consola).", COLOR_ACCENT_TEXT)
        self._log(f"Total de resultats a Shodan: {total}")

    def _on_row_double_click(self, _event):
        selection = self.tree.selection()
        if not selection or self._columns is not SEARCH_COLUMNS:
            return
        ip = self.tree.item(selection[0], "values")[0]
        self.ip_entry.delete(0, "end")
        self.ip_entry.insert(0, ip)
        self._run_lookup()

    # ------------------------------------------------------------------ #
    # Integració amb l'auditoria
    # ------------------------------------------------------------------ #
    def _import_lookup(self):
        if not self._lookup:
            return
        added = self.app_state.add_passive_host(lookup_to_host(self._lookup))
        if not self.app_state.session.target:
            self.app_state.session.target = self._lookup["ip"]
        if self.on_hosts_changed:
            self.on_hosts_changed()
        message = (f"S'han afegit {added} servei(s) de {self._lookup['ip']} a l'auditoria amb l'estat «{SHODAN_STATE}». "
                   "Ja es poden correlacionar a «Vulnerabilitats i CVE» i surten a l'informe.")
        if not added:
            message = f"Els serveis de {self._lookup['ip']} ja eren a l'auditoria."
        self._log(message)
        self._set_status(message, COLOR_SUCCESS)

    def sync_with_session(self):
        """Proposa l'objectiu de l'expedient obert si és una IP pública."""
        target = self.app_state.session.target
        try:
            ip = validate_public_ip(target)
        except ShodanError:
            return
        if not self.ip_entry.get().strip():
            self.ip_entry.insert(0, ip)
