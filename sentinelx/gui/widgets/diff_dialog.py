"""Finestra emergent que mostra el resultat de comparar l'auditoria actual amb una d'anterior."""
import customtkinter as ctk


class DiffDialog(ctk.CTkToplevel):
    def __init__(self, master, diff, baseline_target=""):
        super().__init__(master)
        self.title("Comparació amb l'auditoria anterior")
        self.geometry("760x600")
        self.transient(master.winfo_toplevel())
        self.after(150, self._grab)

        ctk.CTkLabel(
            self, text="Diferències respecte a l'auditoria anterior", font=("Segoe UI", 16, "bold")
        ).pack(pady=(16, 4))
        if baseline_target:
            ctk.CTkLabel(self, text=f"Auditoria de referència: {baseline_target}", text_color="#5B6472").pack(pady=(0, 4))

        resolved = len(diff.get("resolved_vulnerabilities", [])) + len(diff.get("resolved_hardening", []))
        new = len(diff.get("new_vulnerabilities", [])) + len(diff.get("new_hardening", []))
        pending = len(diff.get("persistent_vulnerabilities", []))
        ctk.CTkLabel(
            self, text=f"✓ {resolved} resoltes    ✗ {new} noves    • {pending} pendents",
            font=("Segoe UI", 13, "bold"), text_color="#14335C",
        ).pack(pady=(0, 8))

        box = ctk.CTkTextbox(self, font=("Consolas", 11))
        box.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        box.insert("1.0", self._render(diff))
        box.configure(state="disabled")

        ctk.CTkButton(self, text="Tancar", command=self.destroy).pack(pady=(0, 16))

    def _grab(self):
        try:
            self.grab_set()
        except Exception:  # noqa: BLE001 - la finestra encara no és visible; no és imprescindible
            pass

    @staticmethod
    def _render(diff):
        lines = []

        def section(title, items, empty, render):
            lines.append(f"{title} ({len(items)})")
            lines.append("-" * 64)
            if items:
                lines.extend(render(item) for item in items)
            else:
                lines.append(f"  {empty}")
            lines.append("")

        def vuln_line(prefix):
            return lambda item: (
                f"  {prefix} {item[0]}:{item[1]}  [{item[2].severity.value}]  {item[2].cve_id}  —  {item[2].description[:90]}"
            )

        section("VULNERABILITATS RESOLTES", diff.get("resolved_vulnerabilities", []),
                "Cap vulnerabilitat resolta.", vuln_line("✓"))
        section("VULNERABILITATS NOVES", diff.get("new_vulnerabilities", []),
                "Cap vulnerabilitat nova.", vuln_line("+"))
        section("VULNERABILITATS PENDENTS (continuen presents)", diff.get("persistent_vulnerabilities", []),
                "Cap vulnerabilitat pendent.", vuln_line("•"))
        section("NO VERIFICADES (equips que ara no s'han detectat)", diff.get("unverified_vulnerabilities", []),
                "Totes les troballes anteriors s'han pogut verificar.", vuln_line("?"))

        if diff.get("resolved_hardening") or diff.get("new_hardening"):
            section("REFORÇAMENT RESOLT", diff.get("resolved_hardening", []), "Cap.",
                    lambda v: f"  ✓ [{v.severity.value}] {v.description[:100]}")
            section("REFORÇAMENT NOU", diff.get("new_hardening", []), "Cap.",
                    lambda v: f"  + [{v.severity.value}] {v.description[:100]}")

        section("EQUIPS NOUS", diff.get("new_hosts", []), "Cap equip nou.",
                lambda h: f"  + {h.ip}  ({h.hostname or 's/n'})  —  {len(h.services)} servei(s)")
        section("EQUIPS NO DETECTATS ARA", diff.get("removed_hosts", []), "Tots els equips anteriors s'han detectat.",
                lambda h: f"  - {h.ip}  ({h.hostname or 's/n'})")
        section("PORTS/SERVEIS NOUS EN EQUIPS JA CONEGUTS", diff.get("new_services", []), "Cap port/servei nou.",
                lambda item: f"  + {item[0]}  ->  {item[1].port}/{item[1].protocol} {item[1].product or item[1].service_name} {item[1].version}")
        section("PORTS/SERVEIS QUE JA NO ESTAN OBERTS", diff.get("closed_services", []), "Cap port s'ha tancat.",
                lambda item: f"  - {item[0]}  ->  {item[1].port}/{item[1].protocol} {item[1].product or item[1].service_name}")
        return "\n".join(lines)
