"""Finestra emergent que mostra el resultat de comparar l'auditoria actual amb un baseline."""
import customtkinter as ctk


class DiffDialog(ctk.CTkToplevel):
    def __init__(self, master, diff, baseline_target=""):
        super().__init__(master)
        self.title("Comparació amb Auditoria Base (Baseline)")
        self.geometry("720x560")
        self.transient(master)
        self.grab_set()

        ctk.CTkLabel(
            self, text="Diferències respecte a l'auditoria base", font=("Segoe UI", 16, "bold")
        ).pack(pady=(16, 4))
        if baseline_target:
            ctk.CTkLabel(self, text=f"Baseline: {baseline_target}", text_color="#5B6472").pack(pady=(0, 8))

        box = ctk.CTkTextbox(self, font=("Consolas", 11))
        box.pack(fill="both", expand=True, padx=16, pady=(4, 16))
        box.insert("1.0", self._render(diff))
        box.configure(state="disabled")

        ctk.CTkButton(self, text="Tancar", command=self.destroy).pack(pady=(0, 16))

    @staticmethod
    def _render(diff):
        lines = []

        lines.append(f"EQUIPS NOUS ({len(diff['new_hosts'])})")
        lines.append("-" * 60)
        if diff["new_hosts"]:
            for host in diff["new_hosts"]:
                lines.append(f"  + {host.ip}  ({host.hostname or 's/n'})  —  {len(host.services)} servei(s)")
        else:
            lines.append("  Cap equip nou.")
        lines.append("")

        lines.append(f"EQUIPS DESAPAREGUTS ({len(diff['removed_hosts'])})")
        lines.append("-" * 60)
        if diff["removed_hosts"]:
            for host in diff["removed_hosts"]:
                lines.append(f"  - {host.ip}  ({host.hostname or 's/n'})")
        else:
            lines.append("  Cap equip ha desaparegut.")
        lines.append("")

        lines.append(f"PORTS/SERVEIS NOUS EN EQUIPS JA CONEGUTS ({len(diff['new_services'])})")
        lines.append("-" * 60)
        if diff["new_services"]:
            for ip, service in diff["new_services"]:
                lines.append(f"  + {ip}  ->  {service.port}/{service.protocol} {service.product or service.service_name} {service.version}")
        else:
            lines.append("  Cap port/servei nou.")
        lines.append("")

        lines.append(f"VULNERABILITATS NOVES ({len(diff['new_vulnerabilities'])})")
        lines.append("-" * 60)
        if diff["new_vulnerabilities"]:
            for ip, port_label, vuln in diff["new_vulnerabilities"]:
                lines.append(f"  + {ip}:{port_label}  [{vuln.severity.value}]  {vuln.cve_id}  —  {vuln.description[:100]}")
        else:
            lines.append("  Cap vulnerabilitat nova.")

        return "\n".join(lines)
