"""Generació d'informes d'auditoria en format HTML i PDF.

L'informe inclou: resum executiu, inventari d'equips, matriu de troballes
amb els seus CVE associats i un pla de millora amb recomanacions.
El PDF es genera directament amb ReportLab (sense dependències de sistema
com Cairo/Pango), la qual cosa simplifica molt l'empaquetat amb PyInstaller.
"""
import datetime

from core.models import Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: "#7B0000",
    Severity.HIGH: "#C62828",
    Severity.MEDIUM: "#F0AD4E",
    Severity.LOW: "#5BC0DE",
    Severity.INFO: "#6C757D",
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]

IMPROVEMENT_PLAN = [
    "Actualitzar immediatament els serveis amb vulnerabilitats classificades com a Crítica, "
    "especialment aquelles amb exploits públics coneguts.",
    "Desactivar o substituir protocols sense xifrar (Telnet, FTP, TFTP) per alternatives segures "
    "(SSH, SFTP/FTPS, HTTPS).",
    "Aplicar el principi de mínim privilegi: tancar ports i desactivar serveis no estrictament necessaris.",
    "Establir un calendari periòdic d'auditories i un procés de gestió de pedaços (patch management).",
    "Revisar la configuració del tallafocs perimetral i d'amfitrió (ufw/iptables) i el registre d'accessos.",
]


class ReportGenerator:
    def __init__(self, session, company_name, app_name):
        self.session = session
        self.company_name = company_name
        self.app_name = app_name

    def _collect_findings(self):
        findings = []
        for host in self.session.hosts:
            for service in host.services:
                for vuln in service.vulnerabilities:
                    findings.append((host, service, vuln))
        return findings

    def _summary_counts(self, findings):
        counts = {sev: 0 for sev in SEVERITY_ORDER}
        for _, _, vuln in findings:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        for vuln in self.session.hardening_findings:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts

    # ------------------------------------------------------------------ #
    # HTML
    # ------------------------------------------------------------------ #
    def generate_html(self, output_path):
        findings = self._collect_findings()
        counts = self._summary_counts(findings)
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f[2].severity))
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

        finding_rows = "".join(self._html_finding_row(h, s, v) for h, s, v in findings_sorted) or (
            '<tr><td colspan="6">No s\'han detectat vulnerabilitats conegudes.</td></tr>'
        )
        host_rows = "".join(self._html_host_row(h) for h in self.session.hosts) or (
            '<tr><td colspan="5">No s\'han detectat equips actius.</td></tr>'
        )
        summary_cards = "".join(
            f'<div class="card" style="border-top-color:{SEVERITY_COLORS[sev]}">'
            f'<h2>{counts.get(sev, 0)}</h2><p>{sev.value}</p></div>'
            for sev in SEVERITY_ORDER
        )
        plan_items = "".join(f"<li>{item}</li>" for item in IMPROVEMENT_PLAN)
        hardening_sorted = sorted(self.session.hardening_findings, key=lambda v: SEVERITY_ORDER.index(v.severity))
        hardening_rows = "".join(self._html_hardening_row(v) for v in hardening_sorted) or (
            '<tr><td colspan="3">No s\'ha executat cap auditoria de reforçament del sistema local.</td></tr>'
        )

        html = f"""<!DOCTYPE html>
<html lang="ca">
<head>
<meta charset="UTF-8">
<title>Informe d'Auditoria de Seguretat — {self.app_name}</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 0; padding: 0; background: #f4f6f8; color: #1a1f2b; }}
    .header {{ background: #0d2137; color: white; padding: 32px 48px; }}
    .header h1 {{ margin: 0; font-size: 26px; }}
    .header p {{ margin: 4px 0 0; color: #9fb3c8; }}
    .container {{ padding: 32px 48px; }}
    .summary-cards {{ display: flex; gap: 16px; margin-bottom: 32px; flex-wrap: wrap; }}
    .card {{ background: white; border-radius: 4px; padding: 16px 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); min-width: 140px; border-top: 4px solid #ccc; }}
    .card h2 {{ margin: 0; font-size: 32px; }}
    .card p {{ margin: 4px 0 0; color: #556; font-size: 13px; text-transform: uppercase; }}
    table {{ width: 100%; border-collapse: collapse; background: white; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 32px; }}
    th, td {{ padding: 10px 14px; border-bottom: 1px solid #e2e6ea; text-align: left; font-size: 13px; vertical-align: top; }}
    th {{ background: #0d2137; color: white; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
    .sev-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }}
    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; color: white; margin-left: 6px; }}
    .badge-danger {{ background: #7B0000; }}
    section h2 {{ border-left: 4px solid #0d2137; padding-left: 12px; }}
    .footer {{ padding: 24px 48px; color: #778; font-size: 12px; }}
</style>
</head>
<body>
<div class="header">
    <h1>Informe d'Auditoria de Seguretat Informàtica</h1>
    <p>{self.company_name} &middot; {self.app_name}</p>
    <p>Objectiu de l'auditoria: {self.session.target or 'No especificat'} &middot; Generat el {now}</p>
</div>
<div class="container">
    <section>
        <h2>Resum Executiu</h2>
        <p>Aquest informe recull els resultats de l'auditoria de seguretat realitzada sobre
        <strong>{self.session.target or "l'objectiu especificat"}</strong>. S'han analitzat
        {len(self.session.hosts)} equip(s) actiu(s) i detectat {len(findings)} troballa(es) de seguretat.</p>
        <div class="summary-cards">{summary_cards}</div>
    </section>
    <section>
        <h2>Inventari d'Equips Detectats</h2>
        <table>
            <tr><th>IP</th><th>Nom d'Host</th><th>MAC</th><th>Sistema Operatiu</th><th>Serveis Oberts</th></tr>
            {host_rows}
        </table>
    </section>
    <section>
        <h2>Matriu de Troballes i Vulnerabilitats (CVE)</h2>
        <table>
            <tr><th>Gravetat</th><th>Equip</th><th>Servei</th><th>CVE</th><th>Descripció</th><th>Recomanació</th></tr>
            {finding_rows}
        </table>
    </section>
    <section>
        <h2>Reforçament del Sistema Local (Hardening)</h2>
        <table>
            <tr><th>Gravetat</th><th>Descripció</th><th>Recomanació</th></tr>
            {hardening_rows}
        </table>
    </section>
    <section>
        <h2>Pla de Millora</h2>
        <p>Es recomana prioritzar la mitigació de les troballes classificades com a <strong>Crítica</strong> i
        <strong>Alta</strong>, especialment aquelles amb exploits coneguts disponibles públicament:</p>
        <ol>{plan_items}</ol>
    </section>
</div>
<div class="footer">
    Informe generat automàticament per {self.app_name} &mdash; {self.company_name}.
    Ús exclusiu per a finalitats d'auditoria autoritzada.
</div>
</body>
</html>"""
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    @staticmethod
    def _html_finding_row(host, service, vuln):
        color = SEVERITY_COLORS.get(vuln.severity, "#6C757D")
        exploit_badge = '<span class="badge badge-danger">Exploit conegut</span>' if vuln.exploit_available else ""
        service_label = f"{service.port}/{service.protocol} - {service.product or service.service_name} {service.version}"
        return (
            "<tr>"
            f'<td><span class="sev-dot" style="background:{color}"></span>{vuln.severity.value}</td>'
            f"<td>{host.ip} ({host.hostname or 's/n'})</td>"
            f"<td>{service_label}</td>"
            f"<td>{vuln.cve_id}</td>"
            f"<td>{vuln.description} {exploit_badge}</td>"
            f"<td>{vuln.recommendation}</td>"
            "</tr>"
        )

    @staticmethod
    def _html_hardening_row(vuln):
        color = SEVERITY_COLORS.get(vuln.severity, "#6C757D")
        return (
            "<tr>"
            f'<td><span class="sev-dot" style="background:{color}"></span>{vuln.severity.value}</td>'
            f"<td>{vuln.description}</td>"
            f"<td>{vuln.recommendation}</td>"
            "</tr>"
        )

    @staticmethod
    def _html_host_row(host):
        services_str = ", ".join(f"{s.port}/{s.protocol} {s.service_name}" for s in host.services) or "cap servei detectat"
        return (
            "<tr>"
            f"<td>{host.ip}</td><td>{host.hostname or '-'}</td><td>{host.mac or '-'}</td>"
            f"<td>{host.os_guess or 'Desconegut'}</td><td>{services_str}</td>"
            "</tr>"
        )

    # ------------------------------------------------------------------ #
    # PDF
    # ------------------------------------------------------------------ #
    def generate_pdf(self, output_path):
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        findings = self._collect_findings()
        counts = self._summary_counts(findings)
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f[2].severity))
        now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TitleCustom", parent=styles["Title"], textColor=colors.HexColor("#0d2137"))
        heading_style = ParagraphStyle("HeadingCustom", parent=styles["Heading2"], textColor=colors.HexColor("#0d2137"))
        normal_style = styles["BodyText"]

        doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=20 * mm, bottomMargin=20 * mm)
        story = [
            Paragraph("Informe d'Auditoria de Seguretat Informàtica", title_style),
            Paragraph(f"{self.company_name} &middot; {self.app_name}", normal_style),
            Paragraph(f"Objectiu: {self.session.target or 'No especificat'} — Generat el {now}", normal_style),
            Spacer(1, 12),
            Paragraph("Resum Executiu", heading_style),
            Paragraph(
                f"S'han analitzat {len(self.session.hosts)} equip(s) i detectat {len(findings)} troballa(es) "
                "de seguretat.",
                normal_style,
            ),
        ]

        summary_data = [["Gravetat", "Nombre"]] + [[sev.value, str(counts.get(sev, 0))] for sev in SEVERITY_ORDER]
        story.append(self._styled_table(summary_data, [80 * mm, 40 * mm]))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Inventari d'Equips Detectats", heading_style))
        host_data = [["IP", "Host", "MAC", "SO", "Serveis"]]
        for host in self.session.hosts:
            services_str = ", ".join(f"{s.port}/{s.protocol}" for s in host.services) or "-"
            host_data.append([host.ip, host.hostname or "-", host.mac or "-", host.os_guess or "Desconegut", services_str])
        if len(host_data) == 1:
            host_data.append(["-", "-", "-", "-", "-"])
        story.append(self._styled_table(host_data, [28 * mm, 30 * mm, 30 * mm, 35 * mm, 47 * mm]))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Matriu de Troballes i Vulnerabilitats", heading_style))
        finding_data = [["Gravetat", "Equip", "Servei", "CVE", "Descripció"]]
        for host, service, vuln in findings_sorted:
            finding_data.append(
                [
                    vuln.severity.value,
                    host.ip,
                    f"{service.port}/{service.protocol}",
                    vuln.cve_id,
                    Paragraph(vuln.description[:220], normal_style),
                ]
            )
        if len(finding_data) == 1:
            finding_data.append(["-", "-", "-", "-", "Cap vulnerabilitat detectada."])
        story.append(self._styled_table(finding_data, [20 * mm, 25 * mm, 25 * mm, 30 * mm, 70 * mm]))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Reforçament del Sistema Local (Hardening)", heading_style))
        hardening_sorted = sorted(self.session.hardening_findings, key=lambda v: SEVERITY_ORDER.index(v.severity))
        hardening_data = [["Gravetat", "Descripció", "Recomanació"]]
        for vuln in hardening_sorted:
            hardening_data.append(
                [vuln.severity.value, Paragraph(vuln.description[:200], normal_style), Paragraph(vuln.recommendation[:200], normal_style)]
            )
        if len(hardening_data) == 1:
            hardening_data.append(["-", "No s'ha executat cap auditoria de reforçament del sistema local.", "-"])
        story.append(self._styled_table(hardening_data, [22 * mm, 74 * mm, 74 * mm]))
        story.append(Spacer(1, 16))

        story.append(Paragraph("Pla de Millora", heading_style))
        for item in IMPROVEMENT_PLAN:
            story.append(Paragraph(f"• {item}", normal_style))

        doc.build(story)
        return output_path

    # ------------------------------------------------------------------ #
    # JSON / CSV
    # ------------------------------------------------------------------ #
    def generate_json(self, output_path):
        """Exporta totes les troballes (xarxa + reforçament) en format JSON per a integració

        amb altres eines (SIEM, fulls de càlcul, scripts propis, etc.).
        """
        import json

        findings = self._collect_findings()
        data = {
            "empresa": self.company_name,
            "eina": self.app_name,
            "objectiu": self.session.target,
            "generat_el": datetime.datetime.now().isoformat(),
            "equips": [
                {
                    "ip": host.ip,
                    "hostname": host.hostname,
                    "mac": host.mac,
                    "sistema_operatiu": host.os_guess,
                    "serveis": [
                        {
                            "port": s.port,
                            "protocol": s.protocol,
                            "servei": s.service_name,
                            "producte": s.product,
                            "versio": s.version,
                            "vulnerabilitats": [
                                {
                                    "cve": v.cve_id,
                                    "gravetat": v.severity.value,
                                    "cvss": v.cvss_score,
                                    "descripcio": v.description,
                                    "exploit_conegut": v.exploit_available,
                                    "font_exploit": v.exploit_source,
                                    "recomanacio": v.recommendation,
                                }
                                for v in s.vulnerabilities
                            ],
                        }
                        for s in host.services
                    ],
                }
                for host in self.session.hosts
            ],
            "reforcament_sistema_local": [
                {
                    "gravetat": v.severity.value,
                    "descripcio": v.description,
                    "recomanacio": v.recommendation,
                }
                for v in self.session.hardening_findings
            ],
            "total_troballes": len(findings) + len(self.session.hardening_findings),
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return output_path

    def generate_csv(self, output_path):
        """Exporta la matriu de troballes (xarxa + reforçament) en format CSV."""
        import csv

        findings = self._collect_findings()
        findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.index(f[2].severity))

        with open(output_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Gravetat", "Equip", "Servei", "CVE", "Descripció", "Exploit conegut", "Recomanació"])
            for host, service, vuln in findings_sorted:
                writer.writerow(
                    [
                        vuln.severity.value,
                        host.ip,
                        f"{service.port}/{service.protocol} {service.product or service.service_name}",
                        vuln.cve_id,
                        vuln.description,
                        "Sí" if vuln.exploit_available else "No",
                        vuln.recommendation,
                    ]
                )
            for vuln in self.session.hardening_findings:
                writer.writerow(
                    [vuln.severity.value, "Sistema Local", "-", vuln.cve_id, vuln.description, "No", vuln.recommendation]
                )
        return output_path

    @staticmethod
    def _styled_table(data, col_widths):
        from reportlab.lib import colors
        from reportlab.platypus import Table, TableStyle

        table = Table(data, colWidths=col_widths)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0d2137")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ]
            )
        )
        return table
