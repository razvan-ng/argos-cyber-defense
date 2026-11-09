"""Estat compartit de l'aplicació entre pestanyes de la interfície gràfica."""
from core.models import AuditSession, HostResult, ServiceInfo, Severity

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class AppState:
    """Contenidor senzill que manté la sessió d'auditoria en curs.

    Es passa per referència a totes les pestanyes perquè puguin llegir
    i actualitzar els mateixos resultats (equips, serveis, traçat, etc.).
    """

    def __init__(self):
        self.session = AuditSession()
        # Mode Segur: activat per defecte. Les accions més intrusives o
        # lentes (escaneig complet de ports, UDP, scripts actius NSE)
        # requereixen confirmació explícita mentre estigui actiu.
        self.safe_mode = True

        # Expedient del portal en què es treballa (connexió directa o mode fitxer)
        self.active_expedient = None      # dict amb id, codi, titol, objectiu, empresa...
        self.baseline_session = None      # auditoria anterior de l'expedient (per a reauditories)
        self.baseline_title = ""
        self.portal_mode = ""             # "api" (connexió directa) o "fitxer"
        self.portal_draft_id = None       # esborrany del portal que s'actualitza automàticament

    def set_hosts(self, hosts):
        self.session.hosts = hosts

    def merge_scan(self, new_hosts):
        """Combina un escaneig de ports amb la sessió port per port (core/nmap_modes.py).

        Un escaneig parcial (uns quants ports o una modalitat sense -sV) no esborra els serveis
        dels altres ports ni el producte i la versió ja coneguts; les vulnerabilitats noves s'afegeixen
        sense repetir les que ja hi eren.
        """
        existing = {h.ip: h for h in self.session.hosts}
        for new_host in new_hosts:
            current = existing.get(new_host.ip)
            if current is None:
                self.session.hosts.append(new_host)
                existing[new_host.ip] = new_host
                continue
            for attr in ("hostname", "mac", "os_guess"):
                if getattr(new_host, attr):
                    setattr(current, attr, getattr(new_host, attr))
            services = {(s.port, s.protocol): s for s in current.services}
            for service in new_host.services:
                old = services.get((service.port, service.protocol))
                if old is None:
                    current.services.append(service)
                    continue
                old.state = service.state
                for attr in ("service_name", "product", "version"):
                    if getattr(service, attr):
                        setattr(old, attr, getattr(service, attr))
                known = {(v.cve_id, v.description[:80]) for v in old.vulnerabilities}
                old.vulnerabilities.extend(v for v in service.vulnerabilities
                                           if (v.cve_id, v.description[:80]) not in known)
            current.services.sort(key=lambda s: (s.port, s.protocol))

    def add_passive_host(self, new_host):
        """Afegeix a la sessió un equip conegut per reconeixement passiu (Shodan).

        A diferència de merge_scan, no substitueix els serveis que ja ha trobat un escaneig
        actiu: només hi afegeix els ports que encara no hi eren. Retorna quants n'ha afegit.
        """
        current = next((h for h in self.session.hosts if h.ip == new_host.ip), None)
        if current is None:
            self.session.hosts.append(new_host)
            return len(new_host.services)
        known = {(s.port, s.protocol) for s in current.services}
        added = [s for s in new_host.services if (s.port, s.protocol) not in known]
        current.services.extend(added)
        current.services.sort(key=lambda s: (s.port, s.protocol))
        if not current.hostname:
            current.hostname = new_host.hostname
        if not current.os_guess:
            current.os_guess = new_host.os_guess
        return len(added)

    def set_traceroute(self, hops):
        self.session.traceroute_hops = hops

    def set_local_system_info(self, info):
        self.session.local_system_info = info

    def set_hardening_findings(self, findings):
        self.session.hardening_findings = findings

    def add_finding_by_ip_port(self, ip, port, protocol, vulnerability):
        """Afegeix una vulnerabilitat trobada activament (p. ex. via scripts NSE) a

        l'equip/servei corresponent, creant l'equip o el servei si encara no
        existien a la sessió (pot passar si l'escaneig actiu s'executa sobre
        un objectiu que encara no s'havia escanejat amb -sV).
        """
        host = next((h for h in self.session.hosts if h.ip == ip), None)
        if host is None:
            host = HostResult(ip=ip)
            self.session.hosts.append(host)
        service = next((s for s in host.services if s.port == port and s.protocol == protocol), None)
        if service is None:
            service = ServiceInfo(port=port, protocol=protocol, service_name="")
            host.services.append(service)
        service.vulnerabilities.append(vulnerability)

    def load_session(self, session):
        self.session = session

    # ------------------------------------------------------------------ #
    # Expedients del portal
    # ------------------------------------------------------------------ #
    def open_expedient(self, expedient, baseline=None, baseline_title="", mode="api", keep_results=False):
        """Activa un expedient. Si no es conserven els resultats actuals, comença una sessió nova

        amb l'objectiu de l'expedient (reauditoria) i es fa servir l'auditoria anterior com a referència.
        """
        self.active_expedient = expedient
        self.baseline_session = baseline
        self.baseline_title = baseline_title
        self.portal_mode = mode
        self.portal_draft_id = None
        if not keep_results:
            self.session = AuditSession()
        if not self.session.target:
            self.session.target = expedient.get("objectiu", "")

    def close_expedient(self):
        self.active_expedient = None
        self.baseline_session = None
        self.baseline_title = ""
        self.portal_mode = ""
        self.portal_draft_id = None

    def has_results(self):
        return bool(self.session.hosts or self.session.hardening_findings)

    def dashboard_stats(self):
        """Calcula les estadístiques agregades per al Tauler (Dashboard)."""
        total_hosts = len(self.session.hosts)
        total_open_ports = sum(len(h.services) for h in self.session.hosts)

        counts = {sev: 0 for sev in Severity}
        for host in self.session.hosts:
            for service in host.services:
                for vuln in service.vulnerabilities:
                    counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        for vuln in self.session.hardening_findings:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1

        total_findings = sum(counts.values())
        return {
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "total_findings": total_findings,
            "severity_counts": counts,
            "target": self.session.target,
        }

    def top_priority_findings(self, limit=8):
        """Retorna les troballes (vuln, ubicació) més urgents de mitigar.

        Ordenades per gravetat i, dins d'una mateixa gravetat, prioritzant
        les que tenen un exploit públic conegut — la vista "Què cal arreglar
        primer?" d'una eina d'auditoria professional.
        """
        entries = []
        for host in self.session.hosts:
            for service in host.services:
                for vuln in service.vulnerabilities:
                    entries.append((vuln, f"{host.ip}:{service.port}/{service.protocol}"))
        for vuln in self.session.hardening_findings:
            entries.append((vuln, "Sistema Local"))

        entries.sort(key=lambda item: (_SEVERITY_RANK.get(item[0].severity, 5), not item[0].exploit_available))
        return entries[:limit]
