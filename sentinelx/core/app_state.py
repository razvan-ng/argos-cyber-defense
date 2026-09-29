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

    def set_hosts(self, hosts):
        self.session.hosts = hosts

    def merge_hosts(self, new_hosts):
        """Combina els resultats d'un nou escaneig amb els equips ja coneguts.

        Es fa servir quan l'escaneig de ports s'executa després d'un ping
        sweep, per no perdre equips ja descoberts.
        """
        existing = {h.ip: h for h in self.session.hosts}
        for new_host in new_hosts:
            if new_host.ip in existing:
                current = existing[new_host.ip]
                current.services = new_host.services
                if new_host.os_guess:
                    current.os_guess = new_host.os_guess
                if new_host.mac:
                    current.mac = new_host.mac
                if new_host.hostname:
                    current.hostname = new_host.hostname
            else:
                existing[new_host.ip] = new_host
        self.session.hosts = list(existing.values())

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
