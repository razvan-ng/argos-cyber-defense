"""Desar/carregar sessions d'auditoria en format JSON i comparar-les (baseline).

Permet pausar i reprendre una auditoria, arxivar-ne els resultats, o comparar
l'estat actual d'una xarxa amb una auditoria anterior per detectar canvis
(nous ports oberts, noves vulnerabilitats, equips que han aparegut o
desaparegut) — una funcionalitat habitual en eines d'auditoria contínua.
"""
import json

from core.models import AuditSession, HostResult, ServiceInfo, Severity, TracerouteHop, Vulnerability

FORMAT_VERSION = 1


def _vulnerability_to_dict(v):
    return {
        "cve_id": v.cve_id,
        "description": v.description,
        "severity": v.severity.value,
        "cvss_score": v.cvss_score,
        "reference_url": v.reference_url,
        "exploit_available": v.exploit_available,
        "exploit_source": v.exploit_source,
        "recommendation": v.recommendation,
    }


def _vulnerability_from_dict(d):
    try:
        severity = Severity(d.get("severity", Severity.MEDIUM.value))
    except ValueError:
        severity = Severity.MEDIUM
    return Vulnerability(
        cve_id=d.get("cve_id", ""),
        description=d.get("description", ""),
        severity=severity,
        cvss_score=d.get("cvss_score"),
        reference_url=d.get("reference_url", ""),
        exploit_available=d.get("exploit_available", False),
        exploit_source=d.get("exploit_source", ""),
        recommendation=d.get("recommendation", ""),
    )


def _service_to_dict(s):
    return {
        "port": s.port,
        "protocol": s.protocol,
        "service_name": s.service_name,
        "product": s.product,
        "version": s.version,
        "state": s.state,
        "vulnerabilities": [_vulnerability_to_dict(v) for v in s.vulnerabilities],
    }


def _service_from_dict(d):
    return ServiceInfo(
        port=d.get("port", 0),
        protocol=d.get("protocol", "tcp"),
        service_name=d.get("service_name", ""),
        product=d.get("product", ""),
        version=d.get("version", ""),
        state=d.get("state", "open"),
        vulnerabilities=[_vulnerability_from_dict(v) for v in d.get("vulnerabilities", [])],
    )


def _host_to_dict(h):
    return {
        "ip": h.ip,
        "hostname": h.hostname,
        "mac": h.mac,
        "os_guess": h.os_guess,
        "status": h.status,
        "services": [_service_to_dict(s) for s in h.services],
    }


def _host_from_dict(d):
    return HostResult(
        ip=d.get("ip", ""),
        hostname=d.get("hostname", ""),
        mac=d.get("mac", ""),
        os_guess=d.get("os_guess", ""),
        status=d.get("status", "up"),
        services=[_service_from_dict(s) for s in d.get("services", [])],
    )


def _hop_to_dict(hop):
    return {"hop_number": hop.hop_number, "ip": hop.ip, "hostname": hop.hostname, "rtt_ms": hop.rtt_ms}


def _hop_from_dict(d):
    return TracerouteHop(
        hop_number=d.get("hop_number", 0), ip=d.get("ip", ""),
        hostname=d.get("hostname", ""), rtt_ms=d.get("rtt_ms"),
    )


def session_to_dict(session):
    return {
        "format_version": FORMAT_VERSION,
        "target": session.target,
        "hosts": [_host_to_dict(h) for h in session.hosts],
        "traceroute_hops": [_hop_to_dict(h) for h in session.traceroute_hops],
        "local_system_info": session.local_system_info,
        "hardening_findings": [_vulnerability_to_dict(v) for v in session.hardening_findings],
    }


def session_from_dict(data):
    session = AuditSession()
    session.target = data.get("target", "")
    session.hosts = [_host_from_dict(h) for h in data.get("hosts", [])]
    session.traceroute_hops = [_hop_from_dict(h) for h in data.get("traceroute_hops", [])]
    session.local_system_info = data.get("local_system_info", {})
    session.hardening_findings = [_vulnerability_from_dict(v) for v in data.get("hardening_findings", [])]
    return session


def save_session(session, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(session_to_dict(session), f, ensure_ascii=False, indent=2)
    return path


def load_session(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return session_from_dict(data)


def _finding_key(port, protocol, vuln):
    """Identificador d'una troballa: el CVE o, si no en té, l'inici de la descripció."""
    ident = vuln.cve_id if vuln.cve_id and vuln.cve_id != "N/A" else vuln.description[:120].lower()
    return (port, protocol, ident)


def compare_sessions(current, baseline):
    """Compara la sessió `current` amb una `baseline` (auditoria anterior).

    Retorna un dict amb:
      - new_hosts: equips presents ara però no al baseline
      - removed_hosts: equips presents al baseline però no ara
      - new_services: llista de (ip, ServiceInfo) — ports/serveis nous en equips ja coneguts
      - closed_services: llista de (ip, ServiceInfo) — ports que ja no estan oberts
      - new_vulnerabilities: llista de (ip, port_label, Vulnerability) — troballes noves
      - resolved_vulnerabilities: troballes del baseline que ja no apareixen en equips tornats a analitzar
      - persistent_vulnerabilities: troballes que continuen presents
      - unverified_vulnerabilities: troballes del baseline en equips que ara no s'han detectat
      - resolved_hardening / new_hardening: canvis en el reforçament del sistema local
    """
    baseline_by_ip = {h.ip: h for h in baseline.hosts}
    current_by_ip = {h.ip: h for h in current.hosts}

    result = {
        "new_hosts": [h for ip, h in current_by_ip.items() if ip not in baseline_by_ip],
        "removed_hosts": [h for ip, h in baseline_by_ip.items() if ip not in current_by_ip],
        "new_services": [],
        "closed_services": [],
        "new_vulnerabilities": [],
        "resolved_vulnerabilities": [],
        "persistent_vulnerabilities": [],
        "unverified_vulnerabilities": [],
        "resolved_hardening": [],
        "new_hardening": [],
    }

    for ip, host in current_by_ip.items():
        baseline_host = baseline_by_ip.get(ip)
        if baseline_host is None:
            for service in host.services:
                for vuln in service.vulnerabilities:
                    result["new_vulnerabilities"].append((ip, f"{service.port}/{service.protocol}", vuln))
            continue

        baseline_ports = {(s.port, s.protocol) for s in baseline_host.services}
        current_ports = {(s.port, s.protocol) for s in host.services}
        baseline_findings = {
            _finding_key(s.port, s.protocol, v): (s, v) for s in baseline_host.services for v in s.vulnerabilities
        }
        current_findings = {
            _finding_key(s.port, s.protocol, v): (s, v) for s in host.services for v in s.vulnerabilities
        }

        for service in host.services:
            if (service.port, service.protocol) not in baseline_ports:
                result["new_services"].append((ip, service))
        for service in baseline_host.services:
            if (service.port, service.protocol) not in current_ports:
                result["closed_services"].append((ip, service))

        for key, (service, vuln) in current_findings.items():
            label = f"{service.port}/{service.protocol}"
            bucket = "persistent_vulnerabilities" if key in baseline_findings else "new_vulnerabilities"
            result[bucket].append((ip, label, vuln))
        for key, (service, vuln) in baseline_findings.items():
            if key not in current_findings:
                result["resolved_vulnerabilities"].append((ip, f"{service.port}/{service.protocol}", vuln))

    for host in result["removed_hosts"]:
        for service in host.services:
            for vuln in service.vulnerabilities:
                result["unverified_vulnerabilities"].append((host.ip, f"{service.port}/{service.protocol}", vuln))

    # El reforçament només es pot comparar si a la sessió actual també s'ha executat
    if current.hardening_findings:
        before = {v.description for v in baseline.hardening_findings}
        after = {v.description for v in current.hardening_findings}
        result["resolved_hardening"] = [v for v in baseline.hardening_findings if v.description not in after]
        result["new_hardening"] = [v for v in current.hardening_findings if v.description not in before]

    return result


def session_from_report_data(data):
    """Converteix les dades d'un informe (format de build_report_data o del portal) en una sessió.

    Serveix per carregar l'auditoria anterior d'un expedient i comparar-hi la reauditoria.
    """
    def vulnerability(d):
        try:
            severity = Severity(d.get("gravetat", Severity.MEDIUM.value))
        except ValueError:
            severity = Severity.MEDIUM
        return Vulnerability(
            cve_id=d.get("cve") or "N/A",
            description=d.get("descripcio", ""),
            severity=severity,
            cvss_score=d.get("cvss"),
            reference_url=d.get("referencia", ""),
            exploit_available=bool(d.get("exploit_conegut", False)),
            exploit_source=d.get("font_exploit", ""),
            recommendation=d.get("recomanacio", ""),
        )

    session = AuditSession()
    session.target = data.get("objectiu", "")
    for h in data.get("equips", []):
        host = HostResult(
            ip=h.get("ip", ""), hostname=h.get("hostname", ""), mac=h.get("mac", ""),
            os_guess=h.get("sistema_operatiu", ""),
        )
        for s in h.get("serveis", []):
            host.services.append(ServiceInfo(
                port=int(s.get("port", 0) or 0),
                protocol=s.get("protocol", "tcp"),
                service_name=s.get("servei", ""),
                product=s.get("producte", ""),
                version=s.get("versio", ""),
                state=s.get("estat", "open"),
                vulnerabilities=[vulnerability(v) for v in s.get("vulnerabilitats", [])],
            ))
        session.hosts.append(host)
    session.hardening_findings = [vulnerability(v) for v in data.get("reforcament_sistema_local", [])]
    session.traceroute_hops = [
        TracerouteHop(hop_number=int(t.get("salt", 0) or 0), ip=t.get("ip", ""), hostname=t.get("hostname", ""), rtt_ms=t.get("rtt_ms"))
        for t in data.get("tracat_ruta", [])
    ]
    return session
