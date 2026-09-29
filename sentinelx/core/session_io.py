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


def compare_sessions(current, baseline):
    """Compara la sessió `current` amb una `baseline` (auditoria anterior).

    Retorna un dict amb:
      - new_hosts: equips presents ara però no al baseline
      - removed_hosts: equips presents al baseline però no ara
      - new_services: llista de (ip, ServiceInfo) — ports/serveis nous en equips ja coneguts
      - new_vulnerabilities: llista de (ip, port_label, Vulnerability) — troballes noves
    """
    baseline_by_ip = {h.ip: h for h in baseline.hosts}
    current_by_ip = {h.ip: h for h in current.hosts}

    new_hosts = [h for ip, h in current_by_ip.items() if ip not in baseline_by_ip]
    removed_hosts = [h for ip, h in baseline_by_ip.items() if ip not in current_by_ip]

    new_services = []
    new_vulnerabilities = []

    for ip, host in current_by_ip.items():
        baseline_host = baseline_by_ip.get(ip)
        if baseline_host is None:
            continue

        baseline_ports = {(s.port, s.protocol) for s in baseline_host.services}
        baseline_cves = {
            (s.port, s.protocol, v.cve_id) for s in baseline_host.services for v in s.vulnerabilities
        }

        for service in host.services:
            if (service.port, service.protocol) not in baseline_ports:
                new_services.append((ip, service))
            for vuln in service.vulnerabilities:
                key = (service.port, service.protocol, vuln.cve_id)
                if key not in baseline_cves:
                    new_vulnerabilities.append((ip, f"{service.port}/{service.protocol}", vuln))

    return {
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "new_services": new_services,
        "new_vulnerabilities": new_vulnerabilities,
    }
