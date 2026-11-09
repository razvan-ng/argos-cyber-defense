"""Escaneig de xarxa amb Nmap per modalitats (llibreria python-nmap).

Parteix de l'script escaneig.py de Mouhammed Oualy: les quatre modalitats, la llibreria
python-nmap (nmap.PortScanner) i el format dels resultats són els seus. Aquí s'hi afegeix la
validació de l'objectiu i dels ports, l'opció «tots els ports» i la conversió dels resultats al
model de SentinelX, perquè els facin servir la pestanya Auditoria de Xarxa i l'script escaneig.py.

Modalitats:
  1. Descobriment d'hosts actius a la xarxa (-sn).
  2. Ports oberts d'un host o rang de hosts.
  3. Serveis i versions d'un port, un rang de ports o tots els ports (-sV).
  4. Vulnerabilitats conegudes dels serveis amb els scripts NSE de la categoria «vuln».
"""
import ipaddress
import re
import time

from core.models import HostResult, ServiceInfo, Severity, Vulnerability
from core.vuln_correlator import VulnerabilityCorrelator

try:
    import nmap
except ImportError:  # SentinelX arrenca igualment; la pestanya i l'script avisen que falta
    nmap = None

MODES = {
    1: "Descobriment d'hosts actius a la xarxa",
    2: "Ports oberts d'un host o rang de hosts",
    3: "Serveis i versions dels ports",
    4: "Vulnerabilitats conegudes (scripts NSE «vuln»)",
}
ALL_PORTS = "1-65535"
INTRUSIVE_MODES = {4}  # els scripts NSE interactuen amb els serveis: cal autorització i confirmació

_TARGET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:/]*$")
_PORTS_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")
# Línies de l'script «vulners»: «CVE-2024-6387  8.1  https://vulners.com/cve/CVE-2024-6387»
_VULNERS_RE = re.compile(r"(CVE-\d{4}-\d{4,7})\s+(\d+(?:\.\d+)?)\s+(https?://\S+)")
MAX_VULNERS_PER_SERVICE = 20


class NmapModeError(Exception):
    """Error amb un missatge apte per mostrar a l'usuari."""


def library_available():
    return nmap is not None


def validate_target(text):
    """IP, subxarxa (192.168.1.0/24), rang (192.168.1.1-20) o nom de host. Mai opcions de nmap."""
    target = (text or "").strip()
    if not target:
        raise NmapModeError("Escriviu l'host o la xarxa objectiu (p. ex. 192.168.1.1 o 192.168.1.0/24).")
    if not _TARGET_RE.match(target):
        raise NmapModeError(f"«{target}» no és un objectiu vàlid: feu servir una IP, una subxarxa, un rang o un nom "
                            "de host, sense espais ni opcions de nmap.")
    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            raise NmapModeError(f"«{target}» no és una subxarxa vàlida.") from None
        if network.num_addresses > 65536:
            raise NmapModeError("La subxarxa és massa gran: com a màxim /16 (65.536 adreces).")
    return target


def normalize_ports(text):
    """«» (els 1.000 ports habituals de nmap), «tots» (1-65535) o una llista com 22,80,8000-8100."""
    ports = (text or "").strip().replace(" ", "").lower()
    if ports in ("", "habituals"):
        return ""
    if ports in ("tots", "all", "-", "1-65535"):
        return ALL_PORTS
    if not _PORTS_RE.match(ports):
        raise NmapModeError("Ports no vàlids. Escriviu un port (80), un rang (20-25), una llista (22,80,443) o «tots».")
    for number in re.findall(r"\d+", ports):
        if not 1 <= int(number) <= 65535:
            raise NmapModeError(f"El port {number} no existeix: han d'anar de l'1 al 65535.")
    return ports


def build_arguments(mode, os_detect=False, udp=False):
    """Arguments de nmap de cada modalitat (els ports es passen a part, com fa python-nmap)."""
    if mode == 1:
        return "-sn"
    extra = (" -sU -sS" if udp else "") + (" -O" if os_detect else "")
    if mode == 2:
        return f"--open{extra}"
    if mode == 3:
        return f"-sV --open{extra}"
    if mode == 4:
        return f"-sV --script vuln --open{extra}"
    raise NmapModeError("Modalitat no vàlida: trieu-ne una de l'1 al 4.")


def scan(mode, target, ports="", os_detect=False, udp=False, sudo=False):
    """Executa la modalitat triada i retorna {"command", "elapsed", "lines", "hosts", "findings"}.

    «lines» són els resultats amb el format de l'script original; «hosts» és la llista de
    HostResult (amb les vulnerabilitats confirmades a la modalitat 4) per a la sessió d'auditoria.
    """
    if nmap is None:
        raise NmapModeError("Falta la llibreria python-nmap. Instal·leu-la amb ./install_dependencies.sh "
                            "o amb «venv/bin/pip install python-nmap».")
    target = validate_target(target)
    ports = normalize_ports(ports) if mode != 1 else ""
    arguments = build_arguments(mode, os_detect, udp)
    started = time.time()
    try:
        nm = nmap.PortScanner()
        nm.scan(hosts=target, ports=ports or None, arguments=arguments, sudo=sudo)
    except nmap.PortScannerError as exc:
        raise NmapModeError(_explain_error(str(exc))) from exc
    hosts, findings = _to_hosts(nm, mode)
    return {
        "command": nm.command_line(),
        "elapsed": time.time() - started,
        "lines": format_results(nm, mode),
        "hosts": hosts,
        "findings": findings,
    }


def format_results(nm, mode):
    """Resultats en text, amb el mateix format que imprimia l'script escaneig.py original."""
    lines = []
    if mode == 1:
        lines.append("--- HOSTS ACTIUS TROBATS ---")
        for host in nm.all_hosts():
            if nm[host].state() == "up":
                hostname = nm[host].hostname()
                lines.append(f"Host: {host} ({hostname if hostname else 'Sense nom'}) - Estat: ACTIU")
    elif mode == 2:
        for host in nm.all_hosts():
            lines.append(f"Host: {host} ({nm[host].hostname()})")
            for proto in nm[host].all_protocols():
                lines.append(f" Protocol: {proto.upper()}")
                for port in sorted(nm[host][proto].keys()):
                    lines.append(f"  Port: {port}\tEstat: {nm[host][proto][port]['state']}")
    elif mode == 3:
        for host in nm.all_hosts():
            lines.append(f"Host: {host}")
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    data = nm[host][proto][port]
                    versio = f"{data['product']} {data['version']}".strip()
                    lines.append(f"  Port: {port}/{proto}\tEstat: {data['state']}\tServei: {data['name']}\t"
                                 f"Versió: {versio or 'no identificada'}")
    elif mode == 4:
        for host in nm.all_hosts():
            lines.append(f"=== Vulnerabilitats detectades per a {host} ===")
            for proto in nm[host].all_protocols():
                for port in sorted(nm[host][proto].keys()):
                    data = nm[host][proto][port]
                    if "script" in data:
                        lines.append(f"[+] Port {port}/{proto} - {data['name']}")
                        for script_id, output in data["script"].items():
                            lines.append(f"  - Script [{script_id}]:")
                            lines.extend(f"      {line}" for line in output.strip().splitlines())
                    else:
                        lines.append(f"  Port {port}/{proto}: Sense vulnerabilitats detectades pels scripts.")
            for script in nm[host].get("hostscript", []):  # scripts de l'equip (p. ex. SMB), no d'un port
                lines.append(f"[+] Equip - Script [{script.get('id', '')}]:")
                lines.extend(f"      {line}" for line in (script.get("output") or "").strip().splitlines())
    if len(lines) <= 1:
        lines.append("Cap resultat: no s'ha trobat cap host actiu o cap port obert amb aquests paràmetres.")
    return lines


def summary_lines(hosts):
    """Resum de la modalitat 4: quantes troballes té cada servei i les tres de més puntuació."""
    lines = ["--- RESUM DE VULNERABILITATS PER SERVEI ---"]
    for host in hosts:
        for service in host.services:
            top = sorted(service.vulnerabilities, key=lambda v: -(v.cvss_score or 0))[:3]
            detail = ", ".join(f"{v.cve_id} ({v.cvss_score})" if v.cvss_score else v.cve_id for v in top)
            lines.append(f"{host.ip} {service.port}/{service.protocol} {service.product} {service.version}".rstrip()
                         + f": {len(service.vulnerabilities)} troballa(es)" + (f"; les més greus: {detail}" if detail else ""))
    return lines


def _to_hosts(nm, mode):
    hosts, findings = [], []
    for ip in nm.all_hosts():
        info = nm[ip]
        if info.state() != "up":
            continue
        os_matches = info.get("osmatch") or []
        host = HostResult(ip=ip, hostname=info.hostname(), mac=(info.get("addresses") or {}).get("mac", ""),
                          os_guess=os_matches[0].get("name", "") if os_matches else "", status="up")
        for proto in info.all_protocols():
            for port in sorted(info[proto].keys()):
                data = info[proto][port]
                if data.get("state") != "open":
                    continue
                service = ServiceInfo(port=port, protocol=proto, service_name=data.get("name", ""),
                                      product=data.get("product", ""), version=data.get("version", ""))
                for script_id, output in (data.get("script") or {}).items():
                    if script_id == "vulners":
                        cves = parse_vulners(output, service.product, service.version)
                        service.vulnerabilities.extend(cves)
                        findings.extend({"ip": ip, "port": port, "protocol": proto, "script_id": script_id,
                                         "output": v.cve_id} for v in cves)
                    elif _is_vulnerable(output):
                        finding = {"ip": ip, "port": port, "protocol": proto, "script_id": script_id, "output": output}
                        service.vulnerabilities.append(VulnerabilityCorrelator.vulnerability_from_nse_finding(finding))
                        findings.append(finding)
                host.services.append(service)
        hosts.append(host)
    return hosts, findings


def parse_vulners(output, product="", version=""):
    """CVE coneguts que llista l'script «vulners» per a la versió del servei (els de més puntuació).

    L'script no diu «VULNERABLE»: dona la llista de CVE de la base de dades Vulners per al producte
    i la versió detectats, amb la puntuació CVSS. Els identificadors que no són CVE (exploits de
    GitHub, mòduls d'eines...) no es comptabilitzen com a vulnerabilitats.
    """
    best = {}
    for cve, score, url in _VULNERS_RE.findall(output or ""):
        best[cve] = max(float(score), best.get(cve, (0.0,))[0]), url
    software = f"{product} {version}".strip() or "el servei"
    vulns = []
    for cve, (score, url) in sorted(best.items(), key=lambda item: -item[1][0])[:MAX_VULNERS_PER_SERVICE]:
        vulns.append(Vulnerability(
            cve_id=cve,
            description=f"Vulnerabilitat coneguda {_de(software)} segons l'script NSE vulners de nmap "
                        f"(base de dades Vulners), amb una puntuació CVSS de {score}.",
            severity=_severity(score), cvss_score=score, reference_url=url,
            recommendation=f"Comprovar si {cve} afecta de veritat l'equip (vulners només compara el número de "
                           "versió i distribucions com Ubuntu corregeixen errors sense canviar-lo) i, si és així, "
                           f"actualitzar {software}.",
        ))
    return vulns


def _de(text):
    """«d'OpenSSH», «de ISC BIND»: apòstrof davant de vocal o hac."""
    return f"d'{text}" if text[:1].lower() in "aeiouh" else f"de {text}"


def _severity(score):
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    if score >= 4:
        return Severity.MEDIUM
    return Severity.LOW if score > 0 else Severity.INFO


def _is_vulnerable(output):
    """Mateix criteri que el parser NSE de SentinelX: «VULNERABLE», però no «NOT VULNERABLE»."""
    lower = (output or "").lower()
    return "vulnerable" in lower and "not vulnerable" not in lower and "couldn't find" not in lower


def _explain_error(message):
    lower = message.lower()
    if "nmap program was not found" in lower:
        return "No es troba nmap. Instal·leu-lo amb ./install_dependencies.sh o «sudo apt install nmap»."
    if "requires root" in lower or "root privileges" in lower:
        return "Aquesta opció (-O o -sU) necessita permisos d'administrador: marqueu «Usar sudo» o desmarqueu-la."
    return f"Nmap ha retornat un error: {message.strip()[:300]}"
