"""Auditoria de xarxa: descobriment d'equips i escaneig de ports/serveis.

S'utilitza `nmap` com a motor d'escaneig. Cada execució escriu la sortida
normal a stdout (retransmesa en directe als logs de la interfície) i,
simultàniament, un fitxer XML temporal que es fa servir per extreure
resultats estructurats (equips, ports, serveis, versions, SO).
"""
import os
import tempfile
import xml.etree.ElementTree as ET

from core.models import HostResult, ServiceInfo
from utils.shell import CommandRunner


class NetworkScanner:
    def __init__(self):
        self.runner = CommandRunner()

    @staticmethod
    def _new_xml_path(prefix):
        fd, path = tempfile.mkstemp(suffix=".xml", prefix=prefix)
        os.close(fd)
        return path

    @staticmethod
    def _cleanup(xml_path):
        try:
            if os.path.exists(xml_path):
                os.remove(xml_path)
        except OSError:
            pass

    def ping_sweep(self, subnet, on_output, on_result, on_done):
        """Descobriment d'equips actius amb `nmap -sn` (ping sweep)."""
        xml_path = self._new_xml_path("sentinelx_sweep_")
        command = ["nmap", "-sn", "-oX", xml_path, "-oN", "-", subnet]

        def done(returncode):
            hosts = self._parse_hosts(xml_path) if os.path.exists(xml_path) else []
            self._cleanup(xml_path)
            on_result(hosts)
            on_done(returncode)

        self.runner.run_async(command, on_output, done)

    def port_scan(
        self, target, on_output, on_result, on_done,
        detect_os=False, use_sudo=False, full_ports=False, udp=False, custom_ports="",
    ):
        """Escaneig de ports oberts i detecció de serveis/versions (-sV) i,

        opcionalment, del sistema operatiu (-O, requereix privilegis elevats),
        de tots els ports (-p-), de ports personalitzats, o també per UDP (-sU,
        més lent, també requereix privilegis elevats).
        """
        xml_path = self._new_xml_path("sentinelx_scan_")
        scan_args = ["-sV"]
        if udp:
            scan_args.append("-sU")
        if detect_os:
            scan_args.append("-O")
        if custom_ports.strip():
            scan_args += ["-p", custom_ports.strip()]
        elif full_ports:
            scan_args.append("-p-")
        command = ["nmap", *scan_args, "-oX", xml_path, "-oN", "-", target]
        if use_sudo:
            command = ["sudo", *command]

        def done(returncode):
            hosts = self._parse_hosts(xml_path) if os.path.exists(xml_path) else []
            self._cleanup(xml_path)
            on_result(hosts)
            on_done(returncode)

        self.runner.run_async(command, on_output, done)

    def vuln_scan(self, target, on_output, on_result, on_done, use_sudo=False):
        """Escaneig ACTIU de vulnerabilitats amb els scripts NSE de nmap (--script vuln).

        A diferència de la correlació passiva per versió, aquests scripts
        interactuen amb el servei per confirmar (amb molta més fiabilitat)
        si una vulnerabilitat concreta hi és present.
        """
        xml_path = self._new_xml_path("sentinelx_vulnscan_")
        command = ["nmap", "-sV", "--script", "vuln", "-oX", xml_path, "-oN", "-", target]
        if use_sudo:
            command = ["sudo", *command]

        def done(returncode):
            findings = self._parse_script_findings(xml_path) if os.path.exists(xml_path) else []
            self._cleanup(xml_path)
            on_result(findings)
            on_done(returncode)

        self.runner.run_async(command, on_output, done)

    def _parse_script_findings(self, xml_path):
        """Extreu els resultats dels scripts NSE (categoria 'vuln') del XML."""
        findings = []
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            return findings

        for host_elem in tree.getroot().findall("host"):
            ip = ""
            for addr in host_elem.findall("address"):
                if addr.get("addrtype") in ("ipv4", "ipv6"):
                    ip = addr.get("addr", "")
                    break

            ports_elem = host_elem.find("ports")
            if ports_elem is None:
                continue
            for port_elem in ports_elem.findall("port"):
                port_label = f"{port_elem.get('portid')}/{port_elem.get('protocol', 'tcp')}"
                for script_elem in port_elem.findall("script"):
                    output = (script_elem.get("output") or "").strip()
                    lower_output = output.lower()
                    if not output or "vulnerable" not in lower_output:
                        continue
                    if "not vulnerable" in lower_output or "couldn't find" in lower_output:
                        continue
                    findings.append(
                        {
                            "ip": ip,
                            "port": int(port_elem.get("portid")),
                            "protocol": port_elem.get("protocol", "tcp"),
                            "port_label": port_label,
                            "script_id": script_elem.get("id", ""),
                            "output": output,
                        }
                    )
        return findings

    def _parse_hosts(self, xml_path):
        hosts = []
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError:
            return hosts

        for host_elem in tree.getroot().findall("host"):
            status_elem = host_elem.find("status")
            if status_elem is None or status_elem.get("state") != "up":
                continue

            ip, mac = "", ""
            for addr in host_elem.findall("address"):
                addr_type = addr.get("addrtype")
                if addr_type == "ipv4" or addr_type == "ipv6":
                    ip = addr.get("addr", "")
                elif addr_type == "mac":
                    mac = addr.get("addr", "")

            hostname = ""
            hostnames_elem = host_elem.find("hostnames")
            if hostnames_elem is not None:
                hn = hostnames_elem.find("hostname")
                if hn is not None:
                    hostname = hn.get("name", "")

            os_guess = ""
            os_elem = host_elem.find("os")
            if os_elem is not None:
                match = os_elem.find("osmatch")
                if match is not None:
                    os_guess = match.get("name", "")

            host = HostResult(ip=ip, hostname=hostname, mac=mac, os_guess=os_guess, status="up")

            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    if state_elem is None or state_elem.get("state") != "open":
                        continue
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "") if service_elem is not None else ""
                    product = service_elem.get("product", "") if service_elem is not None else ""
                    version = service_elem.get("version", "") if service_elem is not None else ""
                    host.services.append(
                        ServiceInfo(
                            port=int(port_elem.get("portid")),
                            protocol=port_elem.get("protocol", "tcp"),
                            service_name=service_name,
                            product=product,
                            version=version,
                            state="open",
                        )
                    )
            hosts.append(host)
        return hosts

    def terminate(self):
        self.runner.terminate()
