"""Escaneig actiu de vulnerabilitats amb els scripts NSE de nmap (pestanya Vulnerabilitats i CVE).

La sortida normal de nmap es retransmet en directe als logs de la interfície i, alhora, s'escriu
un fitxer XML temporal d'on s'extreuen les troballes. El descobriment d'equips i l'escaneig de
ports i serveis per modalitats són a core/nmap_modes.py.
"""
import os
import tempfile
import xml.etree.ElementTree as ET

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

    def terminate(self):
        self.runner.terminate()
