"""Auditoria del sistema local: interfícies, connexions, processos, usuaris,

estat del tallafocs (ufw) i reforçament (hardening): actualitzacions pendents,
binaris amb bit SUID/SGID, comptes addicionals amb UID 0 i comptes sense
contrasenya. Basat en `psutil` per a la part multiplataforma i en eines/
fitxers propis de Linux (apt, /etc/passwd, /etc/shadow) per a la resta.
"""
import getpass
import os
import platform
import shutil
import stat
import subprocess

import psutil

from core.models import Severity, Vulnerability
from utils.shell import CommandRunner


class SystemAuditor:
    SUID_SEARCH_DIRS = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin"]

    def __init__(self):
        self.runner = CommandRunner()

    def get_interfaces(self):
        interfaces = []
        addrs = psutil.net_if_addrs()
        stats = psutil.net_if_stats()
        for name, addr_list in addrs.items():
            info = {
                "name": name,
                "is_up": stats[name].isup if name in stats else False,
                "addresses": [
                    {"family": str(addr.family), "address": addr.address, "netmask": addr.netmask}
                    for addr in addr_list
                ],
            }
            interfaces.append(info)
        return interfaces

    def get_connections(self):
        connections = []
        try:
            for conn in psutil.net_connections(kind="inet"):
                connections.append(
                    {
                        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                        "raddr": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                        "status": conn.status,
                        "pid": conn.pid,
                    }
                )
        except (psutil.AccessDenied, PermissionError):
            pass
        return connections

    def get_processes(self):
        processes = []
        for proc in psutil.process_iter(["pid", "name", "username", "cpu_percent", "memory_percent"]):
            try:
                processes.append(proc.info)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return processes

    def get_users(self):
        return [
            {"name": u.name, "terminal": u.terminal, "host": u.host, "started": u.started}
            for u in psutil.users()
        ]

    def get_current_user(self):
        return getpass.getuser()

    def get_platform_summary(self):
        return {
            "system": platform.system(),
            "node": platform.node(),
            "release": platform.release(),
            "version": platform.version(),
            "machine": platform.machine(),
        }

    def check_firewall_status(self, on_output, on_done):
        if platform.system() != "Linux":
            on_output("[INFO] La comprovació de tallafocs (ufw) només està disponible a Linux.")
            on_done(-1)
            return
        self.runner.run_async(["sudo", "ufw", "status", "verbose"], on_output, on_done)

    # ------------------------------------------------------------------ #
    # Reforçament (hardening)
    # ------------------------------------------------------------------ #
    def get_pending_updates(self):
        """Retorna (nombre_actualitzacions, sortida_completa) via `apt list --upgradable`."""
        if platform.system() != "Linux" or not shutil.which("apt"):
            return None, "Només disponible a Linux amb apt."
        try:
            result = subprocess.run(["apt", "list", "--upgradable"], capture_output=True, text=True, timeout=15)
            lines = [line for line in result.stdout.splitlines() if line and not line.startswith("Listing...")]
            return len(lines), result.stdout
        except (subprocess.TimeoutExpired, OSError) as exc:
            return None, str(exc)

    def find_suid_sgid_binaries(self):
        """Cerca binaris amb bit SUID/SGID actiu en directoris habituals de binaris.

        Es limita a directoris coneguts (no tot el sistema de fitxers) per
        mantenir la comprovació ràpida i evitar una allau de permisos denegats.
        """
        findings = []
        for directory in self.SUID_SEARCH_DIRS:
            if not os.path.isdir(directory):
                continue
            try:
                entries = os.listdir(directory)
            except OSError:
                continue
            for name in entries:
                path = os.path.join(directory, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_mode & stat.S_ISUID:
                    findings.append({"path": path, "bit": "SUID"})
                elif st.st_mode & stat.S_ISGID:
                    findings.append({"path": path, "bit": "SGID"})
        return findings

    def find_extra_root_accounts(self):
        """Retorna comptes amb UID 0 diferents de 'root' (senyal clàssic de compromís)."""
        findings = []
        try:
            with open("/etc/passwd", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 3 and parts[2] == "0" and parts[0] != "root":
                        findings.append(parts[0])
        except OSError:
            pass
        return findings

    def find_empty_password_accounts(self):
        """Retorna comptes sense contrasenya establerta (camp buit a /etc/shadow).

        Requereix permisos de lectura sobre /etc/shadow (normalment només root).
        Retorna None (en lloc d'una llista buida) quan no s'ha pogut comprovar,
        per distingir "cap trobat" de "no verificat".
        """
        findings = []
        try:
            with open("/etc/shadow", "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 2 and parts[1] == "":
                        findings.append(parts[0])
        except PermissionError:
            return None
        except OSError:
            return None
        return findings

    def run_hardening_audit(self):
        """Executa totes les comprovacions de reforçament i les retorna com a Vulnerability."""
        findings = []

        update_count, _ = self.get_pending_updates()
        if update_count:
            findings.append(
                Vulnerability(
                    cve_id="N/A",
                    description=f"Hi ha {update_count} paquet(s) amb actualitzacions pendents.",
                    severity=Severity.MEDIUM,
                    cvss_score=None,
                    reference_url="",
                    recommendation="Executar 'sudo apt update && sudo apt upgrade' per aplicar els pedaços pendents.",
                )
            )

        for entry in self.find_suid_sgid_binaries():
            findings.append(
                Vulnerability(
                    cve_id="N/A",
                    description=f"Binari amb bit {entry['bit']} actiu: {entry['path']}",
                    severity=Severity.LOW,
                    cvss_score=None,
                    reference_url="",
                    recommendation="Revisar si el bit SUID/SGID és realment necessari per a aquest binari.",
                )
            )

        for user in self.find_extra_root_accounts():
            findings.append(
                Vulnerability(
                    cve_id="N/A",
                    description=f"Compte addicional amb privilegis de root (UID 0): '{user}'.",
                    severity=Severity.CRITICAL,
                    cvss_score=None,
                    reference_url="",
                    recommendation="Investigar immediatament aquest compte; podria indicar una porta del darrere.",
                )
            )

        empty_password_accounts = self.find_empty_password_accounts()
        if empty_password_accounts is None:
            findings.append(
                Vulnerability(
                    cve_id="N/A",
                    description="No s'ha pogut comprovar si hi ha comptes sense contrasenya (calen privilegis root).",
                    severity=Severity.INFO,
                    cvss_score=None,
                    reference_url="",
                    recommendation="Executar l'aplicació amb sudo per completar aquesta comprovació.",
                )
            )
        else:
            for user in empty_password_accounts:
                findings.append(
                    Vulnerability(
                        cve_id="N/A",
                        description=f"El compte '{user}' no té contrasenya establerta.",
                        severity=Severity.CRITICAL,
                        cvss_score=None,
                        reference_url="",
                        recommendation="Establir una contrasenya forta o bloquejar el compte immediatament.",
                    )
                )

        return findings
