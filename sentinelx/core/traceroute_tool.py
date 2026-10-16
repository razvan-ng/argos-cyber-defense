"""Traçat de rutes de xarxa fent servir `traceroute` o, com a alternativa,

`tracepath` quan el primer no estigui disponible (habitual en instal·lacions
mínimes de Debian/Ubuntu).
"""
import re
import shutil

from core.models import TracerouteHop
from utils.shell import CommandRunner

_IP_RE = re.compile(r"\(([\d.:a-fA-F]+)\)")
_RTT_RE = re.compile(r"([\d.]+)\s*ms")


class TracerouteRunner:
    def __init__(self):
        self.runner = CommandRunner()

    @staticmethod
    def _resolve_binary():
        if shutil.which("traceroute"):
            return "traceroute"
        if shutil.which("tracepath"):
            return "tracepath"
        return None

    def trace(self, target, on_output, on_result, on_done, max_hops=30):
        binary = self._resolve_binary()
        if not binary:
            on_output("[ERROR] No s'ha trobat 'traceroute' ni 'tracepath' al sistema.")
            on_done(-1)
            return

        if binary == "traceroute":
            command = ["traceroute", "-m", str(max_hops), target]
        else:
            command = ["tracepath", target]

        collected_lines = []

        def capture(line):
            collected_lines.append(line)
            on_output(line)

        def done(returncode):
            hops = self._parse_hops(collected_lines)
            on_result(hops)
            on_done(returncode)

        self.runner.run_async(command, capture, done)

    @staticmethod
    def _parse_hops(lines):
        hops = []
        for line in lines:
            stripped = line.strip()
            if not stripped or not stripped[0].isdigit():
                continue
            parts = stripped.split()
            try:
                hop_num = int(parts[0])
            except ValueError:
                continue

            ip_match = _IP_RE.search(stripped)
            ip = ip_match.group(1) if ip_match else ""
            hostname = parts[1] if len(parts) > 1 and not parts[1].startswith("*") else ""
            if "*" in stripped and not ip:
                hostname = hostname or "sense resposta"

            rtt_match = _RTT_RE.search(stripped)
            rtt = float(rtt_match.group(1)) if rtt_match else None

            hops.append(TracerouteHop(hop_number=hop_num, ip=ip, hostname=hostname, rtt_ms=rtt))
        return hops

    def terminate(self):
        self.runner.terminate()
