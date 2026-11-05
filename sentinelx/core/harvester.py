"""Cerca OSINT amb The Harvester (https://github.com/laramies/theHarvester).

The Harvester recull correus, subdominis, adreces IP i noms associats a un domini a partir de
fonts públiques (cercadors, certificats, DNS passiu...), sense escanejar l'objectiu. SentinelX no
el reimplementa: construeix la comanda amb les opcions triades i la llança amb subprocess.

Ho fan servir la pestanya «OSINT» i l'opció 5 de l'script shodan_recon.py.
"""
import json
import os
import re
import shlex
import shutil
import subprocess

SOURCES = ("google", "bing", "linkedin", "all")  # fonts que demana l'activitat
DEFAULT_SOURCE = "all"
DEFAULT_LIMIT = 500
# On el deixa install_dependencies.sh quan no hi ha paquet de la distribució (relatiu a sentinelx/)
LOCAL_EXECUTABLE = os.path.join("tools", "theHarvester", ".venv", "bin", "theHarvester")
INSTALL_HINT = ("No es troba The Harvester. Executeu ./install_dependencies.sh o instal·leu-lo seguint "
                "https://github.com/laramies/theHarvester.")
RESULT_KEYS = (("emails", "Correus"), ("hosts", "Subdominis i hosts"), ("ips", "Adreces IP"),
               ("asns", "ASN"), ("interesting_urls", "URL interessants"), ("linkedin_people", "Persones (LinkedIn)"))

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EXEC_RE = re.compile(r"""exec'?\s+'([^']+)'""")
_SOURCES_CODE = "from theHarvester.lib.core import Core; print(' '.join(Core.get_supportedengines()))"


class HarvesterError(Exception):
    """Error amb un missatge apte per mostrar a l'usuari."""


def find_executable():
    """Ruta de theHarvester: el del PATH o el que instal·la install_dependencies.sh."""
    path = shutil.which("theHarvester")
    if path:
        return path
    local = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), LOCAL_EXECUTABLE)
    return local if os.access(local, os.X_OK) else None


def command_name(executable):
    """«theHarvester» si és al PATH (la comanda es llegeix millor); si no, la ruta completa."""
    return "theHarvester" if shutil.which("theHarvester") == executable else executable


def validate_domain(text):
    domain = (text or "").strip().lower().rstrip(".")
    if not domain:
        raise HarvesterError("Escriviu el domini objectiu (p. ex. iesebre.cat).")
    if not _DOMAIN_RE.match(domain):
        raise HarvesterError(f"«{domain}» no és un domini vàlid. Escriviu-ne un com iesebre.cat, sense http:// ni /.")
    return domain


def supported_sources(executable):
    """Fonts que admet la versió instal·lada, o None si no es pot saber.

    No n'hi ha prou amb «theHarvester -h»: l'ajuda no llista «all» ni «linkedin», tot i que
    funcionen. Per això es pregunta a la mateixa llibreria, amb el Python de l'eina.
    """
    for interpreter in _interpreters(executable):
        try:
            result = subprocess.run([interpreter, "-I", "-c", _SOURCES_CODE], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode == 0 and result.stdout.strip():
            return set(result.stdout.split()) | {"all"}
    return None


def check_source(executable, source):
    """Comprova que la font existeixi a la versió instal·lada (google i bing ja no hi són a la 4.x)."""
    if source not in SOURCES:
        raise HarvesterError(f"Font no vàlida. Trieu-ne una d'aquestes: {', '.join(SOURCES)}.")
    available = supported_sources(executable)
    if available is not None and source not in available:
        offered = [s for s in SOURCES if s in available]
        raise HarvesterError(f"La versió instal·lada de The Harvester ja no té la font «{source}». "
                             f"Trieu {' o '.join(f'«{s}»' for s in offered)}.")


def build_command(domain, source, filename="", limit=DEFAULT_LIMIT, executable="theHarvester"):
    """Cadena de text de la comanda que s'executarà al terminal."""
    command = f"{shlex.quote(executable)} -d {shlex.quote(domain)} -b {shlex.quote(source)} -l {int(limit)}"
    if filename:
        command += f" -f {shlex.quote(filename)}"
    return command


def output_files(filename):
    """Fitxers que genera -f, amb el mateix tractament del nom que fa The Harvester 4.x: canvia
    l'extensió per .xml i .json (ja no genera HTML) i substitueix els caràcters estranys per «_»."""
    if filename.startswith("~/"):
        path = os.path.join(os.path.expanduser("~"), _sanitize(filename[2:]))
    elif os.path.isabs(filename):
        path = os.path.join(os.path.dirname(filename), _sanitize(os.path.basename(filename)))
    else:
        path = _sanitize(filename)
    base = path.rsplit(".", 1)[0] if os.path.splitext(path)[1] else path
    return base + ".xml", base + ".json"


def _sanitize(name):
    name = re.sub(r"_+", "_", re.sub(r"[^a-zA-Z0-9._-]", "_", os.path.basename(name))).strip("_.")
    return name or "sanitized_file"


def summarize(json_path):
    """Recompte de resultats a partir del JSON de -f: [(etiqueta, nombre, primers valors)]."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    summary = []
    for key, label in RESULT_KEYS:
        values = data.get(key) or []
        if isinstance(values, list) and values:
            summary.append((label, len(values), [str(v) for v in values[:5]]))
    return summary


def _interpreters(executable):
    """Pythons candidats d'un executable: el de l'entorn virtual o el del shebang."""
    real = os.path.realpath(executable)
    candidates = [os.path.join(os.path.dirname(real), name) for name in ("python3", "python")]
    try:
        with open(real, "r", encoding="utf-8", errors="replace") as f:
            head = f.read(400)
    except OSError:
        head = ""
    first = head.splitlines()[0] if head else ""
    if first.startswith("#!") and "python" in first:
        candidates.append(first[2:].strip().split()[0])
    match = _EXEC_RE.search(head)  # scripts de uv/pip que comencen amb #!/bin/sh i fan exec del Python
    if match:
        candidates.insert(0, match.group(1))
    return [c for c in dict.fromkeys(candidates) if os.access(c, os.X_OK)]
