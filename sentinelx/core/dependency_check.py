"""Comprovació de les eines externes del sistema operatiu necessàries.

SentinelX no reimplementa nmap/traceroute/etc.: en depèn com a binaris
externs del sistema. Aquest mòdul comprova que estiguin disponibles al
PATH abans de permetre executar els mòduls d'auditoria corresponents.
"""
import platform
import shutil

REQUIRED_TOOLS = {
    "nmap": {
        "description": "Descobriment d'equips i escaneig de ports/serveis",
        "apt_package": "nmap",
    },
    "ping": {
        "description": "Comprovació de connectivitat ICMP bàsica",
        "apt_package": "iputils-ping",
    },
    "traceroute": {
        "description": "Traçat de rutes de xarxa",
        "apt_package": "traceroute",
        "alternatives": ["tracepath"],
    },
    "ss": {
        "description": "Consulta de connexions de xarxa actives",
        "apt_package": "iproute2",
        "alternatives": ["netstat"],
    },
}

OPTIONAL_TOOLS = {
    "searchsploit": {
        "description": "Cerca d'exploits coneguts (Exploit-DB) — opcional",
        "apt_package": "exploitdb",
    },
    "ufw": {
        "description": "Consulta de l'estat del tallafocs — opcional",
        "apt_package": "ufw",
    },
}


def check_tool(name):
    return shutil.which(name) is not None


def _evaluate(tools_dict):
    results = {}
    missing = []
    for tool, meta in tools_dict.items():
        found = check_tool(tool)
        resolved_as = tool if found else None
        if not found:
            for alt in meta.get("alternatives", []):
                if check_tool(alt):
                    resolved_as = alt
                    found = True
                    break
        results[tool] = {
            "available": found,
            "resolved_as": resolved_as,
            "description": meta["description"],
        }
        if not found:
            missing.append(tool)
    return results, missing


def run_health_check():
    """Comprova les eines obligatòries. Retorna (resultats, eines_absents)."""
    return _evaluate(REQUIRED_TOOLS)


def run_optional_check():
    """Comprova eines opcionals que amplien funcionalitat (no bloquejants)."""
    return _evaluate(OPTIONAL_TOOLS)


def build_install_command(missing_tools, tools_dict=None):
    tools_dict = tools_dict or REQUIRED_TOOLS
    packages = []
    for tool in missing_tools:
        meta = tools_dict.get(tool, {})
        pkg = meta.get("apt_package", tool)
        if pkg not in packages:
            packages.append(pkg)
    if not packages:
        return ""
    return f"sudo apt update && sudo apt install -y {' '.join(packages)}"


def get_platform_info():
    return {
        "system": platform.system(),
        "release": platform.release(),
        "is_linux": platform.system() == "Linux",
    }
