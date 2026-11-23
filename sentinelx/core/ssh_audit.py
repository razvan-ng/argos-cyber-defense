"""Auditoria de la configuració d'un servidor SSH amb ssh-audit (https://github.com/jtesta/ssh-audit).

Parteix de l'script auditoria_ssh.py: s'executa ssh-audit en format JSON contra el servidor i se'n
processa la sortida. Aquí s'hi afegeix la instal·lació d'ssh-audit a l'entorn de SentinelX, la
consulta dels mètodes d'autenticació que accepta el servidor (ssh-audit no els comprova) i la
conversió dels resultats a dades estructurades i a troballes de l'auditoria, perquè els facin
servir la pestanya Auditoria SSH, l'script auditoria_ssh.py, els informes i els expedients.
"""
import datetime
import importlib.util
import json
import os
import re
import shutil
import socket
import subprocess
import sys

from core.models import Severity, Vulnerability

SSH_AUDIT_URL = "https://github.com/jtesta/ssh-audit"
HARDENING_URL = "https://www.ssh-audit.com/hardening_guides.html"
AUDIT_TIMEOUT = 120

# Seccions d'algorismes del JSON d'ssh-audit, en l'ordre en què es mostren
CATEGORIES = [
    ("key", "Claus d'host", "HostKeyAlgorithms"),
    ("enc", "Algorismes de xifratge", "Ciphers"),
    ("mac", "Algorismes MAC (integritat)", "MACs"),
    ("kex", "Intercanvi de claus (KEX)", "KexAlgorithms"),
]
CATEGORY_NAMES = {key: name for key, name, _ in CATEGORIES}
DIRECTIVES = {key: directive for key, _, directive in CATEGORIES}

# Estat de cada element: el criteri d'ssh-audit («fail» i «warn» de les notes)
FAIL, WARN, OK = "fail", "warn", "ok"
STATE_LABELS = {FAIL: "Obsolet / insegur", WARN: "Avís", OK: "Correcte"}
LEVEL_LABELS = {"critical": "Crític", "warning": "Avís", "informational": "Informació"}

# Mètodes d'autenticació SSH (RFC 4252 i extensions d'OpenSSH)
AUTH_METHODS = {
    "publickey": (OK, "Clau pública: el mètode recomanat."),
    "gssapi-with-mic": (OK, "Kerberos (GSSAPI): segur si el domini està ben configurat."),
    "password": (WARN, "Contrasenya: exposat a atacs de força bruta. Desactiveu-lo (PasswordAuthentication no)."),
    "keyboard-interactive": (WARN, "Interactiu (sol ser una contrasenya via PAM): exposat a força bruta. "
                                   "Desactiveu-lo (KbdInteractiveAuthentication no) si no feu servir 2FA."),
    "hostbased": (WARN, "Basat en l'equip d'origen: confia en altres servidors. Desactiveu-lo "
                        "(HostbasedAuthentication no)."),
    "gssapi-keyex": (WARN, "Intercanvi de claus GSSAPI: obsolet."),
}

_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-:]*$")
_DENIED_RE = re.compile(r"Permission denied \(([^)]*)\)")


class SshAuditError(Exception):
    """Error amb un missatge apte per mostrar a l'usuari."""


# ---------------------------------------------------------------------- #
# Instal·lació d'ssh-audit a l'entorn de l'aplicació
# ---------------------------------------------------------------------- #
def find_command():
    """Comanda per executar ssh-audit: el mòdul de Python de l'entorn o el programa del sistema."""
    if importlib.util.find_spec("ssh_audit") is not None:
        return [sys.executable, "-m", "ssh_audit"]
    path = shutil.which("ssh-audit")
    return [path] if path else None


def is_available():
    return find_command() is not None


def install():
    """Instal·la ssh-audit amb pip a l'entorn de Python de SentinelX (el venv). Retorna el missatge."""
    try:
        result = subprocess.run([sys.executable, "-m", "pip", "install", "ssh-audit"],
                                capture_output=True, text=True, timeout=300, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SshAuditError(f"No s'ha pogut executar pip: {exc}") from exc
    importlib.invalidate_caches()
    if result.returncode != 0 or not is_available():
        detail = (result.stderr or result.stdout).strip().splitlines()[-1:] or [""]
        raise SshAuditError("No s'ha pogut instal·lar ssh-audit. Executeu ./install_dependencies.sh o "
                            f"«venv/bin/pip install ssh-audit». {detail[0]}".strip())
    return "ssh-audit instal·lat a l'entorn de SentinelX."


# ---------------------------------------------------------------------- #
# Validació de l'objectiu
# ---------------------------------------------------------------------- #
def validate_host(text):
    """IP o nom de host, mai opcions d'ssh-audit."""
    host = (text or "").strip()
    if not host:
        raise SshAuditError("Escriviu l'adreça IP o el nom del servidor SSH.")
    if not _HOST_RE.match(host):
        raise SshAuditError(f"«{host}» no és una IP ni un nom de host vàlid.")
    return host


def validate_port(text):
    port = str(text or "").strip() or "22"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise SshAuditError(f"El port «{port}» no és vàlid: ha d'anar de l'1 al 65535.")
    return int(port)


# ---------------------------------------------------------------------- #
# Execució i processament
# ---------------------------------------------------------------------- #
def run_audit(host, port=22):
    """Executa ssh-audit contra host:port i retorna l'auditoria estructurada (diccionari)."""
    host = validate_host(host)
    port = validate_port(port)
    command = find_command()
    if command is None:
        raise SshAuditError("ssh-audit no està instal·lat. Instal·leu-lo des de la pestanya Auditoria SSH, "
                            "amb ./install_dependencies.sh o amb «venv/bin/pip install ssh-audit».")
    arguments = ["-j", "-n", "-p", str(port), host]
    try:
        result = subprocess.run(command + arguments, capture_output=True, text=True, timeout=AUDIT_TIMEOUT,
                                check=False)
    except subprocess.TimeoutExpired as exc:
        raise SshAuditError(f"ssh-audit no ha acabat en {AUDIT_TIMEOUT} s.") from exc
    # ssh-audit acaba amb el codi 1, 2 o 3 quan troba avisos o errors: el que compta és el JSON
    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        detail = (result.stdout or result.stderr).strip()
        raise SshAuditError(f"No s'ha pogut auditar {host}:{port}. {detail[:300]}".strip()) from None
    audit = parse_output(data, host, port)
    audit["comanda"] = " ".join(["ssh-audit"] + arguments)
    audit["autenticacio"] = auth_methods(host, port)
    audit["resum"] = summarize(audit)
    return audit


def parse_output(data, host, port):
    """Converteix el JSON d'ssh-audit al format de SentinelX."""
    banner = data.get("banner") or {}
    fingerprints = {}
    for fp in data.get("fingerprints") or []:
        fingerprints.setdefault(fp.get("hostkey", ""), f"{fp.get('hash_alg', '')}:{fp.get('hash', '')}")

    categories = []
    for key, name, _ in CATEGORIES:
        items = []
        for item in data.get(key) or []:
            notes = item.get("notes") or {}
            algorithm = item.get("algorithm") or item.get("name") or "N/A"
            details = []
            if item.get("keysize"):
                details.append(f"{item['keysize']} bits")
            if key == "key" and algorithm in fingerprints:
                details.append(fingerprints[algorithm])
            items.append({
                "nom": algorithm,
                "estat": FAIL if notes.get("fail") else WARN if notes.get("warn") else OK,
                "detall": ", ".join(details),
                "notes": {level: list(notes.get(level) or []) for level in ("fail", "warn", "info") if notes.get(level)},
            })
        categories.append({"clau": key, "nom": name, "elements": items})

    recommendations = []
    actions = {"del": "Eliminar", "chg": "Canviar", "add": "Afegir"}
    for level, groups in (data.get("recommendations") or {}).items():
        for action, by_category in (groups or {}).items():
            for category, entries in (by_category or {}).items():
                for entry in entries or []:
                    recommendations.append({
                        "nivell": level, "accio": actions.get(action, action), "categoria": category,
                        "nom": entry.get("name", ""), "nota": entry.get("notes", ""),
                    })

    protocol = str(banner.get("protocol") or "")
    return {
        "objectiu": f"{host}:{port}",
        "host": host,
        "ip": _resolve(host),
        "port": port,
        "data": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "servidor": {
            "banner": banner.get("raw") or "",
            "programari": banner.get("software") or "",
            "protocol": protocol,
            "estat_protocol": FAIL if protocol.startswith("1") else OK,
        },
        "categories": categories,
        "compressio": list(data.get("compression") or []),
        "cves": [{"cve": c.get("name", ""), "cvss": c.get("cvssv2"), "descripcio": c.get("description", "")}
                 for c in data.get("cves") or []],
        "recomanacions": recommendations,
        "notes": list(data.get("additional_notes") or []),
    }


def auth_methods(host, port):
    """Mètodes d'autenticació que ofereix el servidor.

    El client OpenSSH demana el mètode «none» sense provar cap credencial, i el servidor respon
    amb la llista de mètodes que accepta («Permission denied (publickey,password)»).
    """
    if shutil.which("ssh") is None:
        return {"metodes": [], "error": "No es troba el client ssh (paquet openssh-client)."}
    command = ["ssh", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none", "-o", "ConnectTimeout=10",
               "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
               "-p", str(port), f"sentinelx-audit@{host}", "true"]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=30, check=False,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"metodes": [], "error": f"No s'han pogut consultar: {exc}"}
    if result.returncode == 0:
        return {"metodes": [{"nom": "none", "estat": FAIL,
                             "detall": "El servidor deixa entrar sense autenticació. Cal desactivar-ho."}], "error": ""}
    match = _DENIED_RE.search(result.stderr or "")
    if not match:
        error = (result.stderr or "").strip().splitlines()[-1:] or ["sense resposta"]
        return {"metodes": [], "error": f"El servidor no ha informat dels mètodes: {error[0]}"}
    methods = []
    for name in filter(None, (m.strip() for m in match.group(1).split(","))):
        state, detail = AUTH_METHODS.get(name, (WARN, "Mètode poc habitual: comproveu si cal."))
        methods.append({"nom": name, "estat": state, "detall": detail})
    return {"metodes": methods, "error": ""}


def summarize(audit):
    counts = {FAIL: 0, WARN: 0, OK: 0}
    for category in audit["categories"]:
        for item in category["elements"]:
            counts[item["estat"]] += 1
    for method in audit["autenticacio"]["metodes"]:
        counts[method["estat"]] += 1
    return {"obsolets": counts[FAIL], "avisos": counts[WARN], "correctes": counts[OK], "cves": len(audit["cves"])}


def _resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError:
        return host


# ---------------------------------------------------------------------- #
# Troballes per a l'auditoria (Tauler, informes i expedients)
# ---------------------------------------------------------------------- #
def findings(audit):
    """Troballes de l'auditoria SSH com a Vulnerability: una per categoria i estat, una per CVE."""
    result = []
    for category in audit["categories"]:
        key = category["clau"]
        for state, severity in ((FAIL, Severity.HIGH), (WARN, Severity.LOW)):
            names = [item["nom"] for item in category["elements"] if item["estat"] == state]
            if not names:
                continue
            kind = "elements obsolets o insegurs" if state == FAIL else "elements amb avisos"
            result.append(Vulnerability(
                cve_id="N/A",
                description=f"SSH, {category['nom']}: {kind} segons ssh-audit: {', '.join(names)}.",
                severity=severity, cvss_score=None, reference_url=HARDENING_URL,
                recommendation=f"Treure'ls de la directiva {DIRECTIVES[key]} de sshd_config i reiniciar el "
                               "servei, seguint la guia de reforçament d'ssh-audit.",
            ))
    if audit["servidor"]["estat_protocol"] == FAIL:
        result.append(Vulnerability(
            cve_id="N/A", description="SSH: el servidor accepta la versió 1 del protocol, obsoleta i insegura.",
            severity=Severity.HIGH, cvss_score=None, reference_url=SSH_AUDIT_URL,
            recommendation="Desactivar SSH-1 i actualitzar el servidor.",
        ))
    for method in audit["autenticacio"]["metodes"]:
        if method["estat"] == OK:
            continue
        result.append(Vulnerability(
            cve_id="N/A", description=f"SSH: autenticació «{method['nom']}» activada. {method['detall']}",
            severity=Severity.CRITICAL if method["nom"] == "none" else Severity.MEDIUM, cvss_score=None,
            reference_url=SSH_AUDIT_URL,
            recommendation="Deixar només l'autenticació amb clau pública (AuthenticationMethods publickey).",
        ))
    for cve in audit["cves"]:
        score = cve.get("cvss")
        result.append(Vulnerability(
            cve_id=cve["cve"], description=f"SSH: {cve.get('descripcio') or 'vulnerabilitat coneguda'} "
                                           f"({audit['servidor']['programari']}).",
            severity=_severity(score), cvss_score=score,
            reference_url=f"https://nvd.nist.gov/vuln/detail/{cve['cve']}",
            recommendation=f"Actualitzar {audit['servidor']['programari'] or 'el servidor SSH'}.",
        ))
    return result


def _severity(score):
    if score is None:
        return Severity.MEDIUM
    if score >= 9:
        return Severity.CRITICAL
    if score >= 7:
        return Severity.HIGH
    return Severity.MEDIUM if score >= 4 else Severity.LOW


# ---------------------------------------------------------------------- #
# Historial de l'script de terminal (sessió de SentinelX en JSON)
# ---------------------------------------------------------------------- #
def history_path():
    """Sessió on l'script auditoria_ssh.py desa les auditories (es pot obrir a Informes > Carregar Sessió)."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SentinelX", "auditories_ssh.json")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "sentinelx", "auditories_ssh.json")


def load_history():
    from core.session_io import load_session
    from core.models import AuditSession

    try:
        return load_session(history_path())
    except (OSError, ValueError):
        return AuditSession()


def save_to_history(audit):
    """Afegeix l'auditoria a l'historial (substitueix l'anterior del mateix servidor). Retorna el fitxer."""
    from core.app_state import AppState
    from core.session_io import save_session

    state = AppState()
    state.load_session(load_history())
    state.add_ssh_audit(audit)
    state.session.target = state.session.target or audit["host"]
    path = history_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    return save_session(state.session, path)


# ---------------------------------------------------------------------- #
# Vista jeràrquica (terminal)
# ---------------------------------------------------------------------- #
def tree_lines(audit):
    """Resultats en forma d'arbre per a l'script de terminal."""
    server = audit["servidor"]
    summary = audit["resum"]
    lines = [f"AUDITORIA SSH | {audit['objectiu']} | {audit['data'][:16].replace('T', ' ')}",
             f"├─ Servidor: {server['banner'] or 'desconegut'}",
             f"│  └─ Protocol SSH-{server['protocol'] or '?'} [{STATE_LABELS[server['estat_protocol']]}]"]
    sections = [(c["nom"], [(i["nom"], i["estat"], i["detall"]) for i in c["elements"]])
                for c in audit["categories"]]
    auth = audit["autenticacio"]
    sections.append(("Mètodes d'autenticació", [(m["nom"], m["estat"], m["detall"]) for m in auth["metodes"]]))
    for title, items in sections:
        lines.append(f"├─ {title} ({len(items)})")
        if not items:
            lines.append(f"│  └─ {auth['error'] if title.startswith('Mètodes') and auth['error'] else 'Sense dades.'}")
        for index, (name, state, detail) in enumerate(items):
            branch = "└─" if index == len(items) - 1 else "├─"
            lines.append(f"│  {branch} [{STATE_LABELS[state]}] {name}" + (f" | {detail}" if detail else ""))
    if audit["compressio"]:
        lines.append(f"├─ Compressió: {', '.join(audit['compressio'])}")
    if audit["cves"]:
        lines.append(f"├─ CVE ({len(audit['cves'])})")
        for index, cve in enumerate(audit["cves"]):
            branch = "└─" if index == len(audit["cves"]) - 1 else "├─"
            lines.append(f"│  {branch} {cve['cve']} (CVSS {cve['cvss']}): {cve['descripcio']}")
    lines.append(f"├─ Recomanacions ({len(audit['recomanacions'])})")
    for index, rec in enumerate(audit["recomanacions"]):
        branch = "└─" if index == len(audit["recomanacions"]) - 1 else "├─"
        level = LEVEL_LABELS.get(rec["nivell"], rec["nivell"])
        note = f" ({rec['nota']})" if rec["nota"] else ""
        lines.append(f"│  {branch} [{level}] {rec['accio']} {rec['categoria'].upper()}: {rec['nom']}{note}")
    lines.append(f"└─ Resum: {summary['obsolets']} obsolet(s) / insegur(s), {summary['avisos']} avís(os), "
                 f"{summary['correctes']} correcte(s), {summary['cves']} CVE")
    return lines
