"""Reconeixement passiu amb l'API de Shodan (https://developer.shodan.io/api).

Abans de llançar escanejos actius (que fan soroll i els tallafocs poden detectar), SentinelX
consulta què en sap Shodan, el cercador de dispositius connectats a Internet. Shodan rastreja
Internet pel seu compte, de manera que cap d'aquestes consultes envia ni un sol paquet a la
xarxa de l'objectiu.

Funcions (les fan servir la pestanya «Reconeixement passiu» i l'script shodan_recon.py):
  1. Consulta d'host (IP lookup): IP, noms de domini associats i ports oberts.
  2. Identificació de serveis (banner grabbing): producte i versió de cada port obert.
  3. Cerca de serveis específics: equips d'Internet amb un producte o servei (p. ex. «proftpd»).

La clau de l'API no s'escriu mai al codi: es llegeix de la variable d'entorn SHODAN_API_KEY o
del fitxer shodan.json del perfil de l'usuari (permisos 600, al costat de portal.json).
Es fa servir la llibreria oficial de Shodan (pip install shodan).
"""
import ipaddress
import json
import os
import re
import socket
import time

from core.models import HostResult, ServiceInfo
from core.portal_client import settings_path as portal_settings_path

try:
    import shodan
except ImportError:  # SentinelX funciona igualment; la pestanya avisa que falta la llibreria
    shodan = None

API_KEY_ENV = "SHODAN_API_KEY"
SEARCH_LIMITS = (5, 10)
SHODAN_STATE = "open (Shodan)"  # estat dels serveis afegits a l'auditoria des de Shodan
SUMMARY_FACETS = [("port", 5), ("org", 5), ("country", 5), ("product", 5)]
BANNER_MAX = 90

_SSH_RE = re.compile(r"^SSH-[\d.]+-([A-Za-z][\w.+-]*?)[_-](\d[\w.~+-]*)")
_SERVER_RE = re.compile(r"^Server:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)


class ShodanError(Exception):
    """Error de Shodan amb un missatge apte per mostrar a l'usuari."""


class ShodanPlanError(ShodanError):
    """La clau és vàlida, però el seu pla no permet la consulta (p. ex. el pla gratuït i la cerca)."""


def library_available():
    return shodan is not None


# ------------------------------------------------------------------ #
# Clau de l'API (mai al codi ni al repositori)
# ------------------------------------------------------------------ #
def api_key_path():
    return os.path.join(os.path.dirname(portal_settings_path()), "shodan.json")


def load_api_key():
    """Retorna (clau, origen). L'origen és "entorn", "fitxer" o "" si no n'hi ha cap."""
    key = os.environ.get(API_KEY_ENV, "").strip()
    if key:
        return key, "entorn"
    try:
        with open(api_key_path(), "r", encoding="utf-8") as f:
            key = (json.load(f).get("api_key") or "").strip()
    except (OSError, ValueError, AttributeError):
        key = ""
    return key, ("fitxer" if key else "")


def save_api_key(key):
    """Desa la clau al perfil de l'usuari amb permisos 600 (només la pot llegir el propietari)."""
    path = api_key_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"api_key": key.strip()}, f, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # a Windows els permisos els gestiona el perfil de l'usuari
    return path


def delete_api_key():
    try:
        os.remove(api_key_path())
    except FileNotFoundError:
        pass


def mask_key(key):
    return f"{'•' * 8}{key[-4:]}" if len(key) > 8 else "•" * len(key)


# ------------------------------------------------------------------ #
# Validació i identificació de serveis
# ------------------------------------------------------------------ #
def validate_public_ip(text):
    """Comprova que el text sigui una adreça IP pública. Retorna l'adreça normalitzada."""
    text = (text or "").strip()
    if not text:
        raise ShodanError("Escriviu una adreça IP pública (p. ex. 45.33.32.156).")
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        raise ShodanError(f"«{text}» no és una adreça IP vàlida. Escriviu-ne una com 45.33.32.156.") from None
    if not address.is_global:
        raise ShodanError(
            f"{address} és una adreça privada o reservada. Shodan només coneix adreces públiques d'Internet: "
            "per a la xarxa interna feu servir l'Auditoria de Xarxa."
        )
    return str(address)


def describe_service(banner):
    """Banner grabbing: (servei, producte, versió, primera línia del banner) d'un resultat de Shodan.

    Si Shodan no ha identificat el producte, s'intenta treure del banner (capçalera SSH o
    «Server:» d'HTTP), com faria un analista a mà.
    """
    raw = banner.get("data") or ""
    product = (banner.get("product") or "").strip()
    version = (banner.get("version") or "").strip()
    if not product:
        product, version = _product_from_banner(raw)
    return _service_name(banner, raw), product, version, _banner_line(raw)


def service_label(service):
    """«OpenSSH 7.6» o, si no hi ha producte, el nom del servei."""
    product = f"{service['product']} {service['version']}".strip()
    if product:
        return product
    if service["name"]:
        return f"{service['name']} (producte no identificat)"
    return "Servei no identificat per Shodan"


def _product_from_banner(raw):
    match = _SSH_RE.match(raw)
    if match:
        return match.group(1), match.group(2)
    match = _SERVER_RE.search(raw)
    if match:
        server = match.group(1).strip()
        name, _, rest = server.partition("/")
        return name.strip(), rest.split(" ")[0].strip()
    return "", ""


def _service_name(banner, raw):
    module = ((banner.get("_shodan") or {}).get("module") or "").lower()
    for suffix in ("-simple-new", "-simple", "-tcp", "-udp"):
        if module.endswith(suffix):
            module = module[: -len(suffix)]
    if module and module != "auto":
        return module
    if raw.startswith("HTTP/"):
        return "http"
    if raw.startswith("SSH-"):
        return "ssh"
    try:
        return socket.getservbyport(int(banner.get("port") or 0), banner.get("transport") or "tcp")
    except (OSError, OverflowError, ValueError):
        return ""


def _banner_line(raw):
    """Línia més útil del banner: la capçalera «Server:» d'HTTP o, si no n'hi ha, la primera llegible."""
    match = _SERVER_RE.search(raw)
    lines = [match.group(0)] if match else raw.splitlines()
    for line in lines:
        line = line.strip()
        if line and line.isprintable() and line.count("\\x") < 3:  # Shodan escriu els banners binaris com a \x01...
            return line[:BANNER_MAX] + ("…" if len(line) > BANNER_MAX else "")
    return ""


# ------------------------------------------------------------------ #
# Consultes a l'API
# ------------------------------------------------------------------ #
class ShodanRecon:
    def __init__(self, api_key):
        if shodan is None:
            raise ShodanError(
                "Falta la llibreria de Shodan. Instal·leu-la amb ./install_dependencies.sh "
                "o amb «venv/bin/pip install shodan»."
            )
        if not api_key:
            raise ShodanError("Falta la clau de l'API de Shodan (la trobareu a https://account.shodan.io).")
        self.api = shodan.Shodan(api_key)

    def account_info(self):
        """Pla de la clau i crèdits disponibles (no gasta cap crèdit)."""
        info = self._call(self.api.info)
        return {
            "plan": info.get("plan") or "desconegut",
            "query_credits": info.get("query_credits", 0),
            "scan_credits": info.get("scan_credits", 0),
        }

    def host_lookup(self, ip):
        """Funcions 1 i 2: tota la informació de Shodan d'una IP, ja filtrada i neta."""
        ip = validate_public_ip(ip)
        host = self._call(self.api.host, ip)
        services = {}
        for banner in host.get("data", []):
            name, product, version, first_line = describe_service(banner)
            key = (banner.get("port") or 0, banner.get("transport") or "tcp")
            current = services.get(key)
            if current is None or (product and not current["product"]):  # un sol resultat per port
                services[key] = {
                    "port": key[0], "transport": key[1], "name": name,
                    "product": product, "version": version, "banner": first_line,
                }
        return {
            "ip": host.get("ip_str") or ip,
            "hostnames": sorted(set(host.get("hostnames") or [])),
            "domains": sorted(set(host.get("domains") or [])),
            "ports": sorted(set(host.get("ports") or [])),
            "services": [services[key] for key in sorted(services)],
            "org": host.get("org") or "",
            "isp": host.get("isp") or "",
            "asn": host.get("asn") or "",
            "country": host.get("country_name") or "",
            "city": host.get("city") or "",
            "os": host.get("os") or "",
            "last_update": (host.get("last_update") or "")[:10],
            "vulns": sorted(host.get("vulns") or []),
        }

    def search(self, query, limit=10):
        """Funció 3: cerca inversa d'un servei o producte, limitada als primers resultats.

        El pla gratuït de Shodan no permet la cerca amb resultats (error 403). En aquest cas es
        fa un recompte amb facetes, que sí que és gratuït, i es retorna un resum agregat.
        """
        query = (query or "").strip()
        if not query:
            raise ShodanError("Escriviu el nom d'un servei o producte (p. ex. proftpd, nginx o webcam).")
        limit = max(1, min(int(limit), max(SEARCH_LIMITS)))
        try:
            result = self._call(self.api.search, query, limit=limit)
        except ShodanPlanError as exc:
            time.sleep(1.1)  # el pla gratuït admet una consulta per segon
            summary = self._call(self.api.count, query, facets=SUMMARY_FACETS)
            return {
                "mode": "resum", "query": query, "total": summary.get("total", 0),
                "facets": summary.get("facets") or {}, "notice": str(exc), "results": [],
            }
        results = []
        for match in result.get("matches", [])[:limit]:
            results.append({
                "ip": match.get("ip_str") or "",
                "port": match.get("port") or 0,
                "transport": match.get("transport") or "tcp",
                "org": match.get("org") or "",
                "isp": match.get("isp") or "",
                "product": f"{match.get('product') or ''} {match.get('version') or ''}".strip(),
                "country": (match.get("location") or {}).get("country_name") or "",
                "hostnames": match.get("hostnames") or [],
            })
        return {"mode": "complet", "query": query, "total": result.get("total", 0), "results": results}

    @staticmethod
    def _call(func, *args, **kwargs):
        try:
            return func(*args, **kwargs)
        except shodan.APIError as exc:
            raise _translate_error(str(exc)) from exc


def _translate_error(message):
    text = message.lower()
    if "no information available" in text:
        return ShodanError(
            "Shodan no té informació d'aquesta IP: no l'ha indexada o no hi ha trobat cap port obert a Internet."
        )
    if "invalid api key" in text or "401" in text:
        return ShodanError("La clau de l'API de Shodan no és vàlida. Reviseu-la a https://account.shodan.io.")
    if "access denied" in text or "403" in text:
        return ShodanPlanError(
            "El pla de la clau de Shodan no permet aquesta consulta: la cerca amb resultats necessita "
            "crèdits de consulta (Shodan Membership o pla acadèmic)."
        )
    if "rate limit" in text:
        return ShodanError("Shodan limita les consultes (una per segon al pla gratuït). Espereu uns segons.")
    if "unable to connect" in text or "timed out" in text:
        return ShodanError("No s'ha pogut connectar amb Shodan. Comproveu la connexió a Internet.")
    return ShodanError(f"Error de l'API de Shodan: {message}")


# ------------------------------------------------------------------ #
# Integració amb l'auditoria
# ------------------------------------------------------------------ #
def lookup_to_host(lookup):
    """Converteix una consulta d'host en un HostResult per afegir-lo a la sessió d'auditoria.

    Els serveis queden marcats amb l'estat «open (Shodan)» perquè l'informe distingeixi les dades
    passives de les que ha confirmat un escaneig actiu.
    """
    services = [
        ServiceInfo(
            port=s["port"], protocol=s["transport"], service_name=s["name"],
            product=s["product"], version=s["version"], state=SHODAN_STATE,
        )
        for s in lookup["services"]
    ]
    return HostResult(
        ip=lookup["ip"], hostname=(lookup["hostnames"] or [""])[0], os_guess=lookup["os"],
        status="Shodan", services=services,
    )
