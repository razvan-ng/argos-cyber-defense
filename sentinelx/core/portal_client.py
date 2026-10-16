"""Connexió amb el portal de clients d'Argos Cyber Defense (API REST de la web).

SentinelX treballa amb els mateixos expedients que el portal: un administrador hi inicia la
sessió amb el seu usuari de la web, obre l'expedient d'una empresa (i, si n'hi ha, l'auditoria
anterior per fer-ne la reauditoria) i hi desa els resultats de l'auditoria.

Punts de l'API (tots retornen JSON amb el camp "ok"):
  POST   /api/v1/sessio.php       inicia la sessió (correu i contrasenya d'administrador)
  DELETE /api/v1/sessio.php       tanca la sessió
  GET    /api/v1/estat.php        comprova la sessió
  GET    /api/v1/empreses.php     empreses client actives
  GET    /api/v1/expedients.php   expedients (i detall amb l'historial d'auditories)
  POST   /api/v1/expedients.php   crea un expedient
  GET    /api/v1/informes.php     auditories (i dades completes d'una auditoria)
  POST   /api/v1/informes.php     desa una auditoria (nova o actualització d'un esborrany)

Alguns allotjaments gratuïts (com InfinityFree) bloquegen totes les peticions que no fa un
navegador. En aquest cas es llança PortalBlockedError i SentinelX passa al mode fitxer
(core/expedient_io.py).
"""
import base64
import json
import os
import sys
from urllib.parse import urlparse

import requests

API_PREFIX = "/api/v1"
DEFAULT_TIMEOUT = 60
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Senyals de les pàgines de verificació que alguns allotjaments retornen en lloc de l'API
BLOCK_MARKERS = ("aes.js", "slowaes", "this site requires javascript", "__test=", "checking your browser")


class PortalError(Exception):
    """Error de comunicació amb el portal, amb un missatge apte per mostrar a l'usuari."""


class PortalAuthError(PortalError):
    """La sessió ha caducat o les credencials no són vàlides."""


class PortalBlockedError(PortalError):
    """L'allotjament del portal no deixa connectar aplicacions (només navegadors)."""


# ------------------------------------------------------------------ #
# Configuració desada (adreça del portal i darrer correu; mai la contrasenya)
# ------------------------------------------------------------------ #
def settings_path():
    """Fitxer de configuració del portal dins del perfil de l'usuari."""
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "SentinelX", "portal.json")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, "sentinelx", "portal.json")


def load_settings():
    try:
        with open(settings_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_settings(settings):
    """Desa la configuració amb permisos 600 (només la pot llegir el propietari)."""
    path = settings_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(settings, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # a Windows els permisos els gestiona el perfil de l'usuari
    return path


def normalize_base_url(url):
    """Valida l'adreça del portal i n'exigeix HTTPS (excepte en proves locals)."""
    url = (url or "").strip().rstrip("/")
    if url and "://" not in url:
        url = "https://" + url
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise PortalError("L'adreça del portal no és vàlida (exemple: https://argoscyberdefense.tech).")
    if parsed.scheme == "http" and parsed.hostname not in LOCAL_HOSTS:
        raise PortalError("Per seguretat, el portal s'ha de fer servir per HTTPS: les credencials viatjarien sense xifrar.")
    return url


# ------------------------------------------------------------------ #
# Client de l'API
# ------------------------------------------------------------------ #
class PortalClient:
    def __init__(self, base_url, token="", user_agent="SentinelX", timeout=DEFAULT_TIMEOUT):
        self.base_url = normalize_base_url(base_url)
        self.token = (token or "").strip()
        self.user_agent = user_agent
        self.timeout = timeout
        self.user = None
        self.expires_at = ""

    @property
    def logged_in(self):
        return bool(self.token)

    def _request(self, method, endpoint, payload=None, params=None, auth=True):
        url = f"{self.base_url}{API_PREFIX}/{endpoint}"
        headers = {"Accept": "application/json", "User-Agent": self.user_agent}
        if auth:
            if not self.token:
                raise PortalAuthError("Cal iniciar la sessió al portal.")
            headers["Authorization"] = f"Bearer {self.token}"
            # Alguns hostings compartits no passen la capçalera Authorization a PHP
            headers["X-Argos-Token"] = self.token
        try:
            # Sense seguir redireccions: un POST redirigit es convertiria en GET i les
            # credencials podrien acabar en un altre servidor.
            response = requests.request(
                method, url, headers=headers, json=payload, params=params, timeout=self.timeout,
                allow_redirects=False,
            )
        except requests.exceptions.SSLError as exc:
            raise PortalError(f"No s'ha pogut verificar el certificat HTTPS del portal ({exc}).") from exc
        except requests.exceptions.Timeout as exc:
            raise PortalError("El portal no ha respost a temps. Torneu-ho a provar d'aquí a una estona.") from exc
        except requests.exceptions.ConnectionError as exc:
            raise PortalError(
                "No s'ha pogut connectar amb el portal. Comproveu l'adreça i la connexió a Internet."
            ) from exc
        except requests.exceptions.RequestException as exc:
            raise PortalError(f"Error de comunicació amb el portal: {exc}") from exc

        if 300 <= response.status_code < 400:
            location = response.headers.get("Location", "")
            raise PortalError(
                f"El portal redirigeix la petició a «{location}». Revisa l'adreça del portal (per exemple, sense «www»)."
            )

        try:
            data = response.json()
        except ValueError as exc:
            body = (response.text or "")[:4000].lower()
            if any(marker in body for marker in BLOCK_MARKERS):
                raise PortalBlockedError(
                    "L'allotjament del portal bloqueja les connexions que no venen d'un navegador "
                    "(per exemple, l'allotjament gratuït d'InfinityFree). Feu servir el mode fitxer: "
                    "descarregueu l'expedient des de la web i, en acabar, exporteu l'auditoria i pugeu-la al portal."
                ) from exc
            raise PortalError(
                f"Resposta inesperada del servidor (HTTP {response.status_code}). "
                "Comproveu que l'adreça correspon al portal d'Argos."
            ) from exc

        if not response.ok or not isinstance(data, dict) or not data.get("ok"):
            error = data.get("error") if isinstance(data, dict) else None
            message = error.get("missatge") if isinstance(error, dict) else None
            message = message or f"El portal ha retornat un error (HTTP {response.status_code})."
            if response.status_code == 401:
                raise PortalAuthError(message)
            raise PortalError(message)
        return data

    # --- Sessió ---------------------------------------------------- #
    def login(self, email, password, device=""):
        """Inicia la sessió amb un usuari administrador del portal."""
        data = self._request(
            "POST", "sessio.php", {"email": email, "contrasenya": password, "equip": device}, auth=False,
        )
        self.token = data.get("token", "")
        self.user = data.get("usuari") or {}
        self.expires_at = data.get("expira_el", "")
        return data

    def logout(self):
        if not self.token:
            return
        try:
            self._request("DELETE", "sessio.php")
        finally:
            self.token = ""
            self.user = None
            self.expires_at = ""

    def check(self):
        return self._request("GET", "estat.php")

    # --- Empreses i expedients ------------------------------------- #
    def list_companies(self):
        """Empreses client actives: llista de diccionaris {"id": ..., "nom": ...}."""
        return self._request("GET", "empreses.php").get("empreses", [])

    def list_expedients(self, company_id=None, state=None):
        params = {}
        if company_id:
            params["empresa_id"] = int(company_id)
        if state:
            params["estat"] = state
        return self._request("GET", "expedients.php", params=params).get("expedients", [])

    def get_expedient(self, expedient_id):
        """Detall d'un expedient amb l'historial d'auditories (de la més antiga a la més recent)."""
        return self._request("GET", "expedients.php", params={"id": int(expedient_id)}).get("expedient", {})

    def create_expedient(self, company_id, title, target="", notes=""):
        payload = {"empresa_id": int(company_id), "titol": title, "objectiu": target, "notes": notes}
        return self._request("POST", "expedients.php", payload).get("expedient", {})

    # --- Auditories ------------------------------------------------ #
    def get_report(self, report_id):
        """Auditoria completa (camp "dades" amb el mateix format que build_report_data)."""
        return self._request("GET", "informes.php", params={"id": int(report_id)}).get("informe", {})

    def save_audit(self, expedient_id, report_data, title="", publish=False, pdf_bytes=None, report_id=None):
        """Desa l'auditoria a l'expedient.

        Amb report_id s'actualitza aquest esborrany (sincronització automàtica); sense, se'n crea
        un de nou. Amb publish=True, el client la podrà consultar a l'Àrea de clients.
        """
        payload = {
            "expedient_id": int(expedient_id),
            "titol": title,
            "estat": "publicat" if publish else "esborrany",
            "informe": report_data,
        }
        if report_id:
            payload["informe_id"] = int(report_id)
        if pdf_bytes:
            payload["pdf"] = base64.b64encode(pdf_bytes).decode("ascii")
        return self._request("POST", "informes.php", payload)
