"""Client de l'API d'Argos (argos-api/ al repositori, publicada a Cloudflare Workers).

L'API d'Argos guarda les claus de Gemini i de Shodan de l'empresa i fa les consultes en nom de
SentinelX, de manera que l'usuari no ha de posar cap clau. Si l'usuari té una clau pròpia, es fa
servir la seva i no es passa per aquí.

L'adreça es configura a data/branding.json («api_url») o amb la variable d'entorn ARGOS_API_URL.
"""
import os

import requests

from core.branding import load_branding

API_URL_ENV = "ARGOS_API_URL"
TIMEOUT = 120


class ArgosAPIError(Exception):
    """Error de l'API d'Argos. `own` indica que el missatge és de la mateixa API (ja en català)."""

    def __init__(self, message, status=0, own=False):
        super().__init__(message)
        self.status = status
        self.own = own


def api_url():
    url = os.environ.get(API_URL_ENV, "").strip() or (load_branding().get("api_url") or "").strip()
    return url.rstrip("/")


def available():
    return bool(api_url())


def post(path, payload, timeout=TIMEOUT):
    """Fa una petició a l'API d'Argos i retorna el JSON. Els errors es llancen com a ArgosAPIError."""
    url = api_url()
    if not url:
        raise ArgosAPIError("L'API d'Argos no està configurada.", own=True)
    try:
        response = requests.post(f"{url}{path}", json=payload, timeout=timeout,
                                 headers={"X-Argos-Client": "sentinelx", "User-Agent": "SentinelX"})
    except requests.exceptions.RequestException as exc:
        raise ArgosAPIError(f"No s'ha pogut connectar amb l'API d'Argos. Comproveu la connexió a Internet ({exc}).",
                            own=True) from exc
    try:
        data = response.json()
    except ValueError as exc:
        raise ArgosAPIError("L'API d'Argos ha retornat una resposta inesperada.", response.status_code, own=True) from exc
    if not response.ok:
        error = data.get("error") if isinstance(data, dict) else None
        if isinstance(error, dict):
            raise ArgosAPIError(error.get("message", ""), response.status_code, own=bool(error.get("argos")))
        raise ArgosAPIError(str(error or f"HTTP {response.status_code}"), response.status_code)
    return data
