"""Comprovació de versions noves de SentinelX a GitHub Releases."""
import re

import requests

RELEASES_API = "https://api.github.com/repos/razvan-ng/argos-cyber-defense/releases/latest"
RELEASES_PAGE = "https://github.com/razvan-ng/argos-cyber-defense/releases/latest"


class UpdateCheckError(Exception):
    pass


def parse_version(text):
    """«v2.0.1» → (2, 0, 1). Les parts no numèriques s'ignoren."""
    return tuple(int(part) for part in re.findall(r"\d+", text or "")[:3]) or (0,)


def check_latest(current_version, timeout=8):
    """Consulta l'última versió publicada. Retorna {"latest", "newer", "url", "notes"}."""
    try:
        response = requests.get(
            RELEASES_API, timeout=timeout,
            headers={"Accept": "application/vnd.github+json", "User-Agent": f"SentinelX/{current_version}"},
        )
    except requests.exceptions.RequestException as exc:
        raise UpdateCheckError(f"No s'ha pogut consultar GitHub: {exc}") from exc
    if response.status_code == 404:
        raise UpdateCheckError("Encara no s'ha publicat cap versió a GitHub.")
    if not response.ok:
        raise UpdateCheckError(f"GitHub ha respost amb l'error HTTP {response.status_code}.")
    try:
        data = response.json()
    except ValueError as exc:
        raise UpdateCheckError("Resposta inesperada de GitHub.") from exc

    latest = (data.get("tag_name") or "").lstrip("vV")
    return {
        "latest": latest,
        "newer": parse_version(latest) > parse_version(current_version),
        "url": data.get("html_url") or RELEASES_PAGE,
        "notes": (data.get("body") or "")[:800],
    }
