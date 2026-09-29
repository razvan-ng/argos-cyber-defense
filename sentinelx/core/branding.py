"""Configuració de marca (branding) del producte.

Externalitzada en data/branding.json perquè SentinelX es pugui instal·lar
per a diferents organitzacions/entorns sense haver de tocar el codi font
(nom de producte, empresa, colors corporatius, enllaços de suport, etc.).
Si el fitxer no existeix o està incomplet, s'apliquen uns valors per
defecte raonables perquè l'aplicació sempre arrenqui correctament.
"""
import json

from utils.resources import resource_path

BRANDING_CONFIG_PATH = "data/branding.json"

DEFAULT_BRANDING = {
    "product_name": "SentinelX Audit Suite",
    "company_name": "Argos Cyber Defense",
    "instance_name": "",
    "primary_color": "#0D2137",
    "secondary_color": "#1E88E5",
    "support_url": "",
    "documentation_url": "",
    "copyright": "Argos Cyber Defense",
    "version": "1.0.0",
    "project_label": (
        "Projecte Intermodular — 2n curs, Cicle Formatiu de Grau Superior "
        "d'Administració de Sistemes Informàtics en Xarxa (ASIX)"
    ),
}


def load_branding():
    """Retorna la configuració de marca activa (defectes + data/branding.json)."""
    branding = dict(DEFAULT_BRANDING)
    path = resource_path(BRANDING_CONFIG_PATH)
    try:
        with open(path, "r", encoding="utf-8") as f:
            custom = json.load(f)
        if isinstance(custom, dict):
            branding.update({k: v for k, v in custom.items() if k in DEFAULT_BRANDING})
    except (OSError, json.JSONDecodeError):
        pass
    return branding


def save_branding(branding):
    """Desa la configuració de marca a data/branding.json."""
    path = resource_path(BRANDING_CONFIG_PATH)
    payload = dict(DEFAULT_BRANDING)
    payload.update({k: v for k, v in branding.items() if k in DEFAULT_BRANDING})
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path
