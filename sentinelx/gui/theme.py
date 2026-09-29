"""Identitat corporativa, paleta de colors i tema visual de l'aplicació.

La identitat de marca (nom de producte, empresa, colors, enllaços) es carrega
des de data/branding.json (vegeu core/branding.py) perquè la mateixa
plataforma es pugui instal·lar per a diferents organitzacions sense
modificar el codi font. Els noms exportats aquí es mantenen estables perquè
la resta de la interfície en depèn.
"""
import customtkinter as ctk

from core.branding import load_branding
from utils.resources import resource_path

_branding = load_branding()

PRODUCT_NAME = _branding["product_name"]
COMPANY_NAME = _branding["company_name"]
INSTANCE_NAME = _branding["instance_name"]
APP_NAME = PRODUCT_NAME
APP_VERSION = _branding["version"]
SUPPORT_URL = _branding["support_url"]
DOCUMENTATION_URL = _branding["documentation_url"]
COPYRIGHT = _branding["copyright"]
PROJECT_LABEL = _branding["project_label"]

# Paleta corporativa: blau marí professional + accent blau viu, sense
# cantonades excessivament arrodonides ni estètica "cute".
COLOR_PRIMARY_DARK = _branding.get("primary_color") or "#0D2137"
COLOR_PRIMARY = "#123A5C"
COLOR_ACCENT = _branding.get("secondary_color") or "#1E88E5"
COLOR_ACCENT_HOVER = "#1565C0"
COLOR_SUCCESS = "#2E7D32"
COLOR_WARNING = "#F0AD4E"
COLOR_DANGER = "#C62828"
COLOR_CRITICAL = "#7B0000"
COLOR_BACKGROUND = "#EEF1F5"
COLOR_SURFACE = "#FFFFFF"
COLOR_TEXT = "#1A1F2B"
COLOR_TEXT_MUTED = "#5B6472"

SEVERITY_COLORS = {
    "Crítica": COLOR_CRITICAL,
    "Alta": COLOR_DANGER,
    "Mitjana": COLOR_WARNING,
    "Baixa": "#5BC0DE",
    "Informativa": COLOR_TEXT_MUTED,
}

FONT_HEADING = ("Segoe UI", 20, "bold")
FONT_SUBHEADING = ("Segoe UI", 14, "bold")
FONT_BODY = ("Segoe UI", 12)
FONT_MONO = ("Consolas", 11)

# Logotips d'Argos Cyber Defense (data/logo/). Es desen dins de data/ perquè
# PyInstaller ja els inclou amb el mateix --add-data "data:data".
LOGO_SYMBOL_DARK = "data/logo/argos-simbol-negatiu_256px.png"  # capçalera (fons fosc)
LOGO_HORIZONTAL = "data/logo/argos-logo-horitzontal_1200px.png"  # pestanya Quant a (fons clar)
LOGO_ICON_PNG = "data/logo/argos-simbol_256px.png"  # icona de la finestra (Linux)
LOGO_ICON_ICO = "data/logo/favicon.ico"  # icona de la finestra (Windows)


def apply_theme():
    ctk.set_appearance_mode("Light")
    ctk.set_default_color_theme("blue")


def load_logo(relative_path, size):
    """Carrega un logotip com a CTkImage. Retorna None si el fitxer no hi és o
    Pillow no està disponible, perquè l'aplicació funcioni igualment sense logotip.
    """
    try:
        from PIL import Image

        return ctk.CTkImage(light_image=Image.open(resource_path(relative_path)), size=size)
    except (ImportError, OSError):
        return None
