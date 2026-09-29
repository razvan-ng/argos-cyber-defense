"""Identitat corporativa, paleta de colors i tema visual de l'aplicació.

La identitat de marca (nom de producte, empresa, colors, enllaços) es carrega
des de data/branding.json (vegeu core/branding.py) perquè la mateixa
plataforma es pugui instal·lar per a diferents organitzacions sense
modificar el codi font. Els noms exportats aquí es mantenen estables perquè
la resta de la interfície en depèn.
"""
import sys
import tkinter
from tkinter import ttk

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

# Paleta corporativa d'Argos Cyber Defense (Guia d'identitat visual v1.0):
# blau Argos com a color principal i cian Sentinel com a accent.
COLOR_PRIMARY_DARK = _branding.get("primary_color") or "#0B1F3A"  # Blau Argos
COLOR_PRIMARY = "#14335C"  # Blau faceta
COLOR_ACCENT = _branding.get("secondary_color") or "#16B4D2"  # Cian Sentinel
COLOR_ACCENT_HOVER = "#3CC6DF"
COLOR_ACCENT_TEXT = "#1188A8"  # Blau verdós: text en color sobre fons clar
COLOR_SUCCESS = "#2E7D32"
COLOR_WARNING = "#F0AD4E"
COLOR_DANGER = "#C62828"
COLOR_CRITICAL = "#7B0000"
COLOR_BACKGROUND = "#EEF1F5"
COLOR_SURFACE = "#FFFFFF"
COLOR_BORDER = "#DDE3EA"
COLOR_TAB_BAR = "#E2E8EF"
COLOR_HEADER = "#061427"
COLOR_CONSOLE = "#061427"
COLOR_CONSOLE_TEXT = "#D5E2EE"
COLOR_TEXT = "#1A1F2B"
COLOR_TEXT_MUTED = "#5B6472"

SEVERITY_COLORS = {
    "Crítica": COLOR_CRITICAL,
    "Alta": COLOR_DANGER,
    "Mitjana": COLOR_WARNING,
    "Baixa": "#5BC0DE",
    "Informativa": COLOR_TEXT_MUTED,
}
# Color del text dins de les etiquetes de gravetat (fons clars necessiten text fosc)
SEVERITY_TEXT_COLORS = {
    "Crítica": "#FFFFFF",
    "Alta": "#FFFFFF",
    "Mitjana": "#3A2A00",
    "Baixa": "#0B1F3A",
    "Informativa": "#FFFFFF",
}

FONT_HEADING = ("Segoe UI", 20, "bold")
FONT_SUBHEADING = ("Segoe UI", 14, "bold")
FONT_BODY = ("Segoe UI", 12)
FONT_MONO = ("Consolas", 11)

# Tipografia de títols i xifres de la marca (Bahnschrift ve amb Windows 10 i 11;
# a Linux es fa servir Ubuntu i, si no hi és, Tk en tria una de similar).
FONT_DISPLAY_FAMILY = "Bahnschrift" if sys.platform.startswith("win") else "Ubuntu"
FONT_MONO_FAMILY = "Consolas" if sys.platform.startswith("win") else "Ubuntu Mono"

# Tema de CustomTkinter amb els colors d'Argos (data/argos_theme.json)
CUSTOM_THEME_PATH = "data/argos_theme.json"

# Logotips d'Argos Cyber Defense (data/logo/). Es desen dins de data/ perquè
# PyInstaller ja els inclou amb el mateix --add-data "data:data".
LOGO_SYMBOL_DARK = "data/logo/argos-simbol-negatiu_256px.png"  # capçalera (fons fosc)
LOGO_HORIZONTAL = "data/logo/argos-logo-horitzontal_1200px.png"  # pestanya Quant a (fons clar)
LOGO_ICON_PNG = "data/logo/argos-simbol_256px.png"  # icona de la finestra (Linux)
LOGO_ICON_ICO = "data/logo/favicon.ico"  # icona de la finestra (Windows)


def apply_theme():
    ctk.set_appearance_mode("Light")
    try:
        ctk.set_default_color_theme(resource_path(CUSTOM_THEME_PATH))
    except (OSError, ValueError):
        ctk.set_default_color_theme("blue")  # si falta el tema d'Argos, el de sèrie
    _style_tables()


def _style_tables():
    """Taules (ttk.Treeview) amb el mateix estil que la resta de la interfície:
    files blanques, capçalera gris clar i selecció en cian suau.

    S'ha de cridar amb la finestra principal ja creada.
    """
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except tkinter.TclError:
        return

    style.configure(
        "Treeview",
        background=COLOR_SURFACE, fieldbackground=COLOR_SURFACE, foreground=COLOR_TEXT,
        bordercolor=COLOR_BORDER, lightcolor=COLOR_BORDER, darkcolor=COLOR_BORDER,
        rowheight=24, font=(FONT_BODY[0], 10),
    )
    style.map("Treeview", background=[("selected", "#CDEFF6")], foreground=[("selected", COLOR_PRIMARY_DARK)])
    style.configure(
        "Treeview.Heading",
        background=COLOR_TAB_BAR, foreground=COLOR_PRIMARY_DARK,
        bordercolor=COLOR_BORDER, lightcolor=COLOR_TAB_BAR, darkcolor=COLOR_TAB_BAR,
        relief="flat", padding=(8, 6), font=(FONT_BODY[0], 10, "bold"),
    )
    style.map("Treeview.Heading", background=[("active", "#D5E2EE")])
    for orient in ("Vertical", "Horizontal"):
        style.configure(
            f"{orient}.TScrollbar",
            background="#B7C4D1", troughcolor=COLOR_BACKGROUND, bordercolor=COLOR_BACKGROUND,
            lightcolor="#B7C4D1", darkcolor="#B7C4D1", arrowcolor=COLOR_PRIMARY_DARK,
        )


def load_logo(relative_path, size):
    """Carrega un logotip com a CTkImage. Retorna None si el fitxer no hi és o
    Pillow no està disponible, perquè l'aplicació funcioni igualment sense logotip.
    """
    try:
        from PIL import Image

        return ctk.CTkImage(light_image=Image.open(resource_path(relative_path)), size=size)
    except (ImportError, OSError):
        return None
