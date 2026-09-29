"""Resolució de rutes a recursos (dades, icones) compatible amb PyInstaller."""
import os
import sys


def resource_path(relative_path):
    """Retorna la ruta absoluta a un recurs, tant en execució normal com

    empaquetada amb PyInstaller (onefile o onedir), on els recursos es
    copien dins del directori temporal/`_internal` referenciat per
    ``sys._MEIPASS``.
    """
    if hasattr(sys, "_MEIPASS"):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    return os.path.join(base_path, relative_path)
