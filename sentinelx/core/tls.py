"""Verificació HTTPS quan l'allotjament no envia la cadena de certificats completa.

Alguns allotjaments (com l'allotjament gratuït d'InfinityFree) només envien el certificat del
domini, sense el certificat intermedi de l'autoritat que l'ha emès. Els navegadors descarreguen
l'intermedi pel seu compte, però Python no, i la connexió falla amb l'error «unable to get local
issuer certificate».

SentinelX porta els certificats intermedis públics de Let's Encrypt (data/certs). Si la
verificació normal falla per aquest motiu, es torna a provar amb el magatzem de confiança
habitual més aquests intermedis. La cadena s'ha de continuar validant fins a una arrel de
confiança i el certificat ha de correspondre al domini: la verificació no es desactiva mai.
"""
import atexit
import os
import tempfile
import threading
from urllib.parse import urlparse

import requests
from requests import certs

from utils.resources import resource_path

INTERMEDIATES_PATH = "data/certs/letsencrypt-intermediates.pem"

# Errors d'OpenSSL quan el servidor no envia el certificat intermedi
MISSING_ISSUER_MARKERS = ("unable to get local issuer certificate", "unable to verify the first certificate")

_lock = threading.Lock()
_bundle_path = None
_hosts_with_incomplete_chain = set()


def is_missing_issuer_error(exc):
    text = str(exc).lower()
    return any(marker in text for marker in MISSING_ISSUER_MARKERS)


def _remove_bundle():
    if _bundle_path:
        try:
            os.remove(_bundle_path)
        except OSError:
            pass


def extended_ca_bundle():
    """Fitxer amb el magatzem de confiança de requests més els intermedis de Let's Encrypt.

    Es crea una sola vegada per execució i s'esborra en tancar SentinelX. Retorna None si no
    es troba algun dels dos fitxers d'origen.
    """
    global _bundle_path
    with _lock:
        if _bundle_path and os.path.exists(_bundle_path):
            return _bundle_path
        try:
            with open(certs.where(), "rb") as f:
                roots = f.read()
            with open(resource_path(INTERMEDIATES_PATH), "rb") as f:
                intermediates = f.read()
        except OSError:
            return None
        # mkstemp crea el fitxer amb un nom únic i permisos 600: cap altre usuari el pot substituir
        fd, path = tempfile.mkstemp(prefix="sentinelx-ca-", suffix=".pem")
        with os.fdopen(fd, "wb") as f:
            f.write(roots.rstrip() + b"\n\n" + intermediates)
        if _bundle_path is None:
            atexit.register(_remove_bundle)
        _bundle_path = path
        return path


def request(method, url, **kwargs):
    """Com requests.request, però completa la cadena de certificats si el servidor no l'envia."""
    host = (urlparse(url).hostname or "").lower()
    if kwargs.get("verify", True) is True and host in _hosts_with_incomplete_chain:
        bundle = extended_ca_bundle()
        if bundle:
            return requests.request(method, url, **dict(kwargs, verify=bundle))
    try:
        return requests.request(method, url, **kwargs)
    except requests.exceptions.SSLError as exc:
        if kwargs.get("verify", True) is not True or not is_missing_issuer_error(exc):
            raise
        bundle = extended_ca_bundle()
        if not bundle:
            raise
        # L'error es produeix en la negociació TLS, abans d'enviar res: es pot repetir sense risc
        response = requests.request(method, url, **dict(kwargs, verify=bundle))
        _hosts_with_incomplete_chain.add(host)
        return response
