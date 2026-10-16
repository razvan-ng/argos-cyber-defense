"""Mode fitxer: intercanvi d'expedients amb el portal sense connexió directa.

S'utilitza quan l'allotjament del portal no deixa connectar aplicacions (p. ex. InfinityFree):
  1. Al portal, «Fitxer per a SentinelX» descarrega l'expedient amb la darrera auditoria
     (format "argos-expedient").
  2. SentinelX l'obre, en fa servir l'auditoria com a referència i permet fer-ne la reauditoria.
  3. «Exporta per al portal» genera un fitxer "argos-auditoria" (dades + PDF opcional) que
     l'administrador puja a Administració → Puja una auditoria; queda vinculat a l'expedient.
"""
import base64
import datetime
import json

from core.session_io import session_from_report_data

EXPEDIENT_FORMAT = "argos-expedient"
AUDIT_FORMAT = "argos-auditoria"


class ExpedientFileError(Exception):
    """El fitxer no és un expedient vàlid del portal."""


def load_expedient_file(path):
    """Llegeix un fitxer d'expedient descarregat del portal.

    Retorna un diccionari amb:
      - expedient: dades de l'expedient (id, codi, titol, objectiu, empresa...)
      - auditories: resum de les auditories de l'expedient
      - baseline: AuditSession amb la darrera auditoria (o None si encara no n'hi ha)
      - baseline_title: títol de la darrera auditoria
      - portal: adreça del portal que l'ha generat
    """
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise ExpedientFileError(f"No s'ha pogut llegir el fitxer: {exc}") from exc

    if not isinstance(data, dict) or data.get("format") != EXPEDIENT_FORMAT:
        raise ExpedientFileError(
            "El fitxer no és un expedient del portal. Descarregueu-lo des de la fitxa de l'expedient "
            "(botó «Fitxer per a SentinelX»)."
        )
    expedient = data.get("expedient") or {}
    if not expedient.get("id") or not expedient.get("codi"):
        raise ExpedientFileError("El fitxer d'expedient està incomplet (falta l'identificador).")

    latest = data.get("darrera_auditoria") or None
    baseline = session_from_report_data(latest["dades"]) if latest and isinstance(latest.get("dades"), dict) else None
    return {
        "expedient": expedient,
        "auditories": data.get("auditories") or [],
        "baseline": baseline,
        "baseline_title": latest.get("titol", "") if latest else "",
        "portal": data.get("portal", ""),
    }


def export_audit_file(path, expedient, report_data, title="", pdf_bytes=None):
    """Desa l'auditoria en un fitxer que es puja al portal (Puja una auditoria)."""
    payload = {
        "format": AUDIT_FORMAT,
        "format_version": 1,
        "exportat_el": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "expedient": {"id": expedient.get("id"), "codi": expedient.get("codi", "")} if expedient else None,
        "titol": title,
        "informe": report_data,
    }
    if pdf_bytes:
        payload["pdf"] = base64.b64encode(pdf_bytes).decode("ascii")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
    return path
