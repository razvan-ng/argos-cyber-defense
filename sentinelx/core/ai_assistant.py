"""Assistent d'IA (Google Gemini) per fer les auditories més entenedores.

Fa tres coses:
  1. Tradueix al català les descripcions dels CVE que arriben en anglès o castellà (NVD i NSE).
  2. Explica una vulnerabilitat en llenguatge senzill (què és, quin risc té i què cal fer).
  3. Redacta l'informe senzill per a l'empresa client: resum per a la direcció, riscos principals
     explicats sense tecnicismes, recomanacions i glossari.

Es fa servir l'API REST de Gemini (https://ai.google.dev) amb requests, sense dependències noves.
La clau es llegeix de la variable d'entorn GEMINI_API_KEY o del fitxer ia.json del perfil de
l'usuari (permisos 600), mai del codi. Si l'usuari no en té cap, les consultes passen per l'API
d'Argos (core/argos_api.py), que fa servir la clau de l'empresa. Abans d'enviar res, les IP i els noms dels equips es poden
substituir per àlies («Equip 1»...) i es tornen a posar en rebre la resposta.
"""
import json
import os
import re

import requests

from core import argos_api
from core.models import Severity
from core.portal_client import settings_path as portal_settings_path

API_URL = "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
API_KEY_ENV = "GEMINI_API_KEY"
DEFAULT_MODEL = "gemini-3.5-flash"
FALLBACK_MODEL = "gemini-3.5-flash-lite"  # si el model principal està saturat (503) o al límit (429)
TIMEOUT = 180
TRANSLATE_BATCH = 5
MAX_REPORT_FINDINGS = 40
RISK_LEVELS = ("Baix", "Moderat", "Alt", "Crític")
URGENCY_LEVELS = ("Immediata", "Aquest mes", "Planificada")

SYSTEM_PROMPT = (
    "Ets un consultor de ciberseguretat d'Argos Cyber Defense. Escrius sempre en català correcte i "
    "planer, per a persones sense coneixements tècnics (gerents i personal d'oficina d'una empresa). "
    "No t'inventis dades: fes servir només la informació que se't dona. Si alguna cosa és incerta, "
    "digues-ho. Respon sempre amb JSON vàlid amb exactament els camps que se't demanen."
)


class AIError(Exception):
    """Error de l'assistent amb un missatge apte per mostrar a l'usuari."""


# ------------------------------------------------------------------ #
# Configuració (clau i opcions, mai al codi ni al repositori)
# ------------------------------------------------------------------ #
def config_path():
    return os.path.join(os.path.dirname(portal_settings_path()), "ia.json")


def load_config():
    """Configuració de l'assistent: {"api_key", "model", "anonymize", "source"}."""
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        data = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        data = {}
    config = {
        "api_key": (data.get("api_key") or "").strip(),
        "model": (data.get("model") or DEFAULT_MODEL).strip(),
        "anonymize": data.get("anonymize", True) is not False,
        "source": "fitxer" if data.get("api_key") else "",
    }
    env_key = os.environ.get(API_KEY_ENV, "").strip()
    if env_key:
        config.update(api_key=env_key, source="entorn")
    elif not config["api_key"] and argos_api.available():
        config["source"] = "argos"
    return config


def save_config(api_key=None, anonymize=None, model=None):
    """Desa la configuració amb permisos 600. Els valors None es mantenen com estaven."""
    try:
        with open(config_path(), "r", encoding="utf-8") as f:
            data = json.load(f)
        data = data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        data = {}
    data["provider"] = "gemini"
    if api_key is not None:
        data["api_key"] = api_key.strip()
    if anonymize is not None:
        data["anonymize"] = bool(anonymize)
    if model is not None:
        data["model"] = model.strip() or DEFAULT_MODEL
    path = config_path()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # a Windows els permisos els gestiona el perfil de l'usuari
    return path


def delete_api_key():
    save_config(api_key="")


def mask_key(key):
    return f"{'•' * 8}{key[-4:]}" if len(key) > 8 else "•" * len(key)


def is_configured():
    """Hi ha IA disponible: amb la clau de l'usuari o a través de l'API d'Argos."""
    return bool(load_config()["api_key"]) or argos_api.available()


# ------------------------------------------------------------------ #
# Anonimització de les dades que s'envien a la IA
# ------------------------------------------------------------------ #
class Anonymizer:
    """Substitueix les IP i els noms dels equips per àlies i els torna a posar a les respostes."""

    def __init__(self, session=None, enabled=True):
        self.enabled = enabled
        self._real_to_alias = {}
        self._one_way = {}  # l'objectiu s'amaga però no es torna a posar (la IA ja escriu «la xarxa auditada»)
        if enabled and session is not None:
            for index, host in enumerate(session.hosts, start=1):
                self._real_to_alias[host.ip] = f"Equip {index}"
                if host.hostname:
                    self._real_to_alias[host.hostname] = f"Equip {index}"
            if session.target and session.target not in self._real_to_alias:
                self._one_way[session.target] = "la xarxa auditada"

    def alias(self, value):
        """Àlies d'un valor (IP o nom d'equip); si no el coneix, el crea."""
        if not self.enabled or not value:
            return value
        if value not in self._real_to_alias:
            self._real_to_alias[value] = f"Equip {len(set(self._real_to_alias.values())) + 1}"
        return self._real_to_alias[value]

    def hide(self, text):
        if not self.enabled or not text:
            return text
        replacements = {**self._one_way, **self._real_to_alias}
        for real in sorted(replacements, key=len, reverse=True):
            text = text.replace(real, replacements[real])
        return re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[IP]", text)  # IP que no són de cap equip conegut

    def show(self, text):
        if not self.enabled or not isinstance(text, str):
            return text
        reals = {}
        for real, alias in self._real_to_alias.items():
            reals.setdefault(alias, real)  # la IP té prioritat sobre el nom de l'equip

        def restore(match):
            real = reals.get(f"Equip {match.group(2)}")
            if real is None:
                return match.group(0)
            return f"{match.group(1)}equip {real}" if match.group(1) else real  # «de l'Equip 2» -> «de l'equip IP»

        return re.sub(r"\b([lL]')?Equip (\d+)\b", restore, text)

    def show_all(self, value):
        """Torna a posar les dades reals a totes les cadenes d'una estructura JSON."""
        if isinstance(value, dict):
            return {k: self.show_all(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.show_all(v) for v in value]
        return self.show(value)


# ------------------------------------------------------------------ #
# Client de Gemini
# ------------------------------------------------------------------ #
class AIAssistant:
    def __init__(self, api_key=None, model=None):
        config = load_config()
        self.api_key = (api_key or config["api_key"]).strip()
        self.model = model or config["model"] or DEFAULT_MODEL
        self.via_argos = not self.api_key and argos_api.available()
        self.provider = ""  # quina IA ha redactat la darrera resposta (p. ex. «Google Gemini (gemini-3.5-flash)»)
        if not self.api_key and not self.via_argos:
            raise AIError("Falta la clau de l'API de Gemini. Creeu-ne una a https://aistudio.google.com/apikey "
                          "i deseu-la a la pestanya Informes.")

    def check(self):
        """Comprova la clau amb una consulta mínima. Retorna el model que respon."""
        result = self._generate('Respon només amb aquest JSON: {"estat": "ok"}', temperature=0)
        if not isinstance(result, dict) or result.get("estat") != "ok":
            raise AIError("La IA ha respost, però no amb el format esperat.")
        return self.provider

    def translate(self, texts):
        """Tradueix al català una llista de textos (en anglès o castellà) mantenint l'ordre."""
        translated = []
        for start in range(0, len(texts), TRANSLATE_BATCH):
            batch = texts[start:start + TRANSLATE_BATCH]
            prompt = (
                "Tradueix al català cada descripció de vulnerabilitat d'aquesta llista. Mantén els noms de "
                "productes, versions, codis CVE i termes tècnics sense traduir quan sigui habitual. "
                f"Retorna {{\"traduccions\": [...]}} amb exactament {len(batch)} textos, en el mateix ordre.\n\n"
                + json.dumps(batch, ensure_ascii=False)
            )
            result = self._generate(prompt, temperature=0.1)
            items = result.get("traduccions") if isinstance(result, dict) else None
            if not isinstance(items, list) or len(items) != len(batch):
                raise AIError("La traducció de Gemini no té el nombre de textos esperat.")
            translated.extend(str(item).strip() or original for item, original in zip(items, batch))
        return translated

    def explain(self, vuln, service_label, location, anonymizer=None):
        """Explicació senzilla d'una troballa: {"que_es", "risc", "que_cal_fer"}."""
        anonymizer = anonymizer or Anonymizer(enabled=False)
        data = {
            "cve": vuln.cve_id,
            "gravetat": vuln.severity.value,
            "puntuacio_cvss": vuln.cvss_score,
            "servei": anonymizer.hide(service_label),
            "equip": anonymizer.alias(location) if location else "",
            "descripcio_tecnica": anonymizer.hide(vuln.description[:1200]),
            "exploit_public": vuln.exploit_available,
            "recomanacio_tecnica": vuln.recommendation,
        }
        prompt = (
            "Explica aquesta troballa d'una auditoria a una persona de l'empresa sense coneixements tècnics, "
            "amb frases curtes i un exemple fàcil si ajuda. Retorna un JSON amb els camps \"que_es\" "
            "(2-3 frases), \"risc\" (2-3 frases: què podria passar a l'empresa) i \"que_cal_fer\" "
            "(llista de 2-4 accions concretes).\n\n" + json.dumps(data, ensure_ascii=False)
        )
        result = self._generate(prompt)
        if not isinstance(result, dict):
            raise AIError("Gemini no ha retornat l'explicació amb el format esperat.")
        actions = result.get("que_cal_fer") or []
        explanation = {
            "que_es": str(result.get("que_es", "")).strip(),
            "risc": str(result.get("risc", "")).strip(),
            "que_cal_fer": [str(a).strip() for a in (actions if isinstance(actions, list) else [actions]) if str(a).strip()],
        }
        explanation = anonymizer.show_all(explanation)
        explanation["proveidor"] = self.provider
        return explanation

    def company_report(self, session, client_name="", anonymizer=None):
        """Contingut de l'informe senzill per a l'empresa (vegeu ReportGenerator.generate_company_pdf)."""
        anonymizer = anonymizer or Anonymizer(session, enabled=False)
        findings = []
        for host in session.hosts:
            for service in host.services:
                for vuln in service.vulnerabilities:
                    findings.append({
                        "gravetat": vuln.severity.value, "cvss": vuln.cvss_score, "cve": vuln.cve_id,
                        "equip": anonymizer.alias(host.ip),
                        "servei": f"{service.port}/{service.protocol} {service.product} {service.version}".strip(),
                        "descripcio": anonymizer.hide(vuln.description[:400]),
                        "exploit_public": vuln.exploit_available,
                    })
        for vuln in session.hardening_findings:
            findings.append({"gravetat": vuln.severity.value, "cvss": vuln.cvss_score, "cve": vuln.cve_id,
                             "equip": "equip auditat (sistema local)", "servei": "configuració del sistema",
                             "descripcio": anonymizer.hide(vuln.description[:400]), "exploit_public": False})
        order = {sev.value: i for i, sev in enumerate([Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                                                        Severity.LOW, Severity.INFO])}
        findings.sort(key=lambda f: (order.get(f["gravetat"], 9), not f["exploit_public"]))
        counts = {}
        for finding in findings:
            counts[finding["gravetat"]] = counts.get(finding["gravetat"], 0) + 1
        data = {
            "empresa_client": client_name or "l'empresa client",
            "equips_analitzats": len(session.hosts),
            "ports_oberts": sum(len(h.services) for h in session.hosts),
            "troballes_per_gravetat": counts,
            "troballes": findings[:MAX_REPORT_FINDINGS],
            "troballes_no_incloses": max(0, len(findings) - MAX_REPORT_FINDINGS),
        }
        prompt = (
            "A partir dels resultats tècnics d'aquesta auditoria, redacta l'informe senzill per a la direcció de "
            "l'empresa. Agrupa les troballes semblants en un sol risc i ordena'ls per urgència. Retorna un JSON "
            "amb aquests camps:\n"
            f"- \"nivell_risc\": un d'aquests valors: {', '.join(RISK_LEVELS)};\n"
            "- \"resum\": 3-5 frases per a la direcció (situació general, el més greu i què es recomana);\n"
            "- \"punts_clau\": llista de 3-5 frases curtes;\n"
            "- \"riscos\": llista d'un màxim de 8 objectes amb \"titol\", \"explicacio\" (què passa, sense "
            "tecnicismes), \"impacte\" (què podria passar a l'empresa), \"urgencia\" (un de: "
            f"{', '.join(URGENCY_LEVELS)}), \"accio\" (què cal fer) i \"equips\" (llista d'equips afectats);\n"
            "- \"recomanacions\": llista de 3-6 recomanacions generals;\n"
            "- \"glossari\": llista de 3-6 objectes amb \"terme\" i \"definicio\" per als termes tècnics que "
            "facis servir.\n"
            "Si no hi ha cap troballa, digues-ho clarament i fes recomanacions de manteniment.\n\n"
            + json.dumps(data, ensure_ascii=False)
        )
        result = self._generate(prompt, temperature=0.3)
        if not isinstance(result, dict):
            raise AIError("Gemini no ha retornat l'informe amb el format esperat.")
        report = anonymizer.show_all(_normalize_report(result))
        report["proveidor"] = self.provider
        return report

    # ------------------------------------------------------------------ #
    def _generate(self, prompt, temperature=0.3):
        body = {
            "systemInstruction": {"parts": [{"text": SYSTEM_PROMPT}]},
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {"temperature": temperature, "responseMimeType": "application/json"},
        }
        if self.via_argos:
            try:
                data = argos_api.post("/v1/gemini", {"model": self.model, **body})
            except argos_api.ArgosAPIError as exc:
                if not exc.own and ("free tier is not available" in str(exc) or "billing" in str(exc).lower()):
                    raise AIError("L'API d'Argos no pot fer servir Gemini: cal activar la facturació al projecte de "
                                  "Google de la clau de l'empresa.") from exc
                raise (AIError(str(exc)) if exc.own else _http_error(exc.status, str(exc))) from exc
        else:
            for model in dict.fromkeys([self.model, FALLBACK_MODEL]):
                try:
                    response = requests.post(API_URL.format(model=model), json=body, timeout=TIMEOUT,
                                             headers={"x-goog-api-key": self.api_key})
                except requests.exceptions.RequestException as exc:
                    raise AIError(f"No s'ha pogut connectar amb Gemini. Comproveu la connexió a Internet ({exc}).") from exc
                if response.status_code not in (429, 500, 503):
                    break  # resposta correcta o error que no s'arregla canviant de model
            if not response.ok:
                try:
                    detail = response.json().get("error", {}).get("message", "")
                except ValueError:
                    detail = ""
                raise _http_error(response.status_code, detail)
            try:
                data = response.json()
            except ValueError as exc:
                raise AIError("Gemini ha retornat una resposta inesperada.") from exc
            data.setdefault("argos_proveidor", f"Google Gemini ({model})")
        self.provider = data.get("argos_proveidor") or "Google Gemini"
        try:
            candidate = data["candidates"][0]
            text = "".join(part.get("text", "") for part in candidate["content"]["parts"])
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise AIError("Gemini no ha retornat cap resposta (pot ser que l'hagi bloquejat el seu filtre).") from exc
        return _parse_json(text)


def _parse_json(text):
    """Llegeix el JSON de la resposta, encara que el model hi afegeixi text o blocs de codi al voltant."""
    text = _strip_fences(text)
    candidates = [text]
    start, end = text.find("{"), text.rfind("}")
    if 0 <= start < end:
        candidates.append(text[start:end + 1])
    for candidate in candidates:
        try:
            return json.loads(candidate, strict=False)
        except ValueError:
            continue
    raise AIError("La resposta de la IA no és JSON vàlid. Torneu-ho a provar.")


def _strip_fences(text):
    text = text.strip()
    match = re.match(r"^```(?:json)?\s*(.*?)\s*```$", text, re.S)
    return match.group(1) if match else text


def _http_error(code, detail):
    if "free tier is not available" in detail or "billing" in detail.lower():
        return AIError("La clau és vàlida, però el pla gratuït de Gemini no està disponible per al projecte de "
                       "Google d'aquesta clau. Activeu-hi la facturació a https://aistudio.google.com/billing o "
                       "feu servir una clau d'un altre projecte.")
    if code in (400, 401, 403) and ("API key" in detail or "API_KEY" in detail or code in (401, 403)):
        return AIError("La clau de l'API de Gemini no és vàlida o no té permís. Reviseu-la a "
                       "https://aistudio.google.com/apikey.")
    if code == 404:
        return AIError("El model de Gemini configurat no existeix o no està disponible per a aquesta clau.")
    if code == 429:
        return AIError("S'ha arribat al límit de consultes del pla gratuït de Gemini. Espereu un minut i "
                       "torneu-ho a provar.")
    if code >= 500:
        return AIError("Gemini està saturat o no està disponible ara mateix. Torneu-ho a provar d'aquí a una estona.")
    return AIError(f"Error de l'API de Gemini (HTTP {code}): {detail[:200]}")


def _normalize_report(result):
    """Assegura que l'informe tingui tots els camps i valors coneguts, encara que la IA n'ometi algun."""
    def text_list(value):
        return [str(v).strip() for v in (value if isinstance(value, list) else []) if str(v).strip()]

    level = str(result.get("nivell_risc", "")).strip().capitalize()
    risks = []
    for risk in result.get("riscos") or []:
        if not isinstance(risk, dict):
            continue
        urgency = str(risk.get("urgencia", "")).strip().capitalize()
        risks.append({
            "titol": str(risk.get("titol", "")).strip(),
            "explicacio": str(risk.get("explicacio", "")).strip(),
            "impacte": str(risk.get("impacte", "")).strip(),
            "urgencia": urgency if urgency in URGENCY_LEVELS else "Planificada",
            "accio": str(risk.get("accio", "")).strip(),
            "equips": text_list(risk.get("equips")),
        })
    glossary = [{"terme": str(g.get("terme", "")).strip(), "definicio": str(g.get("definicio", "")).strip()}
                for g in (result.get("glossari") or []) if isinstance(g, dict) and g.get("terme")]
    return {
        "nivell_risc": level if level in RISK_LEVELS else "Moderat",
        "resum": str(result.get("resum", "")).strip(),
        "punts_clau": text_list(result.get("punts_clau")),
        "riscos": risks[:8],
        "recomanacions": text_list(result.get("recomanacions")),
        "glossari": glossary,
    }
