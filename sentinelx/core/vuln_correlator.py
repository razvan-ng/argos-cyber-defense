"""Correlació de serveis detectats amb vulnerabilitats conegudes (CVE).

Combina dues fonts:
  1. Un diccionari local de signatures (data/cve_signatures.json) amb
     coincidència simplificada per producte/prefix de versió — funciona
     sense connexió a Internet.
  2. (Opcional) La API pública de la NVD (National Vulnerability Database)
     per obtenir CVEs addicionals mitjançant cerca per paraula clau.

Per a cada vulnerabilitat detectada es comprova, a més, si hi ha exploits
públics coneguts (Exploit-DB via `searchsploit`), per destacar-la com a
risc crític quan n'hi hagi.

Nota: la correlació per versió és una simplificació amb finalitats
docents; no substitueix un escàner CPE/CVE professional complet.
"""
import json
import re

import requests

from core.exploit_intel import ExploitIntelligence
from core.models import Severity, Vulnerability
from utils.resources import resource_path

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
}

RISKY_PROTOCOLS = {
    "telnet": "El servei Telnet transmet credencials i dades en text pla, sense cap tipus de xifrat.",
    "ftp": "El protocol FTP tradicional transmet credencials d'accés en text pla per la xarxa.",
    "rsh": "El servei rsh (remote shell) no xifra ni l'autenticació ni la comunicació.",
    "tftp": "TFTP no requereix autenticació i pot exposar fitxers de configuració del sistema.",
}

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnerabilityCorrelator:
    def __init__(self, use_online=True):
        self.use_online = use_online
        self.local_db = self._load_local_db()
        self.exploit_intel = ExploitIntelligence()

    @staticmethod
    def _load_local_db():
        path = resource_path("data/cve_signatures.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (OSError, json.JSONDecodeError):
            return []

    def correlate_service(self, service, on_log=None):
        findings = []
        product = (service.product or service.service_name or "").lower()
        version = (service.version or "").lower()

        findings.extend(self._match_local_db(product, version))

        if service.service_name and service.service_name.lower() in RISKY_PROTOCOLS:
            findings.append(
                Vulnerability(
                    cve_id="N/A",
                    description=RISKY_PROTOCOLS[service.service_name.lower()],
                    severity=Severity.LOW,
                    cvss_score=None,
                    reference_url="",
                    exploit_available=False,
                    exploit_source="",
                    recommendation="Substituir per una alternativa xifrada del protocol (SSH, SFTP, HTTPS, etc.).",
                )
            )

        if self.use_online and product:
            findings.extend(self._query_nvd(product, version, on_log))

        if self.exploit_intel.is_available():
            for vuln in findings:
                if vuln.exploit_available or vuln.cve_id == "N/A":
                    continue
                results = self.exploit_intel.search_cve(vuln.cve_id)
                if results:
                    vuln.exploit_available = True
                    vuln.exploit_source = f"Exploit-DB (searchsploit): {results[0]['title']}"

        return findings

    def _match_local_db(self, product, version):
        findings = []
        if not product:
            return findings
        for entry in self.local_db:
            if not any(p in product for p in entry.get("product_match", [])):
                continue
            if not version:
                continue
            match_type = entry.get("match_type", "prefix")
            if match_type == "prefix":
                if not version.startswith(entry.get("version_match", "")):
                    continue
            elif match_type == "prefix_list":
                if not any(version.startswith(p) for p in entry.get("version_prefixes", [])):
                    continue
            else:
                continue
            findings.append(
                Vulnerability(
                    cve_id=entry["cve_id"],
                    description=entry["description"],
                    severity=SEVERITY_MAP.get(entry["severity"], Severity.MEDIUM),
                    cvss_score=entry.get("cvss_score"),
                    reference_url=entry.get("reference_url", ""),
                    exploit_available=entry.get("exploit_available", False),
                    exploit_source=entry.get("exploit_source", ""),
                    recommendation=entry.get("recommendation", ""),
                )
            )
        return findings

    def _query_nvd(self, product, version, on_log=None):
        findings = []
        try:
            query = f"{product} {version}".strip()
            response = requests.get(
                NVD_API_URL,
                params={"keywordSearch": query, "resultsPerPage": 5},
                timeout=8,
            )
            if response.status_code != 200:
                if on_log:
                    on_log(f"[AVÍS] La NVD API ha respost amb l'estat {response.status_code}.")
                return findings
            data = response.json()
            for item in data.get("vulnerabilities", []):
                findings.append(self._vulnerability_from_nvd_item(item))
        except (requests.RequestException, ValueError) as exc:
            if on_log:
                on_log(f"[AVÍS] No s'ha pogut consultar la NVD API (mode local únicament): {exc}")
        return findings

    @staticmethod
    def _vulnerability_from_nvd_item(item):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        descriptions = cve.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        cvss_score, severity = VulnerabilityCorrelator._extract_cvss(cve.get("metrics", {}))
        references = cve.get("references", [])
        ref_url = references[0]["url"] if references else f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        return Vulnerability(
            cve_id=cve_id,
            description=description or "Sense descripció disponible.",
            severity=severity,
            cvss_score=cvss_score,
            reference_url=ref_url,
            exploit_available=False,
            exploit_source="",
            recommendation="Revisar l'assessorament oficial del fabricant i aplicar el pedaç més recent disponible.",
        )

    @staticmethod
    def vulnerability_from_nse_finding(finding):
        """Converteix un resultat d'un script NSE (--script vuln) en una Vulnerability.

        Els scripts de vulnerabilitats de nmap confirmen activament la troballa
        (a diferència de la correlació passiva per versió), per la qual cosa es
        classifiquen amb gravetat Alta per defecte llevat que s'hi identifiqui
        un CVE concret dins la sortida del script.
        """
        output = finding.get("output", "")
        match = _CVE_RE.search(output)
        cve_id = match.group(0).upper() if match else f"NSE:{finding.get('script_id', 'desconegut')}"
        script_id = finding.get("script_id", "")
        return Vulnerability(
            cve_id=cve_id,
            description=output[:600],
            severity=Severity.HIGH,
            cvss_score=None,
            reference_url=f"https://nmap.org/nsedoc/scripts/{script_id}.html" if script_id else "",
            exploit_available=False,
            exploit_source="",
            recommendation=(
                "Troballa confirmada activament per un script NSE de nmap: verificar "
                "manualment i aplicar el pedaç o la mitigació corresponent com més aviat millor."
            ),
        )

    @staticmethod
    def _extract_cvss(metrics):
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0]
                cvss_data = metric.get("cvssData", {})
                score = cvss_data.get("baseScore")
                severity_str = metric.get("baseSeverity", cvss_data.get("baseSeverity", "MEDIUM"))
                return score, SEVERITY_MAP.get(severity_str, Severity.MEDIUM)
        return None, Severity.MEDIUM
