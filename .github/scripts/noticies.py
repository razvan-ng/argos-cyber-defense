#!/usr/bin/env python3
"""Recull les notícies de ciberseguretat per a la web d'Argos Cyber Defense.

L'allotjament gratuït de la web (InfinityFree) no pot connectar amb les fonts externes, així que
aquest script s'executa a GitHub Actions cada 3 hores i publica el resultat en un fitxer JSON a la
branca `noticies`. La web el llegeix des del servidor o, si no pot, des del navegador.

Ús: python3 noticies.py fitxer_sortida.json
"""

import email.utils
import html
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

USER_AGENT = "Mozilla/5.0 (compatible; ArgosNews/3.0; +https://argoscyberdefense.tech/noticies/)"
ITEMS_PER_SOURCE = 25
KEV_ITEMS = 15
MAX_BYTES = 8 * 1024 * 1024

# Mateixes fonts que DEFAULT_NEWS_SOURCES de la web (app/lib/news.php)
SOURCES = [
    {"nom": "INCIBE-CERT", "url": "https://www.incibe.es/incibe-cert/alerta-temprana/avisos/feed",
     "web": "https://www.incibe.es/incibe-cert/alerta-temprana/avisos", "tipus": "rss", "idioma": "es"},
    {"nom": "Una al Día (Hispasec)", "url": "https://unaaldia.hispasec.com/feed",
     "web": "https://unaaldia.hispasec.com", "tipus": "rss", "idioma": "es"},
    {"nom": "The Hacker News", "url": "https://feeds.feedburner.com/TheHackersNews",
     "web": "https://thehackernews.com", "tipus": "rss", "idioma": "en"},
    {"nom": "BleepingComputer", "url": "https://www.bleepingcomputer.com/feed/",
     "web": "https://www.bleepingcomputer.com", "tipus": "rss", "idioma": "en"},
    {"nom": "CISA KEV", "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
     "web": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", "tipus": "kev", "idioma": "en"},
]

ATOM = "{http://www.w3.org/2005/Atom}"
CONTENT = "{http://purl.org/rss/1.0/modules/content/}encoded"


def fetch(url):
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/rss+xml, application/xml, application/json, text/xml;q=0.9, */*;q=0.5",
    })
    with urllib.request.urlopen(request, timeout=25) as response:
        return response.read(MAX_BYTES)


def clean(text):
    """Text pla a partir de l'HTML dels canals (sense etiquetes ni espais repetits)."""
    text = re.sub(r"<[^>]+>", " ", text or "")
    return re.sub(r"\s+", " ", html.unescape(text)).strip()


def excerpt(text, length):
    if len(text) <= length:
        return text
    cut = text[:length]
    space = cut.rfind(" ")
    if space > length * 0.6:
        cut = cut[:space]
    return cut.rstrip(" ,.;:") + "…"


def parse_date(value):
    value = (value or "").strip()
    if not value:
        return None
    try:
        parsed = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def first_text(entry, names):
    for name in names:
        node = entry.find(name)
        if node is not None and (node.text or "").strip():
            return node.text
    return ""


def parse_feed(body):
    root = ET.fromstring(body)
    entries = root.findall("./channel/item") or root.findall(f"{ATOM}entry")
    items = []
    for entry in entries:
        title = clean(first_text(entry, ["title", f"{ATOM}title"]))
        link = first_text(entry, ["link"]).strip()
        if not link:
            atom_link = entry.find(f"{ATOM}link")
            link = atom_link.get("href", "") if atom_link is not None else ""
        summary = clean(first_text(entry, ["description", f"{ATOM}summary", CONTENT, f"{ATOM}content"]))
        if title and summary.startswith(title):
            summary = summary[len(title):].lstrip()
        category = clean(first_text(entry, ["category"]))
        if not category:
            atom_category = entry.find(f"{ATOM}category")
            category = clean(atom_category.get("term", "")) if atom_category is not None else ""
        date = parse_date(first_text(entry, ["pubDate", f"{ATOM}published", f"{ATOM}updated"]))
        if not title or not re.match(r"^https?://", link, re.I):
            continue
        items.append({
            "titol": title[:300],
            "resum": excerpt(summary, 320),
            "url": link[:700],
            "etiqueta": category[:60],
            "publicat_el": date,
        })
        if len(items) >= ITEMS_PER_SOURCE:
            break
    return items


def parse_kev(body):
    data = json.loads(body)
    vulnerabilities = data.get("vulnerabilities") if isinstance(data, dict) else None
    if not isinstance(vulnerabilities, list):
        return []
    vulnerabilities.sort(key=lambda v: str(v.get("dateAdded", "")), reverse=True)
    items = []
    for vuln in vulnerabilities[:KEV_ITEMS]:
        cve = str(vuln.get("cveID", ""))
        if not re.match(r"^CVE-\d{4}-\d{4,7}$", cve):
            continue
        ransomware = " Utilitzada en campanyes de ransomware." if vuln.get("knownRansomwareCampaignUse") == "Known" else ""
        try:
            date = datetime.strptime(str(vuln.get("dateAdded", "")), "%Y-%m-%d").replace(hour=8, tzinfo=timezone.utc)
        except ValueError:
            date = None
        items.append({
            "titol": f"{cve}: {clean(str(vuln.get('vulnerabilityName', '')))}"[:300],
            "resum": excerpt(clean(str(vuln.get("shortDescription", ""))) + ransomware, 320),
            "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
            "etiqueta": clean(f"{vuln.get('vendorProject', '')} {vuln.get('product', '')}")[:60],
            "publicat_el": date,
        })
    return items


def read_source(source):
    try:
        try:
            body = fetch(source["url"])
        except OSError:
            body = fetch(source["url"])  # segon intent: alguns servidors tallen connexions esporàdicament
        items = parse_kev(body) if source["tipus"] == "kev" else parse_feed(body)
        if not items:
            raise ValueError("La font no ha retornat cap notícia (format no reconegut).")
        return source, items, None
    except Exception as exc:  # noqa: BLE001 - una font que falla no ha d'aturar les altres
        return source, [], f"{type(exc).__name__}: {exc}"[:300]


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2

    now = datetime.now(timezone.utc)
    with ThreadPoolExecutor(max_workers=len(SOURCES)) as pool:
        results = list(pool.map(read_source, SOURCES))

    fonts = []
    news = []
    for source, items, error in results:
        fonts.append({**source, "total": len(items), "error": error})
        for item in items:
            date = min(item["publicat_el"] or now, now)
            news.append({**item, "font_url": source["url"], "font": source["nom"], "tipus": source["tipus"],
                         "idioma": source["idioma"], "publicat_el": date.strftime("%Y-%m-%dT%H:%M:%SZ")})
        print(f"{source['nom']}: {len(items)} notícies" + (f" (error: {error})" if error else ""))

    if not news:
        print("Cap font ha respost: no es publica res i es manté el fitxer anterior.")
        return 1

    news.sort(key=lambda n: n["publicat_el"], reverse=True)
    output = {"versio": 1, "generat_el": now.strftime("%Y-%m-%dT%H:%M:%SZ"), "fonts": fonts, "noticies": news}
    with open(sys.argv[1], "w", encoding="utf-8") as handle:
        json.dump(output, handle, ensure_ascii=False, separators=(",", ":"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
