#!/usr/bin/env python3
"""Reconeixement passiu des del terminal (SentinelX Audit Suite): Shodan i The Harvester.

Versió de línia d'ordres del mòdul core/shodan_intel.py, que també fa servir la pestanya
«Reconeixement passiu» de l'aplicació. Cap de les consultes envia paquets a l'objectiu.

L'opció 5 llança The Harvester (cerca OSINT) amb subprocess, amb el mòdul core/harvester.py que
també fa servir la pestanya «OSINT». L'instal·la ./install_dependencies.sh.

Ús (des de la carpeta de SentinelX):
    venv/bin/python3 shodan_recon.py

La clau de l'API es llegeix de la variable d'entorn SHODAN_API_KEY o de la configuració de
SentinelX (la que es desa a la pestanya). Si no n'hi ha cap, el programa la demana.
"""
import getpass
import subprocess
import sys

from core.harvester import (
    DEFAULT_SOURCE, INSTALL_HINT, SOURCES, HarvesterError, build_command, check_source, command_name, find_executable,
    output_files, summarize, validate_domain,
)
from core.shodan_intel import (
    SEARCH_LIMITS, ShodanError, ShodanRecon, api_key_path, library_available, load_api_key, mask_key,
    save_api_key, service_label,
)

LINE = "=" * 60
MENU = """
SentinelX: reconeixement passiu (Shodan i The Harvester)
  1. Consulta d'host (IP, dominis i ports oberts)
  2. Identificació de serveis (banner grabbing)
  3. Cerca de serveis específics
  4. Estat de la clau de l'API
  5. Cerca OSINT amb The Harvester
  0. Surt
"""


def ask_api_key():
    key, source = load_api_key()
    if key:
        return key, source
    print("No hi ha cap clau de l'API de Shodan configurada (la trobareu a https://account.shodan.io).")
    key = getpass.getpass("Clau de l'API (no es mostra en escriure-la): ").strip()
    if key and input("Voleu desar-la al perfil de l'usuari per a la propera vegada? [s/N] ").strip().lower() == "s":
        print(f"Desada a {save_api_key(key)} (permisos 600).")
    return key, "teclat"


def show_host(recon, with_services):
    lookup = recon.host_lookup(input("Adreça IP pública: "))
    print(f"\n{LINE}")
    print(f"IP consultada: {lookup['ip']}")
    print(f"Noms de domini: {', '.join(lookup['hostnames']) or 'cap domini associat'}")
    print(f"Ports oberts: {', '.join(str(p) for p in lookup['ports']) or 'cap'}")
    if with_services:
        print("\nServeis identificats (banner grabbing):")
        for service in lookup["services"]:
            print(f"  Port {service['port']}/{service['transport']}: {service_label(service)}")
            if service["banner"] and not service["product"]:
                print(f"      Banner: {service['banner']}")
        details = [lookup["org"] or lookup["isp"], lookup["country"], lookup["os"]]
        print(f"\nOrganització, país i SO: {', '.join(d for d in details if d) or 'sense dades'}")
        if lookup["vulns"]:
            print(f"CVE que Shodan hi associa per versió (sense verificar): {len(lookup['vulns'])}")
        print(f"Darrera actualització a Shodan: {lookup['last_update'] or 'desconeguda'}")
    print(LINE)


def show_search(recon):
    query = input("Servei o producte (p. ex. proftpd, nginx, webcam): ")
    limit = input(f"Nombre de resultats {'/'.join(str(n) for n in SEARCH_LIMITS)} [5]: ").strip() or "5"
    result = recon.search(query, limit=int(limit) if limit.isdigit() else 5)
    print(f"\n{LINE}")
    print(f"Cerca: «{result['query']}». Resultats a Shodan: {result['total']:,}".replace(",", "."))
    if result["mode"] == "complet":
        print(f"\n{'Adreça IP':<18}{'Port':<10}Organització o ISP")
        for match in result["results"]:
            print(f"{match['ip']:<18}{str(match['port']) + '/' + match['transport']:<10}"
                  f"{match['org'] or match['isp'] or 'no disponible'}")
    else:
        print(f"\nAvís: {result['notice']}")
        print("Resum gratuït (recompte de Shodan per facetes):")
        for facet, title in (("port", "Ports"), ("org", "Organitzacions"), ("country", "Països")):
            values = ", ".join(f"{item['value']} ({item['count']:,})".replace(",", ".")
                               for item in result["facets"].get(facet, []))
            print(f"  {title}: {values or 'sense dades'}")
    print(LINE)


def show_key_status(recon, source):
    info = recon.account_info()
    origin = {"entorn": "variable d'entorn SHODAN_API_KEY", "fitxer": api_key_path()}.get(source, "introduïda ara")
    print(f"\nClau {mask_key(recon.api.api_key)} ({origin})")
    print(f"Pla: {info['plan']}. Crèdits de consulta: {info['query_credits']}. Crèdits d'escaneig: {info['scan_credits']}.")


def harvester_search():
    """Opció 5: demana domini, font i fitxer, construeix la comanda i la llança amb subprocess."""
    tool = find_executable()
    if not tool:
        print(INSTALL_HINT)
        return
    domini = validate_domain(input("Domini objectiu (p. ex. iesebre.cat): "))
    while True:
        font = input(f"Font de dades ({', '.join(SOURCES)}) [{DEFAULT_SOURCE}]: ").strip().lower() or DEFAULT_SOURCE
        try:
            check_source(tool, font)
            break
        except HarvesterError as exc:
            print(exc)
    fitxer = ""
    if input("Voleu desar els resultats en un fitxer (XML i JSON)? [s/N] ").strip().lower() == "s":
        fitxer = input("Nom del fitxer (sense extensió): ").strip()
    comanda = build_command(domini, font, fitxer, executable=command_name(tool))
    print(f"[*] Iniciant escaneig sobre {domini} utilitzant {font}...")
    print(f"[*] Comanda: {comanda}\n", flush=True)
    subprocess.call(comanda, shell=True)
    if fitxer:
        xml, json_file = output_files(fitxer)
        print(f"\n[*] Resultats desats a {xml} i {json_file}")
        for label, count, _first in summarize(json_file):
            print(f"    {label}: {count}")


def main():
    state = {}

    def shodan():
        """Connecta amb Shodan només quan es tria una opció de Shodan."""
        if "recon" not in state:
            if not library_available():
                raise ShodanError("Falta la llibreria de Shodan: instal·leu-la amb «venv/bin/pip install shodan».")
            key, state["source"] = ask_api_key()
            state["recon"] = ShodanRecon(key)
        return state["recon"]

    actions = {
        "1": lambda: show_host(shodan(), with_services=False),
        "2": lambda: show_host(shodan(), with_services=True),
        "3": lambda: show_search(shodan()),
        "4": lambda: show_key_status(shodan(), state["source"]),
        "5": harvester_search,
    }
    while True:
        print(MENU)
        choice = input("Opció: ").strip()
        if choice == "0":
            return 0
        if choice not in actions:
            print("Opció no vàlida.")
            continue
        try:
            actions[choice]()
        except (ShodanError, HarvesterError) as exc:
            print(f"\nError: {exc}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print("\nFins aviat.")
