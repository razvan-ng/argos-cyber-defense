#!/usr/bin/env python3
"""Escaneig de xarxa amb Nmap per modalitats, des del terminal (SentinelX Audit Suite).

Script original de Mouhammed Oualy, integrat a SentinelX: el menú i els missatges són els seus, i
les quatre modalitats fan servir el mòdul core/nmap_modes.py, el mateix que la pestanya Auditoria
de Xarxa de l'aplicació.

Ús (des de la carpeta de SentinelX):
    venv/bin/python3 escaneig.py

Feu-lo servir només sobre xarxes i equips que tingueu autorització per auditar.
"""
import sys

from core.nmap_modes import INTRUSIVE_MODES, NmapModeError, normalize_ports, scan, summary_lines, validate_target


def escaneig_nmap():
    while True:
        print("\n--- MENÚ D'ESCANEIG AMB NMAP ---")
        print("1. Descobriment d'hosts actius a la xarxa (-sn)")
        print("2. Escaneig i identificació de ports oberts")
        print("3. Llistat detallat de serveis i versions (-sV)")
        print("4. Llistat de vulnerabilitats conegudes (--script vuln)")
        print("0. Sortir")

        opcio = input("\nSelecciona una modalitat d'escaneig (0-4): ").strip()
        if opcio == "0":
            return
        if opcio not in ("1", "2", "3", "4"):
            print("Opció no vàlida.")
            continue
        mode = int(opcio)

        target = input("Introdueix l'host o rang de xarxa objectiu (ex: 192.168.1.1 o 192.168.1.0/24): ").strip()
        ports = ""
        if mode == 2:
            ports = input("Introdueix el rang de ports (deixa en blanc per als ports per defecte, ex: 22-80,443; "
                          "«tots» per a tots): ").strip()
        elif mode == 3:
            ports = input("Introdueix el port o rang de ports (deixa en blanc per als principals; «tots» per a "
                          "tots els ports): ").strip()
        elif mode == 4:
            ports = input("Introdueix el port o rang de ports dels serveis a analitzar (deixa en blanc per als "
                          "principals; «tots» per a tots): ").strip()

        try:  # es comprova abans de començar, perquè l'error surti de seguida
            validate_target(target)
            normalize_ports(ports)
        except NmapModeError as exc:
            print(f"Error: {exc}")
            continue

        if mode in INTRUSIVE_MODES and input(
            "Els scripts de vulnerabilitats interactuen amb els serveis de l'objectiu. Tens autorització per "
            "auditar-lo? [s/N] "
        ).strip().lower() != "s":
            print("Escaneig cancel·lat.")
            continue

        missatges = {1: f"Escanejant hosts actius a {target}...", 2: f"Escanejant ports oberts a {target}...",
                     3: f"Detectant serveis i versions a {target}...",
                     4: f"Analitzant vulnerabilitats a {target} (això pot trigar uns minuts)..."}
        print(f"\n{missatges[mode]}", flush=True)
        try:
            resultat = scan(mode, target, ports)
        except NmapModeError as exc:
            print(f"Error: {exc}")
            continue
        print(f"[*] Comanda: {resultat['command']}  ({resultat['elapsed']:.0f} s)\n")
        for linia in resultat["lines"]:
            print(linia)
        if mode == 4:
            print()
            for linia in summary_lines(resultat["hosts"]):
                print(linia)


if __name__ == "__main__":
    try:
        escaneig_nmap()
    except (KeyboardInterrupt, EOFError):
        print("\nFins aviat.")
        sys.exit(0)
