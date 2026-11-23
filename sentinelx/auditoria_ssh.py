#!/usr/bin/env python3
"""Auditoria de seguretat d'un servidor SSH amb ssh-audit, des del terminal (SentinelX Audit Suite).

Fa servir el mòdul core/ssh_audit.py, el mateix que la pestanya Auditoria SSH de l'aplicació. Cada
auditoria es desa en una sessió de SentinelX (auditories_ssh.json, a la carpeta de configuració),
que es pot obrir a la pestanya Informes amb «Carregar Sessió».

Ús (des de la carpeta de SentinelX):
    venv/bin/python3 auditoria_ssh.py

Feu-lo servir només sobre servidors que tingueu autorització per auditar.
"""
import sys

from core.ssh_audit import SshAuditError, install, is_available, load_history, run_audit, save_to_history
from core.ssh_audit import tree_lines, validate_host, validate_port


def auditoria_ssh():
    print("\n=== AUDITORIA DE SEGURETAT SSH (ssh-audit) ===")

    if not is_available():
        print("ssh-audit no està instal·lat a l'entorn de SentinelX.")
        if input("Vols instal·lar-lo ara amb pip? [s/N] ").strip().lower() != "s":
            return None
        try:
            print(install())
        except SshAuditError as exc:
            print(f"Error: {exc}")
            return None

    try:
        host = validate_host(input("Introdueix l'adreça IP o hostname del servidor SSH: "))
        port = validate_port(input("Introdueix el port (deixa en blanc per al port 22 per defecte): "))
    except SshAuditError as exc:
        print(f"Error: {exc}")
        return None

    print(f"\n[+] Executant ssh-audit contra {host}:{port}...\n", flush=True)
    try:
        dades = run_audit(host, port)
    except SshAuditError as exc:
        print(f"Error: {exc}")
        return None

    mostra(dades)
    print(f"\n[+] Auditoria desada a {save_to_history(dades)}")
    return dades


def historial():
    auditories = load_history().ssh_audits
    if not auditories:
        print("\nEncara no hi ha cap auditoria desada.")
        return
    print("\n--- AUDITORIES DESADES ---")
    for numero, auditoria in enumerate(auditories, 1):
        resum = auditoria["resum"]
        print(f"{numero}. {auditoria['objectiu']} ({auditoria['data'][:16].replace('T', ' ')}): "
              f"{resum['obsolets']} obsolet(s), {resum['avisos']} avís(os)")
    opcio = input("\nNúmero de l'auditoria que vols veure (en blanc per tornar): ").strip()
    if opcio.isdigit() and 1 <= int(opcio) <= len(auditories):
        mostra(auditories[int(opcio) - 1])


def mostra(dades):
    print("=" * 60)
    for linia in tree_lines(dades):
        print(linia)
    print("=" * 60)


def menu():
    while True:
        print("\n--- MENÚ D'AUDITORIA SSH ---")
        print("1. Auditar un servidor SSH")
        print("2. Veure les auditories desades")
        print("0. Sortir")
        opcio = input("\nSelecciona una opció (0-2): ").strip()
        if opcio == "0":
            return
        if opcio == "1":
            auditoria_ssh()
        elif opcio == "2":
            historial()
        else:
            print("Opció no vàlida.")


if __name__ == "__main__":
    try:
        menu()
    except (KeyboardInterrupt, EOFError):
        print("\nFins aviat.")
        sys.exit(0)
