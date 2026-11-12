# Inici Ràpid — SentinelX Audit Suite

Posa SentinelX en marxa a Ubuntu 24.04/26.04 en pocs minuts.

> Descarrega la darrera versió des de
> [GitHub Releases](https://github.com/razvan-ng/argos-cyber-defense/releases/latest)
> i descomprimeix-la (`unzip sentinelx-audit-suite.zip && cd sentinelx-audit-suite`).

## 1. Instal·la les dependències del sistema

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

Això instal·la `nmap`, `traceroute`, eines de xarxa, Python i crea l'entorn
virtual amb totes les llibreries necessàries. Si acaba amb codi de sortida
`0`, ja pots continuar.

## 2. Activa l'entorn virtual

```bash
source venv/bin/activate
```

## 3. Executa l'aplicació

```bash
python main.py
```

En la primera arrencada es comprovaran automàticament les eines del sistema
(health check). Si falta alguna eina obligatòria, l'aplicació t'indicarà
exactament què instal·lar.

## 4. Fes la teva primera auditoria

1. (Opcional) A la pestanya **Reconeixement passiu**, desa la clau de l'API de Shodan i consulta
   què se sap de l'IP pública de l'objectiu abans d'escanejar-la. **Afegeix a l'auditoria** en
   passa els ports i serveis a la sessió. A la pestanya **OSINT**, The Harvester cerca correus i
   subdominis públics del domini del client.
2. A la pestanya **Auditoria de Xarxa**, introdueix l'IP o subxarxa a
   auditar (ex. `192.168.1.0/24`) i prem **Descobriment d'Equips**.
3. Selecciona un equip (doble clic per copiar la seva IP) i executa
   **Escaneig de Ports i Serveis**.
4. Ves a **Vulnerabilitats i CVE** i prem **Analitzar Serveis Detectats**.

## 5. Revisa les troballes

El **Tauler** mostra un resum d'un cop d'ull i la llista de "Què cal
arreglar primer?", ordenada per gravetat.

## 6. Genera l'informe

A la pestanya **Informes**, exporta el resultat en HTML, PDF, JSON o CSV.

## 7. Desa-la a l'expedient del client

A la pestanya **Expedients**, inicia la sessió amb el teu usuari administrador de la web i obre
l'expedient del client (si ja té auditories, la nova serà una **reauditoria** i podràs comparar-la
amb l'anterior). SentinelX hi desa els resultats com a esborrany i, quan estiguin revisats,
**Publica per al client** els fa visibles a l'Àrea de clients de
[argoscyberdefense.tech](https://argoscyberdefense.tech).

Si l'equip no pot connectar amb el portal (per exemple, en una xarxa sense Internet), fes
servir **Obre un fitxer d'expedient** i **Exporta per al portal** (mode fitxer).

---

Per a instal·lació manual, opcions avançades (escaneig UDP, tots els ports,
escaneig actiu NSE, reforçament del sistema, sessions i comparació amb
auditories anteriors), publicació al portal de clients i solució de problemes, consulta el
[README.md](README.md).
