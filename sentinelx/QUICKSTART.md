# Inici Ràpid — SentinelX Audit Suite

Posa SentinelX en marxa a Ubuntu 24.04/26.04 en pocs minuts.

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

1. A la pestanya **Auditoria de Xarxa**, introdueix l'IP o subxarxa a
   auditar (ex. `192.168.1.0/24`) i prem **Descobriment d'Equips**.
2. Selecciona un equip (doble clic per copiar la seva IP) i executa
   **Escaneig de Ports i Serveis**.
3. Ves a **Vulnerabilitats i CVE** i prem **Analitzar Serveis Detectats**.

## 5. Revisa les troballes

El **Tauler** mostra un resum d'un cop d'ull i la llista de "Què cal
arreglar primer?", ordenada per gravetat.

## 6. Genera l'informe

A la pestanya **Informes**, exporta el resultat en HTML, PDF, JSON o CSV.

---

Per a instal·lació manual, opcions avançades (escaneig UDP, tots els ports,
escaneig actiu NSE, reforçament del sistema, sessions i comparació amb
auditories anteriors) i solució de problemes, consulta el [README.md](README.md).
