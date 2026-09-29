# SentinelX Audit Suite

**Argos Cyber Defense** — Suite d'auditoria de seguretat informàtica amb interfície gràfica.

Projecte Intermodular — 2n curs, Cicle Formatiu de Grau Superior d'Administració de Sistemes
Informàtics en Xarxa (ASIX).

Equip de desenvolupament:
- Razvan-Andrei Nastasa Ghitau
- Lluc Sarrà Masdeu
- Mouhammed Oualy

> **Avís legal i ètic:** aquesta eina ha d'utilitzar-se exclusivament sobre xarxes i sistemes
> per als quals es disposi d'autorització expressa i per escrit (laboratori propi, entorn de
> pràctiques o auditoria contractada). L'ús no autoritzat sobre sistemes de tercers pot
> constituir un delicte.

> **Vols posar-lo en marxa ràpidament?** Consulta [QUICKSTART.md](QUICKSTART.md).

---

## 1. Descripció

SentinelX Audit Suite és una aplicació d'escriptori (GUI amb CustomTkinter) que permet
realitzar auditories tècniques completes:

0. **Tauler (Dashboard)** — pestanya d'inici amb l'estat de l'auditoria d'un cop d'ull (equips,
   ports oberts, troballes per gravetat), la vista **"Què cal arreglar primer?"** (troballes
   ordenades per risc), l'interruptor de **Mode Segur** (activat per defecte: les accions més
   intrusives demanen confirmació explícita), una guia de primers passos i accés directe a la
   resta de mòduls.
1. **Auditoria de Xarxa Avançada** — descobriment d'equips (`nmap -sn`), escaneig de ports i
   detecció de serveis/versions/SO (`nmap -sV -O`), amb control sobre l'abast de l'escaneig
   (ports habituals, tots els ports `-p-`, ports personalitzats, i escaneig UDP `-sU`), i traçat
   de rutes (`traceroute`/`tracepath`). Doble clic sobre un equip detectat copia la seva IP al
   camp d'objectiu.
2. **Auditoria de Sistema Local** — interfícies, connexions actives, processos, usuaris i estat
   del tallafocs (`ufw`), mitjançant `psutil`; i una pestanya de **Reforçament (Hardening)** que
   detecta actualitzacions pendents, binaris amb bit SUID/SGID, comptes addicionals amb
   privilegis de root (UID 0) i comptes sense contrasenya.
3. **Correlació de Vulnerabilitats i CVE** — dos mètodes complementaris:
   - **Anàlisi passiu**: creua els serveis/versions detectats amb un diccionari local de CVEs
     conegudes i, opcionalment, amb la API pública de la NVD, incloent la comprovació d'exploits
     públics coneguts via `searchsploit` (Exploit-DB).
   - **Escaneig actiu**: executa els scripts de vulnerabilitats de nmap (NSE, `--script vuln`)
     directament contra un objectiu, que confirmen la troballa interactuant amb el servei real.
   La taula de resultats es pot filtrar en temps real per IP, servei, CVE, gravetat o text lliure.
4. **Generador d'Informes** — exportació a HTML, PDF, JSON i CSV amb resum executiu, matriu de
   troballes, reforçament del sistema local i pla de millora.
5. **Sessions d'auditoria** — desar i carregar l'estat complet d'una auditoria en JSON, i
   **comparar-lo amb una auditoria anterior (baseline)** per detectar equips, ports o
   vulnerabilitats nous des de l'última revisió.

Totes les operacions pesades s'executen en fils independents (threading) perquè la interfície
no es bloquegi, amb una consola de logs en temps real i indicadors de progrés visuals.

## 2. Requisits previs (Linux/Ubuntu)

### Opció ràpida: script automàtic (recomanat)

Per a Ubuntu 24.04 LTS / 26.04 LTS, el projecte inclou [install_dependencies.sh](install_dependencies.sh),
que instal·la totes les eines de sistema, crea l'entorn virtual de Python i hi instal·la totes
les dependències en un sol pas. El script no s'atura a la primera errada: prova cada component
per separat, i mostra al final un resum exacte de què ha funcionat i què no (amb el motiu concret
i un fitxer de log complet per a diagnòstic):

```bash
chmod +x install_dependencies.sh
./install_dependencies.sh
```

Si acaba amb codi de sortida `0`, tots els components obligatoris estan instal·lats i verificats
i ja es pot executar `source venv/bin/activate && python main.py`. Si algun component obligatori
falla, el resum indica exactament quin i per què (i el log complet, línia per línia, de la comanda
que ha fallat).

### Opció manual

- Python 3.10 o superior.
- Eines natives del sistema (l'aplicació les comprova automàticament en iniciar-se i mostra
  un avís si en falta alguna):

```bash
sudo apt update
sudo apt install -y nmap traceroute iputils-ping iproute2 net-tools
```

Opcionalment, per habilitar la cerca d'exploits públics coneguts i la comprovació del
tallafocs:

```bash
sudo apt install -y exploitdb ufw
```

> **`exploitdb` és opcional.** SentinelX funciona perfectament sense aquest paquet: només
> s'omet l'enriquiment addicional "exploit conegut" a la pestanya de Vulnerabilitats (la
> correlació de CVE via diccionari local i la consulta a la NVD API continuen funcionant amb
> normalitat). Si `sudo apt install exploitdb` falla amb `Unable to locate package`, sol ser
> perquè el component `universe` del repositori no està habilitat o la versió d'Ubuntu és
> antiga. Solucions, de més a menys senzilla:
>
> ```bash
> # 1) Habilitar el repositori universe i tornar-ho a intentar
> sudo add-apt-repository universe
> sudo apt update
> sudo apt install -y exploitdb
>
> # 2) Si segueix sense trobar-se, instal·lació manual (mètode oficial del projecte)
> sudo git clone https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb
> sudo ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
> sudo ln -sf /opt/exploitdb/searchsploit_rc /usr/local/bin/.searchsploit_rc 2>/dev/null || true
> ```
>
> Després de qualsevol de les dues opcions, comprova amb `searchsploit -h` que l'ordre
> respon correctament; SentinelX el detectarà automàticament al següent inici (health check).

> **Nota sobre privilegis:** la detecció de sistema operatiu (`-O`) i la comprovació del
> tallafocs (`ufw status`) requereixen privilegis d'administrador. Si l'aplicació no s'executa
> amb `sudo`, aquestes funcions concretes poden fallar; la resta de mòduls (descobriment,
> escaneig de serveis, auditoria de sistema, CVE, informes) funcionen sense privilegis elevats.
> Es recomana executar l'aplicació sencera amb `sudo` quan es necessitin aquestes funcions.

## 3. Instal·lació i execució des del codi font

```bash
# 1. Clonar/copiar el projecte i situar-se al directori arrel
cd sentinelx-audit-suite

# 2. Crear i activar un entorn virtual
python3 -m venv venv
source venv/bin/activate

# 3. Instal·lar les dependències de Python
pip install -r requirements.txt

# 4. Executar l'aplicació
python main.py
```

## 4. Estructura del projecte

```
sentinelx/
├── main.py                     # Punt d'entrada
├── requirements.txt
├── install_dependencies.sh     # Instal·lador automàtic (Ubuntu 24.04/26.04)
├── QUICKSTART.md                # Guia d'inici ràpid (5-6 passos)
├── data/
│   ├── cve_signatures.json     # Diccionari local de signatures CVE
│   └── branding.json            # Configuració de marca (nom, empresa, colors...)
├── core/                       # Lògica de negoci (sense dependències de GUI)
│   ├── models.py                # Dataclasses: HostResult, ServiceInfo, Vulnerability...
│   ├── app_state.py              # Estat compartit de la sessió, Mode Segur, prioritats
│   ├── branding.py                # Càrrega de la configuració de marca (data/branding.json)
│   ├── dependency_check.py       # Health check d'eines externes
│   ├── network_scanner.py        # Ping sweep, escaneig de ports/serveis i NSE (nmap)
│   ├── traceroute_tool.py        # Traçat de rutes
│   ├── system_audit.py           # Auditoria de host local (psutil, ufw) i reforçament
│   ├── vuln_correlator.py        # Correlació CVE (local + NVD API + NSE)
│   ├── exploit_intel.py          # Consulta d'exploits coneguts (searchsploit)
│   ├── report_generator.py       # Generació d'informes HTML/PDF/JSON/CSV
│   └── session_io.py             # Desar/carregar sessions i comparació amb baseline
├── gui/
│   ├── app.py                    # Finestra principal
│   ├── theme.py                  # Identitat corporativa (des de branding.json) i colors
│   ├── widgets/                  # Consola de logs, diàleg de dependències, diàleg de diff
│   └── tabs/                     # Pestanyes: Tauler, Xarxa, Sistema, CVE, Informes, Quant a
└── utils/
    ├── shell.py                   # Execució asíncrona de comandes externes
    └── resources.py               # Resolució de rutes compatible amb PyInstaller
```

### Marca configurable (branding)

Perquè la mateixa aplicació es pugui adaptar a diferents organitzacions sense tocar el codi
font, la identitat de marca (nom de producte, empresa, colors corporatius, enllaços de suport
i documentació) es defineix a [data/branding.json](data/branding.json) i es carrega en
arrencar. Editar aquest fitxer i reiniciar l'aplicació n'és suficient; si no existeix o està
incomplet, s'apliquen valors per defecte perquè l'aplicació sempre funcioni.

## 5. Generació de l'executable amb PyInstaller

Amb l'entorn virtual activat i les dependències instal·lades (`pyinstaller` ja és al
`requirements.txt`), des del directori arrel del projecte:

### Linux / Ubuntu (prioritari)

```bash
pyinstaller \
  --name SentinelX \
  --onedir \
  --windowed \
  --add-data "data:data" \
  --collect-all customtkinter \
  --collect-all darkdetect \
  --collect-all PIL \
  --collect-all certifi \
  main.py
```

### Windows (referència)

```powershell
pyinstaller `
  --name SentinelX `
  --onedir `
  --windowed `
  --add-data "data;data" `
  --collect-all customtkinter `
  --collect-all darkdetect `
  --collect-all PIL `
  --collect-all certifi `
  main.py
```

### Resultat

La carpeta distribuïble final es genera a `dist/SentinelX/`, amb l'executable
(`SentinelX` a Linux, `SentinelX.exe` a Windows) i tots els recursos necessaris
(incloent-hi `data/cve_signatures.json`). Aquesta carpeta és **autocontinguda pel que
fa a dependències de Python**, però continua necessitant que `nmap`, `traceroute`, etc.
estiguin instal·lats al sistema operatiu on s'executi, ja que es criden com a binaris
externs (el health-check inicial ho verificarà i ho indicarà si no és així).

Per distribuir l'aplicació, comprimeix o copia sencera la carpeta `dist/SentinelX/`.

### Notes sobre els flags de `--collect-all`

- `customtkinter` / `darkdetect` / `PIL`: aquestes llibreries carreguen recursos (temes JSON,
  fonts, detecció de tema del sistema) en temps d'execució que PyInstaller no detecta
  automàticament per anàlisi estàtica de codi.
- `certifi`: assegura que el certificat d'autoritats (CA bundle) necessari per a les consultes
  HTTPS a la API de la NVD s'inclou a l'executable final.

Si es vol regenerar la configuració de build (fitxer `.spec`), la primera execució de
`pyinstaller` en genera un automàticament al directori arrel, que es pot editar i reutilitzar
en compilacions posteriors (`pyinstaller SentinelX.spec`).

## 6. Notes tècniques addicionals

- La correlació de CVE per versió (mòdul local) fa servir una coincidència simplificada
  (producte + prefix de versió) amb finalitats docents; no substitueix un escàner CPE/CVE
  professional complet com OpenVAS o Nessus.
- La consulta en línia a la NVD API és opcional (checkbox a la pestanya de Vulnerabilitats) i
  degrada de forma silenciosa al mode local si no hi ha connexió a Internet.
- La detecció d'exploits públics mitjançant `searchsploit` és purament informativa: l'aplicació
  no descarrega, executa ni conté cap codi d'explotació.
