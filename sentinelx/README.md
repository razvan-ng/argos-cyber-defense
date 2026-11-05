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
1. **Reconeixement passiu (Shodan)** — abans dels escanejos actius, consulta a l'API de Shodan què
   se sap de l'objectiu a Internet: noms de domini, ports oberts i producte i versió de cada
   servei (banner grabbing), i cerca d'equips per servei o producte. No envia cap paquet a la
   xarxa auditada. Els resultats es poden afegir a l'auditoria (vegeu l'apartat 8).
   La pestanya **OSINT** cerca amb **The Harvester** correus, subdominis i IP públiques d'un domini
   (vegeu l'apartat 9).
2. **Auditoria de Xarxa Avançada** — descobriment d'equips (`nmap -sn`), escaneig de ports i
   detecció de serveis/versions/SO (`nmap -sV -O`), amb control sobre l'abast de l'escaneig
   (ports habituals, tots els ports `-p-`, ports personalitzats, i escaneig UDP `-sU`), i traçat
   de rutes (`traceroute`/`tracepath`). Doble clic sobre un equip detectat copia la seva IP al
   camp d'objectiu.
3. **Auditoria de Sistema Local** — interfícies, connexions actives, processos, usuaris i estat
   del tallafocs (`ufw`), mitjançant `psutil`; i una pestanya de **Reforçament (Hardening)** que
   detecta actualitzacions pendents, binaris amb bit SUID/SGID, comptes addicionals amb
   privilegis de root (UID 0) i comptes sense contrasenya.
4. **Correlació de Vulnerabilitats i CVE** — dos mètodes complementaris:
   - **Anàlisi passiu**: creua els serveis/versions detectats amb un diccionari local de CVEs
     conegudes i, opcionalment, amb la API pública de la NVD, incloent la comprovació d'exploits
     públics coneguts via `searchsploit` (Exploit-DB).
   - **Escaneig actiu**: executa els scripts de vulnerabilitats de nmap (NSE, `--script vuln`)
     directament contra un objectiu, que confirmen la troballa interactuant amb el servei real.
   La taula de resultats es pot filtrar en temps real per IP, servei, CVE, gravetat o text lliure.
5. **Generador d'Informes** — exportació a HTML, PDF, JSON i CSV amb resum executiu, matriu de
   troballes, reforçament del sistema local i pla de millora, i **informe senzill per a l'empresa**
   redactat amb l'assistent d'IA (vegeu l'apartat 10).
6. **Sessions d'auditoria** — desar i carregar l'estat complet d'una auditoria en JSON, i
   **comparar-lo amb una auditoria anterior (baseline)** per detectar equips, ports o
   vulnerabilitats nous des de l'última revisió.
7. **Expedients i portal de clients** — inici de sessió amb l'usuari administrador de la web,
   expedients de cada client, **reauditories** comparades amb l'auditoria anterior (resoltes,
   noves i pendents), desament automàtic a l'expedient i publicació a l'Àrea de clients de
   [argoscyberdefense.tech](https://argoscyberdefense.tech). Inclou un mode fitxer per a allotjaments
   que no permeten la connexió directa (vegeu l'apartat 7).
8. **Actualitzacions** — avisa quan hi ha una versió nova publicada a GitHub.

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
├── shodan_recon.py             # Reconeixement passiu des del terminal (Shodan i The Harvester)
├── requirements.txt
├── install_dependencies.sh     # Instal·lador automàtic (Ubuntu 24.04/26.04)
├── QUICKSTART.md                # Guia d'inici ràpid (5-6 passos)
├── data/
│   ├── cve_signatures.json     # Diccionari local de signatures CVE
│   ├── certs/                   # Certificats intermedis de Let's Encrypt (vegeu core/tls.py)
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
│   ├── shodan_intel.py           # Reconeixement passiu amb l'API de Shodan
│   ├── harvester.py              # Cerca OSINT amb The Harvester (comanda i subprocess)
│   ├── ai_assistant.py           # Assistent d'IA (Gemini): traducció, explicacions i informe per a l'empresa
│   ├── argos_api.py              # Client de l'API d'Argos (Gemini i Shodan sense clau de l'usuari)
│   ├── report_generator.py       # Generació d'informes HTML/PDF/JSON/CSV
│   ├── portal_client.py          # Connexió amb el portal (sessió, expedients, auditories)
│   ├── tls.py                    # Completa la cadena de certificats si el hosting no l'envia
│   ├── expedient_io.py           # Mode fitxer: expedients i auditories sense connexió directa
│   ├── updates.py                # Comprovació de versions noves a GitHub
│   └── session_io.py             # Desar/carregar sessions i comparació amb baseline
├── gui/
│   ├── app.py                    # Finestra principal
│   ├── theme.py                  # Identitat corporativa (des de branding.json) i colors
│   ├── widgets/                  # Consola, dependències, comparació i diàlegs del portal
│   └── tabs/                     # Pestanyes: Tauler, Expedients, Reconeixement, OSINT, Xarxa, Sistema, CVE, Informes, Quant a
└── utils/
    ├── shell.py                   # Execució asíncrona de comandes externes
    └── resources.py               # Resolució de rutes compatible amb PyInstaller
```

### Marca configurable (branding)

Perquè la mateixa aplicació es pugui adaptar a diferents organitzacions sense tocar el codi
font, la identitat de marca (nom de producte, empresa, colors corporatius, enllaços de suport
i documentació, adreça del portal de clients) es defineix a [data/branding.json](data/branding.json)
i es carrega en arrencar. Editar aquest fitxer i reiniciar l'aplicació n'és suficient; si no existeix o està
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
  degrada de forma silenciosa al mode local si no hi ha connexió a Internet. Només es consulta quan
  es coneix la versió del servei, perquè la cerca només pel nom (p. ex. «ssh») dona CVE que no hi
  tenen res a veure.
- La detecció d'exploits públics mitjançant `searchsploit` és purament informativa: l'aplicació
  no descarrega, executa ni conté cap codi d'explotació.

## 7. Expedients i portal de clients

SentinelX treballa amb els mateixos **expedients** que la web d'Argos
([argoscyberdefense.tech](https://argoscyberdefense.tech)). Un expedient és un encàrrec
d'auditoria d'una empresa client: agrupa l'auditoria inicial i les **reauditories** posteriors, i
permet comprovar si el client ha corregit les vulnerabilitats. Els resultats publicats es poden
consultar a l'**Àrea de clients** de la web.

### Connexió directa (inici de sessió d'administrador)

1. Pestanya **Expedients** → escriviu l'adreça del portal i premeu **Inicia la sessió**.
2. Entreu amb el vostre **usuari administrador de la web** (la sessió dura 8 hores i té la
   mateixa protecció que la web: després de 3 intents fallits cal esperar).
3. Trieu l'empresa i obriu l'expedient (o creeu-ne un amb **Nou expedient**):
   - si l'expedient ja té auditories, la darrera es carrega com a **auditoria de referència** i
     la sessió nova és una **reauditoria** amb el mateix objectiu;
   - si no en té, és l'auditoria inicial.
4. Feu els escaneigs habituals. Amb l'opció **Desa automàticament** activada, cada minut que hi
   hagi canvis SentinelX desa els resultats a l'expedient com a **esborrany** (el client no el veu).
5. **Compara amb l'auditoria anterior** mostra què s'ha resolt, què és nou, què continua pendent i
   què no s'ha pogut verificar (equips que aquesta vegada no s'han detectat).
6. **Publica per al client** publica l'auditoria (amb l'informe PDF) a l'Àrea de clients. També es
   pot revisar i publicar des del panell d'administració de la web.

### Mode fitxer (allotjaments que no permeten la connexió, com InfinityFree)

L'allotjament gratuït d'InfinityFree bloqueja totes les connexions que no fa un navegador, de
manera que SentinelX no s'hi pot connectar directament. En aquest cas:

1. A la web, fitxa de l'expedient → **Fitxer per a SentinelX** (descarrega un `.json`).
2. A SentinelX → **Obre un fitxer d'expedient**: es carrega la darrera auditoria com a referència.
3. Feu la reauditoria i compareu-la igual que en la connexió directa.
4. **Exporta per al portal** genera un fitxer amb els resultats (i el PDF).
5. A la web → **Administració → Informes → Puja una auditoria**: el fitxer queda vinculat a
   l'expedient automàticament.

SentinelX detecta quan el portal bloqueja la connexió i ho indica amb un missatge.

### Seguretat

- Tota la comunicació es fa per **HTTPS**; SentinelX no envia credencials per HTTP (excepte a
  `localhost`, per a proves) i no segueix redireccions.
- La contrasenya no es desa mai: l'inici de sessió retorna un testimoni de sessió que només es
  manté en memòria, caduca al cap de 8 hores i l'administrador el pot revocar des de la web
  (Administració → SentinelX). Al servidor només se'n desa el resum SHA-256.
- Només es desen l'adreça del portal i el darrer correu, fora de la carpeta de l'aplicació i amb
  permisos `600`: `~/.config/sentinelx/portal.json` (Linux) o `%APPDATA%\SentinelX\portal.json`
  (Windows). Si executeu SentinelX amb `sudo`, es desen al perfil de `root`.
- El portal valida i normalitza totes les dades rebudes, les desa **xifrades amb AES-256-GCM** i
  cada client només pot veure les auditories **publicades** de la seva empresa.

### API (per a integracions)

| Mètode | Punt | Descripció |
|--------|------|------------|
| `POST` | `/api/v1/sessio.php` | Inicia la sessió (`email`, `contrasenya`, `equip`) i retorna un testimoni |
| `DELETE` | `/api/v1/sessio.php` | Tanca la sessió |
| `GET`  | `/api/v1/estat.php` | Comprova la sessió |
| `GET`  | `/api/v1/empreses.php` | Empreses client actives |
| `GET`  | `/api/v1/expedients.php` | Expedients (`?empresa_id=`, `?estat=`) o detall amb l'historial (`?id=`) |
| `POST` | `/api/v1/expedients.php` | Crea un expedient (`empresa_id`, `titol`, `objectiu`, `notes`) |
| `GET`  | `/api/v1/informes.php?id=N` | Auditoria completa (per a reauditories) |
| `POST` | `/api/v1/informes.php` | Desa una auditoria (`expedient_id`, `informe`, `estat`, `pdf`, `informe_id` per actualitzar un esborrany) |

El testimoni s'envia a `Authorization: Bearer ...` (i a `X-Argos-Token`, perquè alguns hostings
no passen la primera capçalera a PHP). Les respostes són JSON amb el camp `ok`; en cas d'error,
`error.missatge` n'explica el motiu.

### Solució de problemes

| Missatge | Causa i solució |
|----------|-----------------|
| *L'allotjament del portal bloqueja les connexions...* | El hosting (p. ex. InfinityFree) només deixa entrar navegadors. Feu servir el mode fitxer. |
| *No s'ha pogut verificar el certificat HTTPS del portal...* | El certificat SSL de la web no està instal·lat o ha caducat, o la xarxa inspecciona el trànsit HTTPS (centres educatius, empreses). Si el hosting envia el certificat sense l'intermedi, SentinelX el completa sol (Let's Encrypt). |
| *Massa intents fallits...* | Després de 3 intents fallits cal esperar 5 minuts (després 15 i 60). |
| *Només els administradors poden iniciar la sessió a SentinelX* | L'usuari és un client. Feu servir un usuari administrador. |
| *La sessió ha caducat* | Han passat 8 hores o un administrador ha tancat la sessió. Torneu a iniciar-la. |
| *El portal redirigeix la petició a...* | Feu servir l'adreça exacta que indica el missatge (p. ex. sense `www`). |
| *La petició supera la mida màxima permesa* | Desmarqueu «Inclou l'informe PDF» o reduïu l'abast de l'auditoria. |

## 8. Reconeixement passiu amb Shodan

[Shodan](https://www.shodan.io) rastreja Internet contínuament i desa el que respon cada adreça
pública (ports, banners, productes i versions). Consultar-lo és **reconeixement passiu**: les dades
ja són a Shodan, de manera que no s'envia cap paquet a la xarxa de l'objectiu i els tallafocs no
detecten res. Per això és la primera fase de l'auditoria, abans dels escanejos actius amb nmap.

### Clau de l'API

Amb l'API d'Argos configurada (`api_url` a `data/branding.json`) **no cal cap clau**: les consultes
es fan amb la clau de l'empresa a través del servidor d'Argos. Per fer servir una clau pròpia:

1. Creeu un compte a [account.shodan.io](https://account.shodan.io) i copieu-hi la clau de l'API.
2. Pestanya **Reconeixement passiu** → enganxeu la clau i premeu **Desa la clau**. Es desa a
   `~/.config/sentinelx/shodan.json` (Linux) o `%APPDATA%\SentinelX\shodan.json` (Windows), amb
   permisos `600`. També es pot fer servir la variable d'entorn `SHODAN_API_KEY`, que té prioritat.
3. **Comprova el pla** mostra el pla de la clau i els crèdits de consulta.

La clau no s'escriu mai al codi ni s'envia al portal: aquest repositori és públic.

### Funcions

| Funció | Què mostra | Pla gratuït |
|--------|-----------|-------------|
| Consulta d'host | IP, noms de domini, ports oberts, organització o ISP, ubicació, darrera actualització | Sí |
| Identificació de serveis | Producte i versió de cada port (o el banner, si Shodan no l'ha identificat) | Sí |
| Cerca de serveis | Primers 5 o 10 equips amb el producte: IP, port i organització o ISP | No: es mostra el resum per ports, organitzacions, països i productes |

**Afegeix a l'auditoria** passa l'equip consultat a la sessió: si nmap ja l'havia escanejat, només
s'hi afegeixen els ports que no hi eren. Els serveis queden amb l'estat `open (Shodan)`, es poden
correlacionar a **Vulnerabilitats i CVE**, es desen a l'expedient i, a l'informe, porten un asterisc
perquè es vegi que no s'han confirmat amb un escaneig actiu.

### Des del terminal

```bash
venv/bin/python3 shodan_recon.py
```

El menú té les mateixes funcions (consulta d'host, identificació de serveis, cerca i estat de la
clau) i fa servir el mateix mòdul (`core/shodan_intel.py`) que la pestanya.

### Missatges habituals

| Missatge | Causa i solució |
|----------|-----------------|
| *És una adreça privada o reservada* | Shodan només coneix adreces públiques. Per a la xarxa interna, feu servir l'Auditoria de Xarxa. |
| *Shodan no té informació d'aquesta IP* | Shodan no l'ha indexada o no hi ha trobat ports oberts. |
| *El pla de la clau de Shodan no permet aquesta consulta* | La cerca amb resultats necessita crèdits de consulta (Shodan Membership o pla acadèmic). |
| *Falta la llibreria de Shodan* | Executeu `./install_dependencies.sh` o `venv/bin/pip install shodan`. |

## 9. Cerca OSINT amb The Harvester

[The Harvester](https://github.com/laramies/theHarvester) recull correus, subdominis, adreces IP i
noms associats a un domini a partir de fonts públiques (cercadors, certificats, DNS passiu...). És
recol·lecció d'informació (*information gathering*): no s'escaneja l'objectiu.

### Instal·lació

`./install_dependencies.sh` l'instal·la sol: amb apt si la distribució en té paquet (Kali) i, si no
(Ubuntu), la versió 4.11.1 des de GitHub a `sentinelx/tools/theHarvester` amb uv, que descarrega el
Python 3.14 que necessita l'eina, i crea l'enllaç `~/.local/bin/theHarvester` perquè l'ordre funcioni
des de qualsevol terminal (cal obrir-ne un de nou després d'instal·lar). Si ja és al PATH
(`theHarvester`), es fa servir aquest.

### Ús

- **Pestanya OSINT**: domini objectiu, font de dades (google, bing, linkedin o all) i, si es vol,
  fitxer de resultats. La pestanya mostra la comanda abans d'executar-la, la sortida en temps real i
  un resum de correus, hosts i IP.
- **Terminal**: opció 5 de `venv/bin/python3 shodan_recon.py`, amb les mateixes preguntes.

Totes dues construeixen la comanda i la llancen amb `subprocess`:

```bash
theHarvester -d iesebre.cat -b all -l 500 -f resultats
```

- `-f` desa els resultats en **XML i JSON** (`resultats.xml` i `resultats.json`). Les versions 4.x de
  The Harvester ja no generen HTML.
- **google** i **bing** s'han retirat de The Harvester (la 4.11.1 no les té): SentinelX ho avisa i
  proposa **all** (totes les fonts) o **linkedin**. Algunes fonts de «all» necessiten claus d'API
  (`~/.theHarvester/api-keys.yaml`); sense clau, The Harvester se les salta.

## 10. Assistent d'IA (Google Gemini)

SentinelX pot fer servir [Gemini](https://ai.google.dev) per fer les auditories entenedores per a
persones sense coneixements tècnics. Si Gemini està saturat, prova un model més lleuger, i a través de
l'API d'Argos, si Gemini no està disponible, respon la IA de Cloudflare (Gemma 4). L'informe i les
explicacions indiquen quina IA ha redactat el text.

- **Informe senzill per a l'empresa** (pestanya Informes): PDF per a la direcció amb el nivell de risc,
  un resum, els riscos principals explicats sense tecnicismes (què passa, què podria passar, urgència i
  què cal fer), recomanacions i glossari.
- **Explica amb IA** (pestanya Vulnerabilitats i CVE, o doble clic sobre una troballa): què és, quin
  risc té per a l'empresa i què cal fer.
- **Traducció al català** de les descripcions de la NVD i dels scripts NSE. Sense IA, les de la NVD es
  mostren en castellà quan n'hi ha traducció.

### Configuració

**No cal cap clau** si SentinelX té configurada l'**API d'Argos** (camp `api_url` de
[data/branding.json](data/branding.json), vegeu [`argos-api/`](../argos-api/README.md)): les consultes
de Gemini i de Shodan es fan a través del servidor d'Argos, amb les claus de l'empresa. Una clau
pròpia només cal si es vol fer servir la de l'usuari:

1. Creeu una clau a [aistudio.google.com/apikey](https://aistudio.google.com/apikey). Si Google respon
   que el pla gratuït no està disponible per al projecte, cal activar-hi la facturació
   ([aistudio.google.com/billing](https://aistudio.google.com/billing)) o fer servir un altre projecte.
2. Pestanya **Informes** → apartat «Informe senzill per a l'empresa» → enganxeu la clau, **Desa** i
   **Comprova**. Es desa a `~/.config/sentinelx/ia.json` (permisos `600`); la variable d'entorn
   `GEMINI_API_KEY` té prioritat. El model per defecte és `gemini-flash-latest`.

### Privacitat

Les dades de l'auditoria s'envien a Google. Amb l'opció **Amaga les IP i els noms dels equips**
(activada per defecte), SentinelX hi envia àlies («Equip 1», «la xarxa auditada») i torna a posar les
dades reals a la resposta. Els textos de la IA s'han de revisar abans d'entregar-los al client: l'informe
i les explicacions ho indiquen.
