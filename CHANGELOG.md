# Registre de canvis - SentinelX Audit Suite

Les versions segueixen el format `MAJOR.MENOR.CORRECCIÓ`:

- **MAJOR**: canvis importants en la manera de treballar (p. ex. una integració nova).
- **MENOR**: funcionalitats noves compatibles amb les anteriors.
- **CORRECCIÓ**: errors corregits sense funcionalitats noves.

Cada versió es publica a GitHub Releases amb l'etiqueta `vX.Y.Z`, que ha de coincidir amb el camp
`version` de [`sentinelx/data/branding.json`](sentinelx/data/branding.json).

## [2.7.3] - 2026-11

### Corregit
- **No es podia iniciar la sessió al portal des de la pestanya Expedients**: el portal acceptava
  l'usuari, però el diàleg es tancava abans de llegir el correu i la sessió no arribava a desar-se.
  Ara, després d'iniciar la sessió, es carreguen les empreses i els expedients.

### Canviat
- La web ja no és a InfinityFree sinó en un servidor propi a Azure darrere de Cloudflare, de manera
  que SentinelX s'hi connecta directament. El mode fitxer queda per als equips que no poden connectar
  amb el portal, i s'han tret les referències a l'allotjament antic.
- La detecció de pàgines de verificació antirobots reconeix les de Cloudflare.

## [2.7.2] - 2026-11

### Corregit
- Els missatges d'estat llargs de les pestanyes Auditoria de Xarxa, OSINT i Reconeixement passiu
  eixamplaven tota la finestra; ara salten de línia.

## [2.7.1] - 2026-11

### Canviat
- L'script `escaneig.py` també mostra el resum de vulnerabilitats per servei al final de la
  modalitat 4 (el mateix que la pestanya), perquè la llista de `vulners` és molt llarga.

## [2.7.0] - 2026-11

### Afegit
- **Escaneig amb Nmap per modalitats** a la pestanya Auditoria de Xarxa, a partir de l'script
  `escaneig.py` de Mouhammed Oualy (llibreria python-nmap):
  1. Descobriment d'hosts actius (`-sn`).
  2. Ports oberts d'un host o rang de hosts (`--open`).
  3. Serveis i versions d'un port, un rang de ports o tots els ports (`-sV`).
  4. Vulnerabilitats conegudes amb els scripts NSE de la categoria «vuln», incloent-hi els CVE que
     llista l'script `vulners` per a cada versió (amb la puntuació CVSS i la gravetat).
- Script de terminal `sentinelx/escaneig.py` amb el menú original de les quatre modalitats.
- Nova dependència de Python: `python-nmap`.

### Canviat
- Els resultats d'un escaneig es combinen amb la sessió port per port: escanejar uns quants ports
  ja no esborra els serveis ni les versions dels altres.
- Es validen l'objectiu i els ports abans d'executar nmap (no s'hi poden colar opcions de nmap).
- La modalitat 4, tots els ports i l'UDP demanen confirmació amb el Mode Segur activat.

## [2.6.0] - 2026-11

### Afegit
- **IA de Cloudflare com a reserva gratuïta** a l'API d'Argos: si Gemini està saturat o no està
  disponible, respon Workers AI (Gemma 4 i, si cal, Llama 3.3 70B) amb la quota diària gratuïta.
- L'informe per a l'empresa i les explicacions indiquen quina IA ha redactat el text.

### Canviat
- Models de Gemini actualitzats a `gemini-3.5-flash` (els 2.5 ja no estan disponibles per a comptes
  nous), amb `gemini-3.5-flash-lite` quan el principal està saturat.
- Les traduccions es fan en lots de 5 descripcions i l'espera màxima passa a 180 segons.

### Corregit
- Les respostes de la IA amb text o blocs de codi al voltant del JSON ja no donen error.

## [2.5.0] - 2026-11

### Afegit
- **API d'Argos** (`argos-api/`, Cloudflare Workers): guarda les claus de Gemini i de Shodan de
  l'empresa com a secrets i fa les consultes en nom de SentinelX. Els usuaris **ja no han de posar cap
  clau**: si no en tenen de pròpia, l'assistent d'IA i el reconeixement amb Shodan passen per
  `https://argos-api.argos-api.workers.dev` (camp `api_url` de `data/branding.json` o variable
  `ARGOS_API_URL`). Només admet les peticions de SentinelX, amb un màxim de consultes per minut i
  ordinador.

### Canviat
- Les claus pròpies de Gemini i de Shodan passen a ser opcionals: si l'usuari en desa una, es fa
  servir la seva en lloc de la de l'API d'Argos.

## [2.4.0] - 2026-11

### Afegit
- **Assistent d'IA (Google Gemini)**, configurable a la pestanya Informes (la clau es desa al perfil de
  l'usuari, `ia.json` amb permisos 600, o a la variable d'entorn `GEMINI_API_KEY`):
  - **Informe senzill per a l'empresa** (PDF): nivell de risc, resum per a la direcció, riscos
    principals explicats sense tecnicismes amb la urgència i què cal fer, recomanacions i glossari.
  - **Explica amb IA** (o doble clic) a la pestanya Vulnerabilitats i CVE: què és la troballa, quin
    risc té per a l'empresa i què cal fer, en llenguatge senzill.
  - **Traducció al català** de les descripcions que arriben en anglès o castellà (NVD i scripts NSE).
  - Opció (activada per defecte) per amagar les IP i els noms dels equips abans d'enviar les dades a
    Google: s'envien àlies («Equip 1») i es tornen a posar a la resposta.

### Canviat
- Les descripcions de la NVD es mostren en castellà quan la NVD en té la traducció, en lloc de
  l'anglès. Les dels scripts NSE porten l'explicació en català.
- Si un CVE ja és al diccionari local, no es torna a afegir des de la NVD (sortia repetit).

### Corregit
- La finestra de comprovació d'eines que surt en obrir SentinelX tallava els botons «Tornar a
  comprovar» i «Continuar» (mida fixa de 600×480). Ara els botons sempre es veuen, la finestra és
  més gran i es pot redimensionar.
- La barra de progrés de la pestanya Vulnerabilitats ja no queda mig pintada en repòs.

## [2.3.3] - 2026-11

### Corregit
- Pestanya OSINT: la comanda ocupa tota l'amplada i es veu sencera encara que la ruta del fitxer de
  resultats sigui llarga, i el resum ja no canvia d'amplada en acabar la cerca.

## [2.3.2] - 2026-11

### Canviat
- Quan `install_dependencies.sh` instal·la The Harvester a `sentinelx/tools/`, crea l'enllaç
  `~/.local/bin/theHarvester` (Ubuntu ja té aquesta carpeta al PATH), perquè l'ordre `theHarvester`
  funcioni des de qualsevol terminal i les comandes que mostra SentinelX siguin les de l'enunciat.

## [2.3.1] - 2026-11

### Afegit
- Pestanya **OSINT** a l'aplicació: cerca amb The Harvester amb el domini, la font de dades (google,
  bing, linkedin o all) i, si es vol, el fitxer de resultats (`-f`, en XML i JSON). Mostra la comanda
  abans d'executar-la, la sortida en temps real i un resum de correus, hosts i IP trobats.
- `install_dependencies.sh` instal·la The Harvester 4.11.1: amb apt si la distribució en té paquet
  (Kali) i, si no (Ubuntu), des de GitHub a `sentinelx/tools/theHarvester` amb uv. La pestanya Quant a
  i la comprovació d'eines inicial indiquen si està disponible.
- Mòdul comú `core/harvester.py` per a la pestanya i per a l'opció 5 de `shodan_recon.py`.

### Corregit
- L'opció 5 rebutjava les fonts «all» i «linkedin» amb The Harvester 4.11.1, perquè les buscava a
  l'ajuda de `theHarvester -h`, on no surten. Ara les fonts es consulten a la mateixa eina: «all» i
  «linkedin» funcionen, i «google» i «bing» (retirades de The Harvester) s'expliquen amb un avís.
- L'opció 5 també troba The Harvester quan no és al PATH (instal·lació de `install_dependencies.sh`).

## [2.3.0] - 2026-11

### Afegit
- Opció **5. Cerca OSINT amb The Harvester** al menú de l'script de terminal `sentinelx/shodan_recon.py`:
  demana el domini objectiu i la font de dades (google, bing, linkedin o all), construeix la comanda
  `theHarvester -d <domini> -b <font> -l 500` i la llança amb `subprocess`. Opcionalment desa els
  resultats en un fitxer (paràmetre `-f`). Cal tenir The Harvester instal·lat
  (https://github.com/laramies/theHarvester).
- Si la versió instal·lada de The Harvester no té la font triada, l'script ho avisa i torna a preguntar.

### Canviat
- L'script de terminal només demana la clau de Shodan quan es tria una opció de Shodan.

## [2.2.0] - 2026-11

### Afegit
- Pestanya **Reconeixement passiu** amb l'API de Shodan, per saber què hi ha exposat a Internet
  abans de llançar escanejos actius i sense enviar cap paquet a l'objectiu:
  - **Consulta d'host**: IP, noms de domini associats, ports oberts, organització o ISP,
    ubicació i data de la darrera actualització a Shodan.
  - **Identificació de serveis** (banner grabbing): producte i versió de cada port. Si Shodan no
    ha identificat el producte, es treu del banner (capçalera SSH o `Server:` d'HTTP).
  - **Cerca de serveis**: els primers 5 o 10 equips amb un producte o servei (IP, port i
    organització). Amb el pla gratuït de Shodan, que no permet la cerca, es mostra el resum
    agregat per ports, organitzacions, països i productes.
  - **Afegeix a l'auditoria**: l'equip consultat passa a la sessió (sense substituir els serveis
    trobats amb nmap) i es pot correlacionar amb CVE, comparar i publicar a l'expedient. A
    l'informe, els ports que només coneix Shodan surten marcats amb un asterisc.
- Script de terminal `sentinelx/shodan_recon.py` amb les mateixes funcions i un menú.
- La clau de l'API es desa al perfil de l'usuari (`shodan.json`, permisos 600) o es llegeix de
  la variable d'entorn `SHODAN_API_KEY`. No es guarda mai al codi ni a l'expedient.

### Canviat
- Nova dependència de Python: `shodan` (la llibreria oficial). Si actualitzeu una instal·lació
  existent, torneu a executar `./install_dependencies.sh` o `venv/bin/pip install shodan`.

- La consulta a la NVD només es fa quan es coneix la versió del servei: amb només el nom
  (p. ex. «ssh») retornava CVE antics que no tenien res a veure amb el servei.

### Corregit
- La barra de progrés de l'Auditoria de Xarxa ja no queda mig pintada quan no hi ha cap
  escaneig en curs.

## [2.1.0] - 2026-10

### Afegit
- Inici de sessió al portal amb **verificació en dos passos**: si l'administrador té el 2FA
  activat a la web, la finestra d'inici de sessió demana el codi de l'aplicació d'autenticació
  (o un codi de recuperació). Sense el codi, el portal no obre la sessió.

### Canviat
- Les notícies de la web es recullen ara amb GitHub Actions (workflow «Notícies de la web») i es
  publiquen a la branca `noticies` del repositori, perquè l'allotjament de la web no pot
  connectar amb les fonts externes.

## [2.0.1] - 2026-10

### Corregit
- La connexió amb el portal fallava amb l'error «unable to get local issuer certificate» quan
  el servidor envia el certificat SSL sense el certificat intermedi.
  SentinelX porta ara els certificats intermedis públics de Let's Encrypt
  (`sentinelx/data/certs`) i completa la cadena pel seu compte. La verificació HTTPS continua
  activa: la cadena ha d'acabar en una arrel de confiança i el certificat ha de ser del domini.
- Missatge més clar quan no es pot verificar el certificat del portal (certificat no instal·lat
  o xarxa que inspecciona el trànsit HTTPS).

## [2.0.0] - 2026-10

Integració completa amb la web i l'Àrea de clients d'Argos Cyber Defense.

### Afegit
- Pestanya **Expedients**: inici de sessió amb l'usuari administrador de la web, llista
  d'empreses i expedients, creació d'expedients i expedient actiu.
- **Reauditories**: en obrir un expedient amb auditories, la darrera es fa servir com a
  referència i la comparació mostra les vulnerabilitats resoltes, noves, pendents i no verificades.
- **Desament automàtic** dels resultats a l'expedient (esborrany que s'actualitza cada minut si hi
  ha canvis) i publicació per al client amb l'informe PDF.
- **Mode fitxer** per quan no es pot connectar directament amb el portal: obrir el
  fitxer d'expedient descarregat de la web i exportar l'auditoria per pujar-la.
- Detecció dels allotjaments que bloquegen les aplicacions, amb un missatge clar.
- Avís de **versions noves** publicades a GitHub (a l'inici i a la pestanya Quant a).
- L'exportació JSON inclou el traçat de ruta, la referència de cada CVE i el pla de millora.

### Canviat
- La comparació amb una auditoria anterior (baseline) ara també mostra les vulnerabilitats
  resoltes, els ports tancats i els canvis en el reforçament del sistema.
- La pestanya Informes porta directament a l'expedient per desar o publicar l'auditoria.

## [1.0.0] · 2026-09

Primera versió.

- Tauler amb el resum de l'auditoria, la llista «Què cal arreglar primer?» i el Mode Segur.
- Auditoria de xarxa amb nmap (descobriment, ports, serveis, versions, SO, UDP) i traçat de rutes.
- Auditoria del sistema local i reforçament (actualitzacions, SUID/SGID, comptes de risc).
- Correlació de vulnerabilitats amb CVE (diccionari local, NVD API, Exploit-DB i scripts NSE).
- Informes en HTML, PDF, JSON i CSV.
- Sessions d'auditoria i comparació amb una auditoria anterior.
