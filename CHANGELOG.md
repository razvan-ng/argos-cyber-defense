# Registre de canvis - SentinelX Audit Suite

Les versions segueixen el format `MAJOR.MENOR.CORRECCIÓ`:

- **MAJOR**: canvis importants en la manera de treballar (p. ex. una integració nova).
- **MENOR**: funcionalitats noves compatibles amb les anteriors.
- **CORRECCIÓ**: errors corregits sense funcionalitats noves.

Cada versió es publica a GitHub Releases amb l'etiqueta `vX.Y.Z`, que ha de coincidir amb el camp
`version` de [`sentinelx/data/branding.json`](sentinelx/data/branding.json).

## [2.3.0] - 2026-11

### Afegit
- Opció **5. Cerca OSINT amb The Harvester** al menú de l'script de terminal `sentinelx/shodan_recon.py`:
  demana el domini objectiu i la font de dades (google, bing, linkedin o all), construeix la comanda
  `theHarvester -d <domini> -b <font> -l 500` i la llança amb `subprocess`. Opcionalment desa els
  resultats en un fitxer (paràmetre `-f`). Cal tenir The Harvester instal·lat
  (https://github.com/laramies/theHarvester).
- Si la versió instal·lada de The Harvester no té la font triada (la 5.0.0 ja no inclou google, bing
  ni linkedin), l'script ho avisa i torna a preguntar.

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
  l'allotjament (com InfinityFree) envia el certificat SSL sense el certificat intermedi.
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
- **Mode fitxer** per a allotjaments que no permeten la connexió directa (InfinityFree): obrir el
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
