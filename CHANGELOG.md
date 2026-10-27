# Registre de canvis - SentinelX Audit Suite

Les versions segueixen el format `MAJOR.MENOR.CORRECCIÓ`:

- **MAJOR**: canvis importants en la manera de treballar (p. ex. una integració nova).
- **MENOR**: funcionalitats noves compatibles amb les anteriors.
- **CORRECCIÓ**: errors corregits sense funcionalitats noves.

Cada versió es publica a GitHub Releases amb l'etiqueta `vX.Y.Z`, que ha de coincidir amb el camp
`version` de [`sentinelx/data/branding.json`](sentinelx/data/branding.json).

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
