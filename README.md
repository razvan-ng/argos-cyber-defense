<p align="center">
  <img src="sentinelx/data/logo/argos-logo-horitzontal_1200px.png" alt="Argos Cyber Defense" width="360">
</p>

<p align="center">
  <strong>Detectem, analitzem i prevenim les vulnerabilitats de la vostra infraestructura.</strong>
</p>

<p align="center">
  <a href="https://creativecommons.org/licenses/by-nc-sa/4.0/deed.ca"><img alt="Llicència: CC BY-NC-SA 4.0" src="https://img.shields.io/badge/llic%C3%A8ncia-CC%20BY--NC--SA%204.0-16B4D2?style=flat-square"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-0B1F3A?style=flat-square">
  <img alt="Projecte ASIX" src="https://img.shields.io/badge/projecte-2n%20ASIX%20%C2%B7%20ciberseguretat-14335C?style=flat-square">
  <a href="https://argoscyberdefense.tech"><img alt="Web: argoscyberdefense.tech" src="https://img.shields.io/badge/web-argoscyberdefense.tech-16B4D2?style=flat-square"></a>
</p>

---

# Argos Cyber Defense · SentinelX Audit Suite

Repositori del **projecte intermodular de 2n curs** del Cicle Formatiu de Grau Superior
d'Administració de Sistemes Informàtics en Xarxa (**ASIX**), perfil professional de
**ciberseguretat**, a l'Institut de l'Ebre (Tortosa).

Conté **SentinelX Audit Suite**, l'aplicació d'auditoria de seguretat desenvolupada per
Argos Cyber Defense (carpeta [`sentinelx/`](sentinelx/)).

La web corporativa i l'**Àrea de clients** són a **[argoscyberdefense.tech](https://argoscyberdefense.tech)**,
allotjades en un hosting propi amb PHP i MySQL. SentinelX hi publica els resultats de les
auditories mitjançant una API perquè cada client els consulti iniciant la sessió amb el seu compte.

> Argos Cyber Defense, S.L. és una empresa fictícia creada amb finalitats acadèmiques.

## Equip

| Integrant | Rol |
|-----------|-----|
| Razvan Nastasa Ghitau | Scrum Owner |
| Lluc Sarrà Masdeu | Scrum Master |
| Mouhammed Oualy | Scrum Manager |

## Descàrrega

La darrera versió empaquetada és a la pàgina de
**[Releases](https://github.com/razvan-ng/argos-cyber-defense/releases/latest)**:

- Enllaç directe: [`sentinelx-audit-suite.zip`](https://github.com/razvan-ng/argos-cyber-defense/releases/latest/download/sentinelx-audit-suite.zip)

## SentinelX Audit Suite

Aplicació d'escriptori en Python (CustomTkinter) per fer auditories de seguretat: descobriment
d'equips i serveis amb nmap, auditoria i reforçament del sistema local, correlació de
vulnerabilitats amb CVE (diccionari local, NVD API i scripts NSE), generació d'informes en
HTML, PDF, JSON i CSV i **publicació dels resultats a l'Àrea de clients** de la web.

Inici ràpid a Ubuntu 24.04 / 26.04 LTS:

```bash
unzip sentinelx-audit-suite.zip
cd sentinelx-audit-suite
chmod +x install_dependencies.sh
./install_dependencies.sh
source venv/bin/activate
python main.py
```

Des del codi font, substituïu les dues primeres ordres per `git clone` i `cd argos-cyber-defense/sentinelx`.

Tota la documentació és a [`sentinelx/README.md`](sentinelx/README.md) i
[`sentinelx/QUICKSTART.md`](sentinelx/QUICKSTART.md).

> **Avís legal i ètic:** SentinelX s'ha d'utilitzar exclusivament sobre xarxes i sistemes per
> als quals es disposi d'autorització expressa i per escrit. L'ús no autoritzat sobre sistemes
> de tercers pot constituir un delicte.

## Publicació de resultats a l'Àrea de clients

Quan s'ha d'entregar el resultat d'una auditoria, SentinelX el publica directament a la web:

1. Un administrador del portal crea l'empresa client i els seus usuaris
   (Administració → Empreses / Usuaris) i genera un **token d'API** per a l'equip on s'executa
   SentinelX (Administració → Tokens d'API).
2. A SentinelX, pestanya **Informes → Publicar al Portal de Clients**: s'hi indica l'adreça
   del portal (`https://argoscyberdefense.tech`) i el token, es tria l'empresa i es publica.
3. L'informe arriba com a **esborrany**. L'equip d'Argos el revisa (validació i eliminació de
   falsos positius) i el publica.
4. El client inicia la sessió a l'**Àrea de clients** i consulta l'informe en línia o el
   descarrega en PDF, CSV o JSON.

La comunicació es fa sempre per HTTPS, el token es desa al servidor en forma de resum
SHA-256 i cada client només pot veure els informes publicats de la seva empresa.

## Estructura del repositori

```
.
├── sentinelx/                  # Codi font de l'aplicació SentinelX (Python)
├── .github/workflows/
│   └── release.yml             # Empaqueta SentinelX i crea una release a cada etiqueta vX.Y.Z
├── index.html, 404.html        # Redirecció de l'antiga adreça de GitHub Pages a argoscyberdefense.tech
├── LICENSE                     # Text legal de la llicència CC BY-NC-SA 4.0
└── README.md
```

## Publicar una versió nova

1. Actualitzeu el número de versió a [`sentinelx/data/branding.json`](sentinelx/data/branding.json).
2. Pugeu els canvis i creeu l'etiqueta de la versió:

   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```

3. GitHub Actions empaqueta SentinelX i crea la release automàticament amb els fitxers
   `sentinelx-audit-suite-1.1.0.zip` i `sentinelx-audit-suite.zip` (el que enllaça la web).

## Llicència

<a rel="license" href="https://creativecommons.org/licenses/by-nc-sa/4.0/deed.ca"><img alt="Llicència de Creative Commons" src="https://licensebuttons.net/l/by-nc-sa/4.0/88x31.png"></a>

© 2026 Razvan Nastasa Ghitau, Lluc Sarrà Masdeu i Mouhammed Oualy.

Aquest repositori (aplicació SentinelX, logotips i documentació) està subjecte a una
llicència [Creative Commons Reconeixement-NoComercial-CompartirIgual 4.0 Internacional
(CC BY-NC-SA 4.0)](https://creativecommons.org/licenses/by-nc-sa/4.0/deed.ca). Podeu
compartir-lo i adaptar-lo sempre que:

- **Reconeixement (BY):** en citeu els autors i indiqueu si hi heu fet canvis.
- **NoComercial (NC):** no el feu servir amb finalitats comercials.
- **CompartirIgual (SA):** distribuïu les obres derivades amb aquesta mateixa llicència.

El text legal complet és al fitxer [`LICENSE`](LICENSE).
