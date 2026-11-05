# API d'Argos

Intermediari (Cloudflare Worker) perquè SentinelX pugui fer servir **Gemini** (assistent d'IA) i
**Shodan** (reconeixement passiu) sense que l'usuari hagi de posar cap clau. Les claus de l'empresa
es guarden com a **secrets de Cloudflare**: no són al codi ni surten mai del servidor.

```
SentinelX ──► API d'Argos (Cloudflare Workers, amb les claus) ──► Gemini / Shodan
```

| Ruta | Què fa |
|------|--------|
| `GET /v1/estat` | Indica si la IA i Shodan estan configurats |
| `POST /v1/gemini` | Envia la petició a Gemini (només els models `gemini-flash-latest`, `gemini-flash-lite-latest`, `gemini-2.5-flash` i `gemini-2.5-flash-lite`) |
| `POST /v1/shodan` | Consulta d'host, cerca, recompte o estat del pla de Shodan |

**Protecció.** Només s'accepten peticions de SentinelX, els models i les accions de la llista, i
peticions de menys de 200 KB. Cada ordinador (adreça IP) pot fer com a màxim 8 consultes d'IA i 20
de Shodan per minut. No es desa cap dada de les peticions. Per controlar la despesa, poseu també un
límit de pressupost al projecte de Google de la clau de Gemini.

## Publicar-la

Cal un compte gratuït de Cloudflare i Node.js:

```bash
cd argos-api
npm install
npx wrangler login                      # obre el navegador per autoritzar el compte
npx wrangler secret put GEMINI_API_KEY  # enganxeu la clau de Gemini de l'empresa
npx wrangler secret put SHODAN_API_KEY  # enganxeu la clau de Shodan de l'empresa
npx wrangler deploy
```

`wrangler deploy` mostra l'adreça (`https://argos-api.<compte>.workers.dev`), que s'ha de posar a
`sentinelx/data/branding.json` (camp `api_url`). Per provar-la en local, poseu les claus a
`argos-api/.dev.vars` (fitxer ignorat per git) i executeu `npx wrangler dev`.
