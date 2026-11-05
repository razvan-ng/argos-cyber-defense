/**
 * API d'Argos: intermediari perquè SentinelX faci servir Gemini i Shodan sense que l'usuari
 * hagi de posar cap clau. Les claus (GEMINI_API_KEY i SHODAN_API_KEY) són secrets de Cloudflare
 * i no surten mai d'aquí: SentinelX envia la petició, aquest Worker hi afegeix la clau, la fa al
 * servei i retorna la resposta tal qual.
 *
 * Rutes (totes en JSON):
 *   GET  /v1/estat    quins serveis estan configurats
 *   POST /v1/gemini   { model, systemInstruction, contents, generationConfig } -> resposta de Gemini
 *   POST /v1/shodan   { accio: "host" | "search" | "count" | "info", ip, query, facets } -> resposta de Shodan
 *
 * Protecció: només s'admeten els models i les accions de SentinelX, la mida de les peticions és
 * limitada i cada ordinador té un màxim de consultes per minut. No es desa cap dada de les peticions.
 */
const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/";
const GEMINI_MODELS = new Set(["gemini-flash-latest", "gemini-flash-lite-latest", "gemini-2.5-flash", "gemini-2.5-flash-lite"]);
const DEFAULT_MODEL = "gemini-flash-latest";
const MAX_OUTPUT_TOKENS = 8192;
const SHODAN_URL = "https://api.shodan.io";
const MAX_BODY = 200_000;
const IP_RE = /^(\d{1,3}(\.\d{1,3}){3}|[0-9a-fA-F:]{2,39})$/;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/v1/estat" && request.method === "GET") {
        return json(200, { ok: true, versio: 1, gemini: Boolean(env.GEMINI_API_KEY), shodan: Boolean(env.SHODAN_API_KEY) });
      }
      if (request.headers.get("X-Argos-Client") !== "sentinelx") {
        return argosError(403, "Aquesta API només la pot fer servir SentinelX.");
      }
      if (request.method !== "POST") return argosError(405, "Mètode no permès.");
      if (url.pathname === "/v1/gemini") return await gemini(request, env);
      if (url.pathname === "/v1/shodan") return await shodan(request, env);
      return argosError(404, "Aquesta ruta no existeix.");
    } catch (error) {
      return argosError(500, "Error intern de l'API d'Argos. Torneu-ho a provar d'aquí a una estona.");
    }
  },
};

async function gemini(request, env) {
  if (!env.GEMINI_API_KEY) return argosError(503, "L'API d'Argos encara no té configurada la IA.");
  if (!(await allowed(env.LIMIT_IA, request))) {
    return argosError(429, "L'API d'Argos limita les consultes d'IA a 8 per minut i ordinador. Espereu un minut.");
  }
  const body = await readJson(request);
  if (!body || !Array.isArray(body.contents)) return argosError(400, "Petició d'IA no vàlida.");
  const model = GEMINI_MODELS.has(body.model) ? body.model : DEFAULT_MODEL;
  const generationConfig = { ...(body.generationConfig || {}) };
  generationConfig.maxOutputTokens = Math.min(Number(generationConfig.maxOutputTokens) || MAX_OUTPUT_TOKENS, MAX_OUTPUT_TOKENS);
  const upstream = await fetch(`${GEMINI_URL}${model}:generateContent`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": env.GEMINI_API_KEY },
    body: JSON.stringify({ systemInstruction: body.systemInstruction, contents: body.contents, generationConfig }),
  });
  return passThrough(upstream);
}

async function shodan(request, env) {
  if (!env.SHODAN_API_KEY) return argosError(503, "L'API d'Argos encara no té configurat Shodan.");
  if (!(await allowed(env.LIMIT_SHODAN, request))) {
    return argosError(429, "L'API d'Argos limita les consultes de Shodan a 20 per minut i ordinador. Espereu un minut.");
  }
  const body = await readJson(request);
  if (!body) return argosError(400, "Petició de Shodan no vàlida.");
  const params = new URLSearchParams({ key: env.SHODAN_API_KEY });
  let path;
  if (body.accio === "host") {
    if (!IP_RE.test(String(body.ip || ""))) return argosError(400, "Adreça IP no vàlida.");
    path = `/shodan/host/${encodeURIComponent(body.ip)}`;
  } else if (body.accio === "search" || body.accio === "count") {
    const query = String(body.query || "").trim().slice(0, 200);
    if (!query) return argosError(400, "Falta el servei o producte a cercar.");
    params.set("query", query);
    if (body.facets) params.set("facets", String(body.facets).slice(0, 200));
    if (body.accio === "search") params.set("minify", "true");
    path = `/shodan/host/${body.accio}`;
  } else if (body.accio === "info") {
    path = "/api-info";
  } else {
    return argosError(400, "Acció de Shodan no permesa.");
  }
  const upstream = await fetch(`${SHODAN_URL}${path}?${params}`, { headers: { "User-Agent": "argos-api" } });
  return passThrough(upstream);
}

async function allowed(limiter, request) {
  if (!limiter) return true; // sense el límit configurat (p. ex. en proves locals), no es limita
  const key = request.headers.get("CF-Connecting-IP") || "local";
  const { success } = await limiter.limit({ key });
  return success;
}

async function readJson(request) {
  const text = await request.text();
  if (text.length > MAX_BODY) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function passThrough(upstream) {
  // La resposta del servei es retorna tal qual (sense capçaleres que puguin revelar res)
  return new Response(await upstream.text(), {
    status: upstream.status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function json(status, data) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store" },
  });
}

function argosError(status, message) {
  // «argos: true» indica a SentinelX que el missatge és de l'API d'Argos i ja és en català
  return json(status, { error: { message, argos: true } });
}
