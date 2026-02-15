import express from "express";
import cors from "cors";
import multer from "multer";
import { MeiliSearch } from "meilisearch";
import { parse } from "csv-parse/sync";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));

// CORS (front Pressero)
app.use(cors({
  origin: ["https://decoration.ams.v6.pressero.com"],
  methods: ["GET", "POST"]
}));

const upload = multer({ storage: multer.memoryStorage() });

const {
  PORT = 3000,

  // Meilisearch
  MEILI_HOST,
  MEILI_KEY,
  INDEX_NAME = "products",
  BASE_URL = "https://decoration.ams.v6.pressero.com",

  // Admin UI protection (simple)
  ADMIN_UI_KEY, // ex: "mysecret"
  // Pressero admin auth
  PRESSERO_ADMIN_BASE = "https://admin.ams.v6.pressero.com",
  PRESSERO_AUTH_PATH = "/api/V2/Authentication",
  PRESSERO_USER = "admin",
  PRESSERO_PASS = "admin",
  PRESSERO_SUBSCRIBER_ID = "00000000-0000-0000-0000-000000000000",
  PRESSERO_CONSUMER_ID = "00000000-0000-0000-0000-000000000000",
  PRESSERO_SITE_DOMAIN = "decoration.ams.v6.pressero.com",

  // Cache
  GROUP_CACHE_TTL_MS = "600000",
  TOKEN_REFRESH_SAFETY_MS = "60000"
} = process.env;

if (!MEILI_HOST || !MEILI_KEY) console.error("Missing MEILI_HOST / MEILI_KEY");

const meili = new MeiliSearch({ host: MEILI_HOST, apiKey: MEILI_KEY });
const index = meili.index(INDEX_NAME);

// ---------------- Helpers: Product parsing ----------------
function normBool(v) {
  const s = String(v ?? "").trim().toLowerCase();
  return s === "vrai" || s === "true" || s === "1" || s === "yes";
}

function stripHtml(html) {
  let s = String(html ?? "");
  s = s.replace(/<script[\s\S]*?<\/script>/gi, " ");
  s = s.replace(/<style[\s\S]*?<\/style>/gi, " ");
  s = s.replace(/<[^>]+>/g, " ");
  s = s.replace(/\s+/g, " ").trim();
  return s;
}

function buildProductDoc(row) {
  const id = String(row["Product Id"] ?? "").trim();
  const name = String(row["Product Name"] ?? "").trim();
  const slug = String(row["Url Name"] ?? "").trim();
  const active = normBool(row["Active"]);

  const shortDesc = stripHtml(row["Short Description"]);
  const longDesc = stripHtml(row["Long Description"]);
  const image = String(row["Primary Image URL"] ?? "").trim();

  // ✅ Doit contenir les GroupName exacts (ex: "Tout le monde")
  const siteGroups = [
    row["Site Group 1"],
    row["Site Group 2"],
    row["Site Group 3"],
    row["Site Group 4"],
    row["Site Group 5"]
  ].map(x => String(x ?? "").trim()).filter(Boolean);

  const partNumber = String(row["Part Number"] ?? "").trim();
  const publicPartNum = String(row["Public Part Num"] ?? "").trim();

  const url = slug ? `${BASE_URL}/product/${encodeURIComponent(slug)}` : "";

  return {
    id, name, slug, url,
    active,
    shortDesc, longDesc,
    image,
    siteGroups,
    partNumber,
    publicPartNum
  };
}

async function ensureIndexSettings() {
  await index.updateSettings({
    searchableAttributes: ["name", "shortDesc", "longDesc", "slug", "partNumber", "publicPartNum"],
    filterableAttributes: ["active", "siteGroups"],
    rankingRules: ["words", "typo", "proximity", "attribute", "sort", "exactness"],
    synonyms: {
      "signaletique": ["signalétique", "enseigne", "panneau", "plv"],
      "signalétique": ["signaletique", "enseigne", "panneau", "plv"],
      "adhesif": ["adhésif", "sticker", "vinyle", "autocollant"],
      "adhésif": ["adhesif", "sticker", "vinyle", "autocollant"],
      "rollup": ["kakemono"],
      "kakemono": ["rollup"]
    }
  });
}

// ---------------- Pressero token auth (V2/Authentication) ----------------
let presseroToken = null;
let presseroTokenExp = 0;

async function presseroAuthenticate() {
  const url = `${PRESSERO_ADMIN_BASE}${PRESSERO_AUTH_PATH}`;
  const payload = {
    UserName: PRESSERO_USER,
    Password: PRESSERO_PASS,
    SubscriberId: PRESSERO_SUBSCRIBER_ID,
    ConsumerID: PRESSERO_CONSUMER_ID
  };

  const resp = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify(payload)
  });

  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    throw new Error(`Auth failed ${resp.status}: ${txt.slice(0, 300)}`);
  }

  const data = await resp.json();

  // ⚠️ Format exact dépend de Pressero: parfois { Token, ExpirationUtc } ou { AccessToken, ExpiresIn }
  // On gère plusieurs formats.
  const token =
    data?.Token || data?.token || data?.AccessToken || data?.access_token || data?.Jwt || data?.jwt;

  // expiration
  let expMs = 0;
  if (data?.ExpirationUtc) expMs = Date.parse(data.ExpirationUtc);
  if (!expMs && data?.ExpiresUtc) expMs = Date.parse(data.ExpiresUtc);
  if (!expMs && data?.expires_in) expMs = Date.now() + Number(data.expires_in) * 1000;
  if (!expMs) expMs = Date.now() + 30 * 60 * 1000; // fallback 30 min

  if (!token) throw new Error("Auth response missing token field");

  presseroToken = token;
  presseroTokenExp = expMs;
  return token;
}

async function getPresseroToken() {
  const safety = Number(TOKEN_REFRESH_SAFETY_MS);
  if (presseroToken && (presseroTokenExp - safety) > Date.now()) return presseroToken;
  return await presseroAuthenticate();
}

async function presseroFetchJson(url) {
  const token = await getPresseroToken();
  const resp = await fetch(url, {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/json"
    }
  });
  if (!resp.ok) {
    const txt = await resp.text().catch(() => "");
    // si token expiré / 401, on retente une fois
    if (resp.status === 401) {
      presseroToken = null;
      const token2 = await getPresseroToken();
      const resp2 = await fetch(url, {
        headers: { "Authorization": `Bearer ${token2}`, "Accept": "application/json" }
      });
      if (!resp2.ok) {
        const txt2 = await resp2.text().catch(() => "");
        throw new Error(`Pressero API ${resp2.status}: ${txt2.slice(0, 300)}`);
      }
      return await resp2.json();
    }
    throw new Error(`Pressero API ${resp.status}: ${txt.slice(0, 300)}`);
  }
  return await resp.json();
}

// ---------------- Groups cache (email -> groups) ----------------
const ttlMs = Number(GROUP_CACHE_TTL_MS);
const groupCache = new Map();

async function getUserIdByEmail(email) {
  const u = new URL(`${PRESSERO_ADMIN_BASE}/api/site/${PRESSERO_SITE_DOMAIN}/users/`);
  u.searchParams.set("pageNumber", "0");
  u.searchParams.set("pageSize", "1");
  u.searchParams.set("email", email);
  u.searchParams.set("includeDeleted", "false");

  const data = await presseroFetchJson(u.toString());
  return data?.Items?.[0]?.UserId || null;
}

async function getGroupsByUserId(userId) {
  const url = `${PRESSERO_ADMIN_BASE}/api/site/${PRESSERO_SITE_DOMAIN}/users/${encodeURIComponent(userId)}`;
  const data = await presseroFetchJson(url);
  return (data?.Groups || []).map(g => String(g?.GroupName || "").trim()).filter(Boolean);
}

async function getGroupsForEmail(email) {
  const key = String(email || "").trim().toLowerCase();
  if (!key) return [];

  const cached = groupCache.get(key);
  if (cached && cached.exp > Date.now()) return cached.groups;

  const userId = await getUserIdByEmail(key);
  if (!userId) {
    groupCache.set(key, { groups: [], exp: Date.now() + ttlMs });
    return [];
  }

  const groups = await getGroupsByUserId(userId);
  groupCache.set(key, { groups, exp: Date.now() + ttlMs });
  return groups;
}

function buildMeiliGroupFilter(groups) {
  const esc = (s) => String(s).replace(/"/g, '\\"');
  if (!groups?.length) return null;
  return "(" + groups.map(g => `siteGroups = "${esc(g)}"`).join(" OR ") + ")";
}

// ---------------- Admin UI auth (simple) ----------------
// Use: /admin?key=XXXX
function requireAdminUi(req, res, next) {
  if (!ADMIN_UI_KEY) return next(); // if not set, no protection (dev only)
  const key = String(req.query.key || "");
  if (key !== ADMIN_UI_KEY) return res.status(401).send("Unauthorized");
  next();
}

// Serve admin page
app.get("/admin", requireAdminUi, (req, res) => {
  const html = fs.readFileSync(path.join(__dirname, "views", "admin.html"), "utf8");
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  res.send(html);
});

// accepte: /admin/reindex  /admin/reindex-ui  /reindex
app.post(["/admin/reindex", "/admin/reindex-ui", "/reindex"], requireAdminUi, upload.single("file"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: "Missing file" });

    const csvText = req.file.buffer.toString("utf8");
    const records = parse(csvText, {
      columns: true,
      skip_empty_lines: true,
      relax_quotes: true,
      relax_column_count: true,
      bom: true
    });

    const docs = [];
    for (const r of records) {
      const doc = buildProductDoc(r);
      if (!doc.id || !doc.name || !doc.slug) continue;
      docs.push(doc);
    }

    await ensureIndexSettings();
    const task = await index.addDocuments(docs, { primaryKey: "id" });

    return res.json({ ok: true, indexed: docs.length, taskUid: task.taskUid });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Reindex failed", detail: String(e?.message || e) });
  }
});


// Public search endpoint
app.get("/api/search", async (req, res) => {
  try {
    const q = String(req.query.q ?? "").trim();
    const limit = Math.min(Number(req.query.limit ?? 12), 50);
    const offset = Math.max(Number(req.query.offset ?? 0), 0);
    const email = String(req.query.email ?? "").trim();

    if (!email) return res.json({ q, total: 0, hits: [], groups: [] });

    const groups = await getGroupsForEmail(email);
    if (!groups.length) return res.json({ q, total: 0, hits: [], groups });

    const filters = ["active = true"];
    const gf = buildMeiliGroupFilter(groups);
    if (gf) filters.push(gf);

    const result = await index.search(q, { limit, offset, filter: filters.join(" AND ") });

    res.json({
      q, email, groups,
      total: result.estimatedTotalHits ?? 0,
      hits: (result.hits || []).map(h => ({
        id: h.id,
        name: h.name,
        url: h.url,
        slug: h.slug,
        image: h.image,
        shortDesc: h.shortDesc,
        partNumber: h.partNumber,
        publicPartNum: h.publicPartNum
      }))
    });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Search failed", detail: String(e?.message || e) });
  }
});

app.get("/health", (_, res) => res.json({ ok: true }));

app.listen(PORT, () => console.log("Search API listening on", PORT));
