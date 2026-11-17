// FexaFY — /api/drive  (v148) — stateless Google token broker
// Why this exists: a browser-only app cannot get a long-lived Google sign-in without a client SECRET, and a
// secret must never ship in the app. So the app asks this endpoint to do just the two secret-requiring steps
// and hands the result straight back:
//   exchange  one-time sign-in code (+PKCE verifier)  ->  access token + refresh token
//   renew     refresh token                            ->  new access token
//   revoke    token                                    ->  Google revokes it (on sign-out)
// NOTHING is stored here and nothing is logged: the refresh token lives only on the person's own device.
// The only Redis use is a per-IP request counter (rate limit). See SECURITY-RULES.md section 2.
import { Redis } from "@upstash/redis";

const redis = Redis.fromEnv();
const TOKEN_URL = "https://oauth2.googleapis.com/token";
const REVOKE_URL = "https://oauth2.googleapis.com/revoke";
const NEEDED_SCOPE = "https://www.googleapis.com/auth/drive.appdata";
const RATE_PREFIX = "fexafy:ratelimit:drive:";
const RATE_LIMIT_MAX = 20;     // requests...
const RATE_LIMIT_WINDOW = 60;  // ...per this many seconds, per IP
const MAX_BODY_CHARS = 4096;

/* CORS: ONE origin only (the same PLUS_ALLOWED_ORIGIN the other endpoints use). No wildcard; no env var = no CORS. */
function cors(req, res) {
  const allowed = process.env.PLUS_ALLOWED_ORIGIN;
  const origin = req.headers.origin;
  if (allowed && origin === allowed) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    res.setHeader("Access-Control-Max-Age", "600");
  }
}

async function withinRateLimit(ip) {
  try {
    const key = RATE_PREFIX + ip;
    const n = await redis.incr(key);
    if (n === 1) await redis.expire(key, RATE_LIMIT_WINDOW);
    return n <= RATE_LIMIT_MAX;
  } catch (e) { return true; } // a Redis hiccup must not block sign-in; every field is still validated below
}

const CODE_RE = /^[A-Za-z0-9._~\-\/+=]{10,600}$/;       // Google auth codes
const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;       // RFC 7636 PKCE verifier
const TOKEN_RE = /^[A-Za-z0-9._~\-\/+=]{20,2048}$/;     // Google refresh/access tokens

async function google(url, params) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(params).toString(),
    signal: AbortSignal.timeout(8000)
  });
  let j = {};
  try { j = await r.json(); } catch (e) {}
  return { ok: r.ok, status: r.status, json: j };
}

export default async function handler(req, res) {
  cors(req, res);
  res.setHeader("Cache-Control", "no-store");
  if (req.method === "OPTIONS") return res.status(204).end();
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "Method not allowed" });
  }
  const clientId = process.env.GOOGLE_CLIENT_ID, clientSecret = process.env.GOOGLE_CLIENT_SECRET, origin = process.env.PLUS_ALLOWED_ORIGIN;
  if (!clientId || !clientSecret || !origin) return res.status(503).json({ error: "not_configured" });
  // Only the app's own origin may call this (CORS alone doesn't stop non-browser callers, but they gain nothing: every action needs a secret Google gave the caller).
  if (req.headers.origin !== origin) return res.status(403).json({ error: "forbidden" });

  const ip = (req.headers["x-forwarded-for"] || "").split(",")[0].trim() || "unknown";
  if (!(await withinRateLimit(ip))) return res.status(429).json({ error: "Too many requests, please slow down" });

  let body = req.body;
  if (typeof body === "string") {
    if (body.length > MAX_BODY_CHARS) return res.status(413).json({ error: "too_large" });
    try { body = JSON.parse(body); } catch { body = {}; }
  }
  if (!body || typeof body !== "object" || JSON.stringify(body).length > MAX_BODY_CHARS) return res.status(400).json({ error: "bad_request" });

  try {
    if (body.action === "exchange") {
      const { code, verifier, redirect_uri } = body;
      // The redirect page must live on the app's own origin: stops this endpoint being used with someone else's page.
      if (typeof code !== "string" || !CODE_RE.test(code) || typeof verifier !== "string" || !VERIFIER_RE.test(verifier)
        || typeof redirect_uri !== "string" || redirect_uri.length > 300
        || !redirect_uri.startsWith(origin + "/") || !/\/oauth-callback\.html$/.test(redirect_uri)) {
        return res.status(400).json({ error: "bad_request" });
      }
      const g = await google(TOKEN_URL, { code, code_verifier: verifier, client_id: clientId, client_secret: clientSecret, redirect_uri, grant_type: "authorization_code" });
      if (!g.ok || typeof g.json.access_token !== "string") return res.status(400).json({ error: "exchange_failed" });
      if (typeof g.json.scope !== "string" || !g.json.scope.split(" ").includes(NEEDED_SCOPE)) return res.status(403).json({ error: "scope" });
      return res.status(200).json({
        access_token: g.json.access_token,
        expires_in: Number(g.json.expires_in) || 3600,
        refresh_token: typeof g.json.refresh_token === "string" ? g.json.refresh_token : null
      });
    }
    if (body.action === "renew") {
      if (typeof body.refresh_token !== "string" || !TOKEN_RE.test(body.refresh_token)) return res.status(400).json({ error: "bad_request" });
      const g = await google(TOKEN_URL, { refresh_token: body.refresh_token, client_id: clientId, client_secret: clientSecret, grant_type: "refresh_token" });
      if (g.ok && typeof g.json.access_token === "string") return res.status(200).json({ access_token: g.json.access_token, expires_in: Number(g.json.expires_in) || 3600 });
      // Google says the grant is dead (revoked / expired / password changed): the app must sign in again. Anything else is temporary.
      if (g.status === 400 && g.json.error === "invalid_grant") return res.status(401).json({ error: "reauth" });
      return res.status(502).json({ error: "upstream" });
    }
    if (body.action === "revoke") {
      if (typeof body.token !== "string" || !TOKEN_RE.test(body.token)) return res.status(400).json({ error: "bad_request" });
      await google(REVOKE_URL, { token: body.token }); // best effort: whatever Google answers, the app is signing out anyway
      return res.status(200).json({ ok: true });
    }
    return res.status(400).json({ error: "bad_request" });
  } catch (e) {
    // Never include the error text: it could contain request details.
    return res.status(502).json({ error: "upstream" });
  }
}
