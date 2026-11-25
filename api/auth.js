// Accounts for Fourth wall: sign up / sign in (unique usernames, hashed passwords), Google sign-in,
// per-user saved films, and an admin-only user list. One file = one URL: /api/auth
const crypto = require("crypto");
const { promisify } = require("util");
const scrypt = promisify(crypto.scrypt);

/* ---------- database: Upstash Redis over plain HTTPS (no packages needed) ---------- */
const DB_URL = () => process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "";
const DB_TOKEN = () => process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "";
const dbReady = () => !!(DB_URL() && DB_TOKEN() && process.env.SESSION_SECRET && process.env.SESSION_SECRET.length >= 24);

async function redis(...cmd) {
  const r = await fetch(DB_URL(), {
    method: "POST",
    headers: { Authorization: "Bearer " + DB_TOKEN(), "Content-Type": "application/json" },
    body: JSON.stringify(cmd.map((c) => (typeof c === "number" ? String(c) : c)))
  });
  const j = await r.json();
  if (j.error) throw new Error("db: " + j.error);
  return j.result;
}
const getJSON = async (key) => { const v = await redis("GET", key); return v ? JSON.parse(v) : null; };
const setJSON = (key, obj, ...extra) => redis("SET", key, JSON.stringify(obj), ...extra);

/* ---------- usernames ---------- */
const USERNAME_RE = /^[A-Za-z0-9._-]{3,24}$/;
const RESERVED = ["admin", "administrator", "root", "support", "system", "moderator", "fourthwall", "fourth-wall", "staff", "owner", "null", "undefined"];
// Two names count as "the same" when they look alike: case, dots/dashes, repeated letters and l/I/1, O/0 swaps are ignored.
function canonName(name) {
  let s = String(name).toLowerCase().replace(/[._-]/g, "");
  s = s.replace(/[0]/g, "o").replace(/[1il|]/g, "l").replace(/3/g, "e").replace(/4/g, "a").replace(/5/g, "s").replace(/7/g, "t").replace(/\$/g, "s").replace(/@/g, "a");
  s = s.replace(/(.)\1+/g, "$1");
  return s;
}
const adminName = () => String(process.env.ADMIN_USERNAME || "").toLowerCase();

/* ---------- passwords: scrypt + random salt (hashed, never stored in readable form) ---------- */
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(pw, salt, 64, { N: 16384, r: 8, p: 1 });
  return "scrypt$16384$" + salt.toString("base64") + "$" + key.toString("base64");
}
async function verifyPassword(pw, stored) {
  try {
    const [alg, n, saltB64, keyB64] = String(stored).split("$");
    if (alg !== "scrypt") return false;
    const key = await scrypt(pw, Buffer.from(saltB64, "base64"), 64, { N: +n, r: 8, p: 1 });
    const want = Buffer.from(keyB64, "base64");
    return want.length === key.length && crypto.timingSafeEqual(want, key);
  } catch (e) { return false; }
}
const sha = (s) => crypto.createHash("sha256").update(String(s)).digest();
const safeEqual = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));

/* ---------- sessions: signed, HttpOnly cookie ---------- */
const COOKIE = "fw_sess", MAXAGE = 30 * 24 * 3600;
const b64u = (b) => Buffer.from(b).toString("base64url");
function sign(payload) {
  const body = b64u(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(body).digest("base64url");
  return body + "." + sig;
}
function verify(token) {
  try {
    const [body, sig] = String(token).split(".");
    const want = crypto.createHmac("sha256", process.env.SESSION_SECRET).update(body).digest("base64url");
    if (!sig || sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch (e) { return null; }
}
function setSession(res, username) {
  const t = sign({ u: username, exp: Date.now() + MAXAGE * 1000 });
  res.setHeader("Set-Cookie", COOKIE + "=" + t + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + MAXAGE);
}
function clearSession(res) { res.setHeader("Set-Cookie", COOKIE + "=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0"); }
function sessionUser(req) {
  const m = String(req.headers.cookie || "").match(new RegExp("(?:^|;\\s*)" + COOKIE + "=([^;]+)"));
  const p = m && verify(m[1]);
  return p ? p.u : null;
}
async function currentUser(req) {
  const u = sessionUser(req);
  if (!u) return null;
  const rec = await getJSON("user:" + u);
  return rec ? { key: u, rec } : null;
}

/* ---------- misc ---------- */
function publicUser(rec) {
  return { username: rec.display, role: rec.role, provider: rec.provider, photo: rec.photo || "", email: rec.email || "" };
}
async function readBody(req) {
  if (req.body && typeof req.body === "object") return req.body;
  let s = typeof req.body === "string" ? req.body : "";
  if (!s) { for await (const c of req) { s += c; if (s.length > 1.2e6) break; } }
  try { return JSON.parse(s || "{}"); } catch (e) { return {}; }
}
function sameOrigin(req) {
  const o = req.headers.origin;
  if (!o) return true;
  try { return new URL(o).host === req.headers.host; } catch (e) { return false; }
}
async function rateLimit(key, max, windowSec) {
  const n = await redis("INCR", "rl:" + key);
  if (n === 1) await redis("EXPIRE", "rl:" + key, windowSec);
  return n <= max;
}
const ip = (req) => String((req.headers["x-forwarded-for"] || "").split(",")[0] || req.socket && req.socket.remoteAddress || "?").trim();
const send = (res, code, obj) => { res.setHeader("Cache-Control", "no-store"); return res.status(code).json(obj); };

const L = { redis, getJSON, setJSON, dbReady, USERNAME_RE, RESERVED, canonName, adminName, hashPassword, verifyPassword, safeEqual, setSession, clearSession, currentUser, publicUser, readBody, sameOrigin, rateLimit, ip, send };

const DUMMY = "scrypt$16384$AAAAAAAAAAAAAAAAAAAAAA==$" + Buffer.alloc(64).toString("base64");

async function claimName(display, extra) {
  // Returns { ok, error } and reserves the name (and its look-alike form) atomically.
  const lower = display.toLowerCase(), canon = L.canonName(lower);
  const reserved = L.RESERVED.concat(L.adminName() ? [L.adminName()] : []);
  if (!extra.allowReserved && reserved.some((r) => r === lower || L.canonName(r) === canon)) return { ok: false, error: "That username is reserved." };
  const got = await L.redis("SET", "canon:" + canon, lower, "NX");
  if (got !== "OK") {
    const owner = await L.redis("GET", "canon:" + canon);
    return { ok: false, error: owner === lower ? "That username is taken." : "That username is too similar to one that already exists. Try a more different one." };
  }
  return { ok: true, lower, canon };
}

async function newUser(display, fields) {
  const lower = display.toLowerCase();
  const rec = Object.assign({ display, role: "user", provider: "password", created: Date.now(), last: Date.now(), films: 0 }, fields);
  const made = await L.redis("SET", "user:" + lower, JSON.stringify(rec), "NX");
  if (made !== "OK") return null;
  await L.redis("SADD", "users", lower);
  return rec;
}

module.exports = async function handler(req, res) {
  try {
    const action = String(req.query.action || "");
    if (req.method === "GET" && action === "config") return L.send(res, 200, { dbReady: L.dbReady(), google: process.env.GOOGLE_CLIENT_ID || "" });
    if (!L.dbReady()) return L.send(res, 503, { error: "Accounts aren't set up on the server yet." });

    if (req.method === "GET" && action === "me") {
      const cu = await L.currentUser(req);
      if (!cu) return L.send(res, 200, { user: null });
      return L.send(res, 200, { user: L.publicUser(cu.rec), data: (await L.getJSON("data:" + cu.key)) || {} });
    }
    if (req.method === "GET" && action === "data") {
      const cu = await L.currentUser(req);
      if (!cu) return L.send(res, 401, { error: "Please sign in." });
      return L.send(res, 200, { data: (await L.getJSON("data:" + cu.key)) || {} });
    }
    if (req.method === "GET" && action === "users") {
      // Admin only: fetch the list of users from the database. Password hashes are never included.
      const cu = await L.currentUser(req);
      if (!cu || cu.rec.role !== "admin") return L.send(res, 403, { error: "Admins only." });
      const keys = (await L.redis("SMEMBERS", "users")) || [];
      const users = [];
      for (let i = 0; i < keys.length && i < 2000; i += 100) {
        const rows = await L.redis("MGET", ...keys.slice(i, i + 100).map((k) => "user:" + k));
        (rows || []).forEach((raw) => {
          if (!raw) return;
          const r = JSON.parse(raw);
          users.push({ username: r.display, email: r.email || "", provider: r.provider, role: r.role, created: r.created, last: r.last, films: r.films || 0 });
        });
      }
      users.sort((a, b) => b.created - a.created);
      return L.send(res, 200, { total: users.length, users });
    }
    if (req.method !== "POST") return L.send(res, 405, { error: "Method not allowed" });
    if (!L.sameOrigin(req)) return L.send(res, 403, { error: "Blocked." });
    const body = await L.readBody(req);
    const act = String(body.action || action);

    if (act === "save") {
      const cu = await L.currentUser(req);
      if (!cu) return L.send(res, 401, { error: "Please sign in." });
      if (!(await L.rateLimit("save:" + cu.key, 240, 60))) return L.send(res, 429, { error: "Saving too fast." });
      const films = Array.isArray(body.films) ? body.films.slice(0, 3000) : [];
      const saved = { films, avatar: body.avatar && typeof body.avatar === "object" ? body.avatar : null, ob: body.ob ? 1 : 0, saved: Date.now() };
      const text = JSON.stringify(saved);
      if (text.length > 900000) return L.send(res, 413, { error: "Your data is too large to save." });
      await L.redis("SET", "data:" + cu.key, text);
      cu.rec.films = films.length; cu.rec.updated = Date.now();
      await L.redis("SET", "user:" + cu.key, JSON.stringify(cu.rec));
      return L.send(res, 200, { ok: true });
    }

    if (act === "logout") { L.clearSession(res); return L.send(res, 200, { ok: true }); }

    if (act === "register") {
      if (!(await L.rateLimit("reg:" + L.ip(req), 10, 3600))) return L.send(res, 429, { error: "Too many sign-ups from here. Try again later." });
      const name = String(body.username || "").trim(), pw = String(body.password || "");
      if (!L.USERNAME_RE.test(name)) return L.send(res, 400, { error: "Username must be 3 to 24 characters: letters, numbers, dot, dash or underscore." });
      if (pw.length < 8 || pw.length > 128) return L.send(res, 400, { error: "Password must be 8 to 128 characters." });
      const c = await claimName(name, {});
      if (!c.ok) return L.send(res, 409, { error: c.error });
      const rec = await newUser(name, { hash: await L.hashPassword(pw) });
      if (!rec) { await L.redis("DEL", "canon:" + c.canon); return L.send(res, 409, { error: "That username is taken." }); }
      L.setSession(res, c.lower);
      return L.send(res, 200, { user: L.publicUser(rec), data: {}, isNew: true });
    }

    if (act === "login") {
      const lower = String(body.username || "").trim().toLowerCase(), pw = String(body.password || "");
      if (!(await L.rateLimit("ip:" + L.ip(req), 30, 600)) || !(await L.rateLimit("u:" + lower, 10, 600))) return L.send(res, 429, { error: "Too many attempts. Wait ten minutes and try again." });
      const bad = () => L.send(res, 401, { error: "Wrong username or password." });
      if (!lower || !pw) return bad();

      // The admin account is defined by environment variables, so its password is never in the database.
      if (L.adminName() && lower === L.adminName() && process.env.ADMIN_PASSWORD) {
        if (!L.safeEqual(pw, process.env.ADMIN_PASSWORD)) return bad();
        let rec = await L.getJSON("user:" + lower);
        if (!rec) {
          const c = await claimName(process.env.ADMIN_USERNAME, { allowReserved: true });
          rec = await newUser(process.env.ADMIN_USERNAME, { role: "admin", provider: "admin" }) || await L.getJSON("user:" + lower);
        }
        if (!rec) return bad();
        rec.role = "admin"; rec.last = Date.now();
        await L.redis("SET", "user:" + lower, JSON.stringify(rec));
        L.setSession(res, lower);
        return L.send(res, 200, { user: L.publicUser(rec), data: (await L.getJSON("data:" + lower)) || {} });
      }

      const rec = await L.getJSON("user:" + lower);
      const ok = await L.verifyPassword(pw, rec && rec.hash ? rec.hash : DUMMY);
      if (!rec || !rec.hash || !ok) return bad();
      rec.last = Date.now();
      await L.redis("SET", "user:" + lower, JSON.stringify(rec));
      L.setSession(res, lower);
      return L.send(res, 200, { user: L.publicUser(rec), data: (await L.getJSON("data:" + lower)) || {} });
    }

    if (act === "google") {
      const cid = process.env.GOOGLE_CLIENT_ID;
      if (!cid) return L.send(res, 503, { error: "Google sign-in isn't set up yet." });
      if (!(await L.rateLimit("g:" + L.ip(req), 30, 600))) return L.send(res, 429, { error: "Too many attempts. Try again later." });
      const r = await fetch("https://oauth2.googleapis.com/tokeninfo?id_token=" + encodeURIComponent(String(body.credential || "")));
      const j = await r.json().catch(() => ({}));
      const okIss = j.iss === "accounts.google.com" || j.iss === "https://accounts.google.com";
      if (!r.ok || j.aud !== cid || !okIss || String(j.email_verified) !== "true" || !j.sub || Number(j.exp) * 1000 < Date.now()) return L.send(res, 401, { error: "Google sign-in failed. Try again." });

      const isAdmin = !!process.env.ADMIN_EMAIL && String(j.email).toLowerCase() === process.env.ADMIN_EMAIL.toLowerCase();
      let lower = await L.redis("GET", "gsub:" + j.sub), rec = lower ? await L.getJSON("user:" + lower) : null, isNew = false;
      if (!rec) {
        let base = String(j.name || String(j.email).split("@")[0] || "film").replace(/[^A-Za-z0-9._-]/g, "").slice(0, 18);
        if (base.length < 3) base = (base + "film").slice(0, 18);
        for (let i = 0; i < 10 && !rec; i++) {
          const cand = i === 0 ? base : base + String(Math.floor(Math.random() * 9000) + 100);
          const c = await claimName(cand, {});
          if (!c.ok) continue;
          rec = await newUser(cand, { provider: "google", email: j.email, photo: j.picture || "", sub: j.sub, role: isAdmin ? "admin" : "user" });
          if (rec) { lower = c.lower; await L.redis("SET", "gsub:" + j.sub, lower); isNew = true; } else await L.redis("DEL", "canon:" + c.canon);
        }
        if (!rec) return L.send(res, 500, { error: "Couldn't create your account. Try again." });
      } else {
        rec.last = Date.now(); rec.photo = j.picture || rec.photo; if (isAdmin) rec.role = "admin";
        await L.redis("SET", "user:" + lower, JSON.stringify(rec));
      }
      L.setSession(res, lower);
      return L.send(res, 200, { user: L.publicUser(rec), data: (await L.getJSON("data:" + lower)) || {}, isNew });
    }
    return L.send(res, 400, { error: "Unknown action." });
  } catch (e) {
    return L.send(res, 500, { error: "Server error: " + String(e && e.message || e).slice(0, 120) });
  }
};
