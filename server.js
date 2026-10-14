// Arawali registration server — Node 22.9+.
// Employees sign in with their name and the staff password, then register customers.
// One registration per Instagram account; duplicates are rejected by the database.
// Data lives in Postgres (see db.js), so the app can run on free hosting such as Render.

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set. Add your Neon connection string to .env (see .env.example).");
  process.exit(1);
}
const db = require("./db");

// 4500 rather than 3000: dev servers like Vite/React often hold localhost:3000 on IPv6,
// which silently steals browser traffic meant for this app.
const PORT = Number(process.env.PORT) || 4500;
const ADMIN_KEY = process.env.ADMIN_KEY || "arawali-admin";
const PUBLIC_DIR = path.join(__dirname, "public");
// Render (and most hosts) sit behind a proxy that passes the visitor's IP and https status in headers.
const BEHIND_PROXY = !!(process.env.RENDER || process.env.TRUST_PROXY);

const LOGIN_MAX_FAILS = 10; // wrong passwords from one device before a pause
const LOGIN_LOCK = 10 * 60 * 1000; // length of that pause
const SESSION_TTL = 12 * 60 * 60 * 1000; // one working shift
const COOKIE = "arw_session";

const STATIC_FILES = {
  "/admin": ["admin.html", "text/html; charset=utf-8"],
  "/logo.png": ["logo.png", "image/png"],
  "/styles.css": ["styles.css", "text/css; charset=utf-8"],
};

// Settings are read once at startup and kept here; only the admin page changes them.
let settings = { version: 1 }; // { staffPassword: { salt, hash }, version, passwordUpdatedAt }
const loginFails = new Map(); // ip -> { count, until }

// ---------- staff password ----------

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString("hex") };
}

// Stray spaces from phone keyboards are ignored. The untrimmed form is also
// accepted, for a password saved with a space before trimming existed.
function checkPassword(password) {
  const stored = settings.staffPassword;
  if (!stored) return false;
  const expected = Buffer.from(stored.hash, "hex");
  const matches = (p) => crypto.timingSafeEqual(Buffer.from(hashPassword(p, stored.salt).hash, "hex"), expected);
  return matches(password.trim()) || matches(password);
}

// ---------- validation ----------

// Accepts "@Name", "name", "instagram.com/name", "https://www.instagram.com/name/?igsh=..."
// and returns the bare lowercase handle, or null if it is not a valid Instagram username.
function normalizeHandle(input) {
  let h = String(input || "").trim().toLowerCase();
  h = h.replace(/^(https?:\/\/)?(www\.|m\.)?(instagram\.com|instagr\.am)\//, "");
  h = h.split(/[/?#]/)[0];
  h = h.replace(/^@+/, "");
  if (!/^[a-z0-9._]{1,30}$/.test(h)) return null;
  if (h.startsWith(".") || h.endsWith(".") || h.includes("..")) return null;
  return h;
}

// Indian mobile numbers: strips spaces/dashes and a leading +91, 91 or 0.
function normalizePhone(input) {
  let p = String(input || "").replace(/[\s\-()]/g, "");
  p = p.replace(/^(\+91|0091|91(?=\d{10}$)|0(?=\d{10}$))/, "");
  return /^[6-9]\d{9}$/.test(p) ? p : null;
}

function normalizeName(input) {
  const n = String(input || "").replace(/\s+/g, " ").trim();
  return n.length >= 2 && n.length <= 80 ? n : null;
}

const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

// ---------- http helpers ----------

function send(res, status, body, headers = {}) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    ...headers,
  });
  res.end(JSON.stringify(body));
}

function redirect(res, location) {
  res.writeHead(302, { Location: location, "Cache-Control": "no-store" });
  res.end();
}

function serveFile(res, file, type) {
  res.writeHead(200, { "Content-Type": type, "Cache-Control": "no-cache" });
  fs.createReadStream(path.join(PUBLIC_DIR, file)).pipe(res);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
      if (raw.length > 10_000) {
        reject(new Error("too_large"));
        req.destroy();
      }
    });
    req.on("end", () => {
      try {
        resolve(JSON.parse(raw || "{}"));
      } catch {
        reject(new Error("bad_json"));
      }
    });
  });
}

function getCookie(req, name) {
  const match = (req.headers.cookie || "").match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? decodeURIComponent(match[1]) : null;
}

function clientIp(req) {
  if (BEHIND_PROXY && req.headers["x-forwarded-for"]) return req.headers["x-forwarded-for"].split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
}

function sessionCookie(req, token, maxAge) {
  const secure = BEHIND_PROXY && req.headers["x-forwarded-proto"] === "https" ? "; Secure" : "";
  return `${COOKIE}=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
}

// Returns { key, name } for a valid signed-in employee, or null.
// Changing the staff password bumps settings.version, which signs everyone out.
async function getSession(req) {
  const token = getCookie(req, COOKIE);
  if (!token) return null;
  const key = sha256(token);
  const s = await db.findSession(key);
  if (!s || s.version !== settings.version) return null;
  return { key, name: s.name };
}

function isAdmin(req) {
  const given = Buffer.from(String(req.headers["x-admin-key"] || ""));
  const expected = Buffer.from(ADMIN_KEY);
  return given.length === expected.length && crypto.timingSafeEqual(given, expected);
}

function regNo(serial) {
  return "ARW-" + String(serial).padStart(4, "0");
}

function csvCell(value, guard = true) {
  let s = String(value ?? "");
  if (guard && /^[=+\-@\t\r]/.test(s)) s = "'" + s; // stop spreadsheet formula injection
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

const SIGNED_OUT = { auth: false, error: "Your session has ended. Sign in again." };

// ---------- routes ----------

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  const route = `${req.method} ${url.pathname}`;

  // ----- pages -----

  if (route === "GET /") {
    if (!(await getSession(req))) return redirect(res, "/login");
    return serveFile(res, "index.html", "text/html; charset=utf-8");
  }
  if (route === "GET /login") {
    if (await getSession(req)) return redirect(res, "/");
    return serveFile(res, "login.html", "text/html; charset=utf-8");
  }
  if (req.method === "GET" && STATIC_FILES[url.pathname]) {
    const [file, type] = STATIC_FILES[url.pathname];
    return serveFile(res, file, type);
  }

  if (route === "GET /api/ping") {
    return send(res, 200, { app: "arawali-registration" });
  }

  // ----- employee sign-in -----

  if (route === "POST /api/auth/login") {
    const body = await readBody(req).catch(() => ({}));
    const name = normalizeName(body.name);
    const password = String(body.password || "");
    if (!name) return send(res, 400, { field: "name", error: "Enter your name." });
    if (!password) return send(res, 400, { field: "password", error: "Enter the staff password." });
    if (!settings.staffPassword) {
      return send(res, 403, { error: "No staff password has been set yet. Ask the admin to set one on the admin page." });
    }

    const ip = clientIp(req);
    const fails = loginFails.get(ip) || { count: 0, until: 0 };
    if (fails.until > Date.now()) {
      const mins = Math.ceil((fails.until - Date.now()) / 60000);
      return send(res, 429, { error: `Too many wrong passwords. Try again in ${mins} minute${mins === 1 ? "" : "s"}.` });
    }
    if (!checkPassword(password)) {
      const count = (fails.until ? 0 : fails.count) + 1; // a finished pause starts the count again
      loginFails.set(ip, { count, until: count >= LOGIN_MAX_FAILS ? Date.now() + LOGIN_LOCK : 0 });
      return send(res, 401, { field: "password", error: "That password isn't right. Check with your admin." });
    }

    loginFails.delete(ip);
    const token = crypto.randomBytes(32).toString("base64url");
    await db.createSession(sha256(token), name, settings.version, Date.now() + SESSION_TTL);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, token, SESSION_TTL / 1000) });
  }

  if (route === "GET /api/auth/me") {
    const session = await getSession(req);
    if (!session) return send(res, 401, SIGNED_OUT);
    return send(res, 200, { name: session.name });
  }

  if (route === "POST /api/auth/logout") {
    const session = await getSession(req);
    if (session) await db.deleteSession(session.key);
    return send(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(req, "", 0) });
  }

  // ----- registration (employees only) -----

  if (route === "GET /api/check") {
    if (!(await getSession(req))) return send(res, 401, SIGNED_OUT);
    const h = normalizeHandle(url.searchParams.get("handle"));
    if (!h) return send(res, 200, { valid: false });
    return send(res, 200, { valid: true, handle: h, available: !(await db.isRegistered(h)) });
  }

  if (route === "POST /api/register") {
    const session = await getSession(req);
    if (!session) return send(res, 401, SIGNED_OUT);

    let body;
    try {
      body = await readBody(req);
    } catch {
      return send(res, 400, { error: "Invalid request." });
    }

    const name = normalizeName(body.name);
    const phone = normalizePhone(body.phone);
    const instagram = normalizeHandle(body.instagram);

    if (!name) return send(res, 400, { field: "name", error: "Please enter a valid name." });
    if (!phone) return send(res, 400, { field: "phone", error: "Please enter a valid 10-digit mobile number." });
    if (!instagram) return send(res, 400, { field: "instagram", error: "Please enter a valid Instagram handle." });

    const entry = await db.addRegistration({
      id: crypto.randomUUID(),
      name,
      phone,
      instagram,
      staffName: session.name,
    });
    if (!entry) {
      return send(res, 409, {
        field: "instagram",
        error: `@${instagram} is already registered. Each Instagram account can only be registered once.`,
      });
    }
    return send(res, 201, { ok: true, registration: entry });
  }

  // ----- admin -----

  if (url.pathname.startsWith("/api/admin/")) {
    if (!isAdmin(req)) return send(res, 401, { error: "Wrong admin key." });

    if (route === "GET /api/admin/registrations") {
      return send(res, 200, { registrations: await db.listRegistrations() });
    }

    if (route === "GET /api/admin/export.csv") {
      const rows = [["Reg. No.", "Name", "Phone", "Instagram", "Registered By", "Registered At"]];
      for (const r of await db.listRegistrations()) {
        rows.push([regNo(r.serial), r.name, r.phone, "@" + r.instagram, r.staffName || "", r.createdAt]);
      }
      // Instagram handles are already validated to [a-z0-9._], so the "@" is safe to keep.
      const csv =
        "﻿" + rows.map((row) => row.map((v, col) => csvCell(v, col !== 3)).join(",")).join("\r\n");
      res.writeHead(200, {
        "Content-Type": "text/csv; charset=utf-8",
        "Content-Disposition": 'attachment; filename="arawali-registrations.csv"',
      });
      return res.end(csv);
    }

    if (req.method === "DELETE" && url.pathname.startsWith("/api/admin/registrations/")) {
      const id = decodeURIComponent(url.pathname.split("/").pop());
      if (!(await db.deleteRegistration(id))) return send(res, 404, { error: "Not found." });
      return send(res, 200, { ok: true });
    }

    if (route === "GET /api/admin/settings") {
      return send(res, 200, { passwordSet: !!settings.staffPassword, passwordUpdatedAt: settings.passwordUpdatedAt || null });
    }

    if (route === "POST /api/admin/password") {
      const body = await readBody(req).catch(() => ({}));
      const password = String(body.password || "").trim();
      if (password.length < 6) return send(res, 400, { error: "Use at least 6 characters." });
      if (password.length > 100) return send(res, 400, { error: "Use 100 characters or fewer." });
      const next = {
        staffPassword: hashPassword(password),
        version: (settings.version || 1) + 1,
        passwordUpdatedAt: new Date().toISOString(),
      };
      await db.saveSettings(next);
      settings = next;
      // Everyone signed in with the old password is signed out.
      await db.deleteAllSessions();
      loginFails.clear();
      return send(res, 200, { ok: true });
    }
  }

  send(res, 404, { error: "Not found." });
}

async function start() {
  try {
    await db.setup();
    settings = (await db.getSettings()) || { version: 1 };
  } catch (err) {
    console.error("Couldn't connect to the database. Check DATABASE_URL.\n", err.message);
    process.exit(1);
  }

  http
    .createServer((req, res) =>
      handle(req, res).catch((err) => {
        console.error(err);
        if (!res.headersSent) send(res, 500, { error: "Something went wrong. Try again." });
      })
    )
    .on("error", (err) => {
      if (err.code === "EADDRINUSE") {
        console.error(`Port ${PORT} is already in use. Start on another port, e.g. in PowerShell:`);
        console.error(`  $env:PORT=4600; npm start`);
        process.exit(1);
      }
      throw err;
    })
    .listen(PORT, async () => {
      const count = (await db.listRegistrations()).length;
      console.log(`Arawali registration running on port ${PORT} with ${count} registration(s).`);
      if (!process.env.ADMIN_KEY) console.log(`Admin key: "${ADMIN_KEY}" (set ADMIN_KEY to change it)`);
      if (!settings.staffPassword) console.log(`No staff password yet: set one on the admin page so employees can sign in.`);
      if (BEHIND_PROXY) return;

      console.log(`Open http://localhost:${PORT}  (admin: http://localhost:${PORT}/admin)`);
      const lan = Object.values(os.networkInterfaces())
        .flat()
        .filter((a) => a && a.family === "IPv4" && !a.internal)
        .map((a) => `http://${a.address}:${PORT}`);
      if (lan.length) console.log(`Other devices on this Wi-Fi: ${lan.join("  ")}`);

      // Make sure "localhost" really reaches this server and not another app on the same port.
      try {
        const res = await fetch(`http://localhost:${PORT}/api/ping`);
        const body = await res.json();
        if (body.app !== "arawali-registration") throw new Error();
      } catch {
        console.warn(`\nWARNING: another program is answering on localhost:${PORT}.`);
        console.warn(`Open http://127.0.0.1:${PORT} instead, or restart with a different port ($env:PORT=4600; npm start).\n`);
      }
    });
}

start();
