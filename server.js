// Arawali registration server — Node 22.9+.
// Anyone with the link can register (name, phone, Instagram handle); only the admin
// page needs a password. One registration per Instagram account, enforced by the database.
// Data lives in Postgres (see db.js), so the app can run on free hosting such as Render.

const http = require("http");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

// Values copied from a .env file often keep their quotes or a "NAME=" prefix when
// pasted into a host's settings page. Clean those off so the app still starts.
for (const name of ["DATABASE_URL", "ADMIN_KEY"]) {
  const raw = process.env[name];
  if (raw) process.env[name] = raw.trim().replace(new RegExp(`^${name}=`), "").replace(/^(["'])(.*)\1$/, "$2").trim();
}

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set. Add your Neon connection string to .env (see .env.example).");
  process.exit(1);
}
if (process.env.RENDER && !process.env.ADMIN_KEY) {
  console.error("ADMIN_KEY is not set. Add it under the service's Environment tab on Render.");
  process.exit(1);
}
const db = require("./db");

// 4500 rather than 3000: dev servers like Vite/React often hold localhost:3000 on IPv6,
// which silently steals browser traffic meant for this app.
const PORT = Number(process.env.PORT) || 4500;
const ADMIN_KEY = process.env.ADMIN_KEY || "Arawali";
const PUBLIC_DIR = path.join(__dirname, "public");
// Render (and most hosts) sit behind a proxy that passes the visitor's IP in a header.
const BEHIND_PROXY = !!(process.env.RENDER || process.env.TRUST_PROXY);

// The form is public, so each device (IP address) gets a budget per 10 minutes.
// A registration desk on one Wi-Fi shares an IP, so the limits are generous.
const WINDOW = 10 * 60 * 1000;
const LIMITS = { register: 60, check: 600, adminFail: 10 };

const STATIC_FILES = {
  "/": ["index.html", "text/html; charset=utf-8"],
  "/admin": ["admin.html", "text/html; charset=utf-8"],
  "/logo.png": ["logo.png", "image/png"],
  "/styles.css": ["styles.css", "text/css; charset=utf-8"],
};

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

// ---------- rate limits ----------

const hits = new Map(); // "kind:ip" -> { count, resetAt }

// Counts one use and returns the seconds to wait if over the limit, else 0.
function overLimit(kind, ip) {
  const key = kind + ":" + ip;
  const now = Date.now();
  let h = hits.get(key);
  if (!h || h.resetAt <= now) hits.set(key, (h = { count: 0, resetAt: now + WINDOW }));
  h.count += 1;
  return h.count > LIMITS[kind] ? Math.ceil((h.resetAt - now) / 1000) : 0;
}

// Checks without counting (used for admin lockout, which only counts failures).
function blocked(kind, ip) {
  const h = hits.get(kind + ":" + ip);
  return h && h.resetAt > Date.now() && h.count >= LIMITS[kind] ? Math.ceil((h.resetAt - Date.now()) / 1000) : 0;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, h] of hits) if (h.resetAt <= now) hits.delete(k);
}, WINDOW).unref();

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

function clientIp(req) {
  if (BEHIND_PROXY && req.headers["x-forwarded-for"]) return req.headers["x-forwarded-for"].split(",")[0].trim();
  return req.socket.remoteAddress || "unknown";
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

const tooMany = (res, wait) =>
  send(res, 429, { error: `Too many attempts from this device. Try again in ${Math.ceil(wait / 60)} minute(s).` });

// ---------- routes ----------

async function handle(req, res) {
  const url = new URL(req.url, "http://localhost");
  const route = `${req.method} ${url.pathname}`;

  // ----- pages -----

  if (req.method === "GET" && STATIC_FILES[url.pathname]) {
    const [file, type] = STATIC_FILES[url.pathname];
    return serveFile(res, file, type);
  }
  if (route === "GET /login") return redirect(res, "/"); // old staff sign-in link

  if (route === "GET /api/ping") {
    return send(res, 200, { app: "arawali-registration" });
  }

  // ----- registration (public) -----

  if (route === "GET /api/check") {
    const wait = overLimit("check", clientIp(req));
    if (wait) return tooMany(res, wait);
    const h = normalizeHandle(url.searchParams.get("handle"));
    if (!h) return send(res, 200, { valid: false });
    return send(res, 200, { valid: true, handle: h, available: !(await db.isRegistered(h)) });
  }

  if (route === "POST /api/register") {
    const wait = overLimit("register", clientIp(req));
    if (wait) return tooMany(res, wait);

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

    const entry = await db.addRegistration({ id: crypto.randomUUID(), name, phone, instagram });
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
    const ip = clientIp(req);
    const wait = blocked("adminFail", ip);
    if (wait) return tooMany(res, wait);
    if (!isAdmin(req)) {
      overLimit("adminFail", ip);
      return send(res, 401, { error: "Wrong admin password." });
    }

    if (route === "GET /api/admin/registrations") {
      return send(res, 200, { registrations: await db.listRegistrations() });
    }

    if (route === "GET /api/admin/export.csv") {
      const rows = [["Reg. No.", "Name", "Phone", "Instagram", "Registered At"]];
      for (const r of await db.listRegistrations()) {
        rows.push([regNo(r.serial), r.name, r.phone, "@" + r.instagram, r.createdAt]);
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
  }

  send(res, 404, { error: "Not found." });
}

async function start() {
  try {
    await db.setup();
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
      if (!process.env.ADMIN_KEY) console.log(`Admin password: "${ADMIN_KEY}" (set ADMIN_KEY to change it)`);
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
