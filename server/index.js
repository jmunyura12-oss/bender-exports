/**
 * Bender Exports Ltd. — Server v2.1 (hardened)
 *
 * What changed vs v2.0 (see CHANGES.md):
 *  - Role/station permissions enforced HERE (service key bypasses RLS), from the
 *    `profiles` table only — never from user-editable Supabase metadata.
 *  - /api/pull, /api/users, /api/system now require login and honour permissions.
 *  - Public signup removed. User creation requires sudo/admin/md.
 *  - Added /api/loans, /api/contracts (+ sub-resources), fixed chat, delete tombstones.
 *  - /api/sync returns per-operation results and rejects unauthorised writes.
 */
"use strict";
require("dotenv").config();
const express = require("express");
const cors    = require("cors");
const path    = require("path");
const crypto  = require("crypto");

let helmet, compression, rateLimit;
try { helmet      = require("helmet");             } catch {}
try { compression = require("compression");        } catch {}
try { rateLimit   = require("express-rate-limit"); } catch {}

// ── Config ────────────────────────────────────────────────────────────
const PORT         = process.env.PORT || 3001;
const PUBLIC_DIR   = path.join(__dirname, "..", "public");
const SUPABASE_URL = (process.env.SUPABASE_URL || "").replace(/\/+$/, "");
const SERVICE_KEY  = process.env.SUPABASE_SERVICE_KEY;
const ANON_KEY     = process.env.SUPABASE_ANON_KEY;
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean);

if (!SUPABASE_URL || !SERVICE_KEY || !ANON_KEY) {
  console.error("[ERROR] SUPABASE_URL, SUPABASE_ANON_KEY and SUPABASE_SERVICE_KEY are all required.");
  process.exit(1);
}

// ── Small helpers ─────────────────────────────────────────────────────
const enc = encodeURIComponent;
const SAFE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const isSafeId = v => typeof v === "string" && SAFE_ID.test(v);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const errMsg = e => typeof e?.message === "string" ? e.message : (e?.message ? JSON.stringify(e.message) : String(e));
const httpStatus = e => (Number.isInteger(e?.status) && e.status >= 400 && e.status < 600) ? e.status : 500;
const fail = (res, e) => res.status(httpStatus(e)).json({ error: errMsg(e) });
const deny = (message, status = 403) => ({ status, message });

function toSnake(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.replace(/([A-Z])/g, m => "_" + m.toLowerCase())] = v;
  return out;
}
function toCamel(obj) {
  if (!obj || typeof obj !== "object" || Array.isArray(obj)) return obj;
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] = v;
  return out;
}
// keep only allowed columns; "" -> null (date/number columns reject "")
function pick(obj, cols) {
  const o = {};
  for (const c of cols) if (obj[c] !== undefined) o[c] = obj[c] === "" ? null : obj[c];
  return o;
}

// ── Supabase REST / Auth ──────────────────────────────────────────────
async function sbFetch(p, opts = {}) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${p.replace(/^\/+/, "")}`, {
    ...opts,
    headers: {
      apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`,
      "Content-Type": "application/json",
      Prefer: opts.prefer || "return=representation",
      ...(opts.headers || {}),
    },
  });
  const text = await res.text();
  let data; try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) throw { status: res.status, message: data?.message || data || "Database error" };
  return data;
}
async function sbAuth(p, body, method = "POST") {
  const res = await fetch(`${SUPABASE_URL}/auth/v1${p}`, {
    method,
    headers: { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw { status: res.status, message: data?.msg || data?.message || "Auth error" };
  return data;
}

// ── Roles & permission matrix (EDIT HERE to change who can do what) ──
const ROLES   = ["sudo","md","admin","hq_finance","hq_accountant","hq_ops","hq_it","station_manager","cashier","clerk","driver"];
const ADMINS  = ["sudo","admin","md"];
const HQ      = ["sudo","md","admin","hq_finance","hq_accountant","hq_ops","hq_it"];
const BILLERS = ["sudo","md","admin","hq_finance","hq_accountant"];   // may issue invoices and draft letters
const STATION = ["station_manager","cashier","clerk"];
const OWNERS  = ["sudo","md"];
const isStation = r => STATION.includes(r);

// scope: column holding the station id. Station roles (manager/cashier/clerk) are
// limited to rows whose scope column is in their cwsAccess. HQ roles are unscoped.
const POLICY = {
  cws:               { read: ROLES,                                   write: ADMINS,                                       scope: "id" },
  farmers:           { read: [...HQ, ...STATION],                     write: [...ADMINS, "hq_ops", ...STATION],            scope: "cws_id" },
  seasons:           { read: ROLES,                                   write: ADMINS },
  station_seasons:   { read: [...HQ, ...STATION],                     write: [...ADMINS, "station_manager"],               scope: "cws_id" },
  cherry:            { read: [...HQ, ...STATION],                     write: [...ADMINS, "hq_ops", ...STATION],            scope: "cws_id" },
  cashbook:          { read: [...HQ, "station_manager", "cashier"],   write: [...ADMINS, "hq_finance", "station_manager", "cashier"], scope: "cws_id" },
  bank_transactions: { read: ["sudo","md","admin","hq_finance","hq_accountant"], write: ["sudo","md","admin","hq_finance"] },
  expenses:          { read: [...HQ, "station_manager", "cashier"],   write: [...ADMINS, "hq_finance", "station_manager", "cashier"], scope: "cws_id" },
  debts:             { read: [...HQ, "station_manager", "cashier"],   write: [...ADMINS, "hq_finance", "station_manager", "cashier"], scope: "cws_id" },
  stock:             { read: [...HQ, ...STATION],                     write: [...ADMINS, "hq_ops", "station_manager", "cashier"],    scope: "cws_id" },
  fund_requests:     { read: [...HQ, "station_manager", "cashier"],   write: [...HQ, "station_manager", "cashier"],        scope: "cws_id", special: "fund" },
  warehouse_stock:   { read: HQ,                                      write: [...ADMINS, "hq_ops"] },
  warehouse_movements:{ read: [...HQ, "driver"],                      write: [...ADMINS, "hq_ops", "driver"] },
  projects:          { read: HQ,                                      write: [...ADMINS, "hq_ops"] },
  project_costs:     { read: HQ,                                      write: [...ADMINS, "hq_ops", "hq_finance"] },
  milestones:        { read: HQ,                                      write: [...ADMINS, "hq_ops"] },
  contractors:       { read: HQ,                                      write: [...ADMINS, "hq_ops"] },
  machines:          { read: [...HQ, "driver"],                       write: [...ADMINS, "hq_ops"] },
  assistants:        { read: [...HQ, "driver"],                       write: [...ADMINS, "hq_ops"] },
  tasks:             { read: [...HQ, "driver"],                       write: [...HQ, "driver"] },
  mach_tx:           { read: [...HQ, "driver"],                       write: [...ADMINS, "hq_ops", "hq_finance", "driver"] },
  driver_logs:       { read: [...HQ, "driver"],                       write: [...HQ, "driver"] },
  leaves:            { read: [...HQ, "driver"],                       write: [...HQ, "driver"] },
  // Invoices (machine-task billing AND general invoices). Visible to every HQ role,
  // drivers excluded. Any HQ member sees every invoice as soon as it's drafted.
  invoices:          { read: HQ,                                      write: BILLERS },
  // Letters/memos. Visible to every HQ role the moment they're drafted (not just once
  // "sent") — editing/deleting someone else's letter is still blocked below.
  letters:           { read: HQ,                                      write: BILLERS, special: "letter" },
};
const TABLES = Object.keys(POLICY);

// Row-level visibility hook (kept for future use). Nothing uses it today: invoices and
// letters are fully visible to every HQ role regardless of author/status, by request.
function visibleRows(user, table, rows) {
  return rows;
}

// Who may move a fund request INTO each status (approval workflow, enforced server-side)
const FUND_STATUS_ROLES = {
  pending_verification:     [...ADMINS, "station_manager", "cashier"],
  pending_approval:         [...ADMINS, "hq_ops"],
  pending_finance_approval: [...ADMINS, "hq_ops"],
  pending_md_release:       [...ADMINS, "hq_finance"],
  approved:                 [...ADMINS, "hq_finance"],
  rejected:                 [...ADMINS, "hq_ops", "hq_finance"],
  confirmed:                [...ADMINS, "station_manager", "cashier"],
};

// ── Express setup ─────────────────────────────────────────────────────
const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);
if (compression) app.use(compression());
if (helmet) app.use(helmet({ contentSecurityPolicy: false })); // CSP needs a build step first (inline Babel)
// Frontend is served by this same server, so cross-origin access is OFF unless listed.
app.use(cors({ origin: ALLOWED_ORIGINS.length ? ALLOWED_ORIGINS : false }));
app.use(express.json({ limit: "2mb" }));

if (rateLimit) {
  // only FAILED logins count, so a whole office behind one IP can't lock itself out
  app.use("/api/auth/login", rateLimit({ windowMs: 15*60*1000, max: 30, skipSuccessfulRequests: true,
    message: { error: "Too many failed attempts, try again in 15 minutes" } }));
  app.use("/api/auth/refresh", rateLimit({ windowMs: 15*60*1000, max: 200 }));
}

// ── Auth middleware: identity from Supabase, role from `profiles` ─────
const authCache = new Map();           // token -> { user, exp }
const AUTH_TTL = 30 * 1000;
setInterval(() => { const n = Date.now(); for (const [k, v] of authCache) if (v.exp < n) authCache.delete(k); }, 60000).unref();

async function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith("Bearer ")) return res.status(401).json({ error: "No token" });
  const token = h.slice(7);
  const hit = authCache.get(token);
  if (hit && hit.exp > Date.now()) { req.user = hit.user; return next(); }
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/user`, { headers: { apikey: ANON_KEY, Authorization: `Bearer ${token}` } });
    const sbUser = await r.json().catch(() => null);
    if (!r.ok || !sbUser?.id) return res.status(401).json({ error: "Invalid or expired token" });
    const rows = await sbFetch(`/profiles?id=eq.${sbUser.id}&select=name,role,cws_access,machine_id,avatar,active`);
    const p = rows?.[0];
    if (!p || !ROLES.includes(p.role)) return res.status(403).json({ error: "No valid profile for this account" });
    if (p.active === false) return res.status(403).json({ error: "Account disabled" });
    const user = { id: sbUser.id, email: sbUser.email, name: p.name, role: p.role,
                   cwsAccess: Array.isArray(p.cws_access) ? p.cws_access : [], machineId: p.machine_id, avatar: p.avatar };
    authCache.set(token, { user, exp: Date.now() + AUTH_TTL });
    req.user = user; next();
  } catch { res.status(401).json({ error: "Token validation failed" }); }
}
const requireRoles = (...roles) => (req, res, next) =>
  roles.includes(req.user?.role) ? next() : res.status(403).json({ error: "Forbidden" });

// ── Audit + tombstones ────────────────────────────────────────────────
async function logAudit(userId, action, table, recordId, payload) {
  try {
    await sbFetch("/audit_log", { method: "POST", prefer: "return=minimal",
      body: JSON.stringify({ user_id: userId, action, table_name: table, record_id: String(recordId ?? ""), payload: payload ?? null }) });
  } catch (e) { console.warn("[audit] failed:", errMsg(e)); }
}
let tombstoneWarned = false;
async function recordDelete(table, id, userId) {
  try {
    await sbFetch("/deleted_records", { method: "POST", prefer: "return=minimal",
      body: JSON.stringify({ table_name: table, record_id: String(id), deleted_by: userId }) });
  } catch (e) {
    if (!tombstoneWarned) { tombstoneWarned = true; console.warn("[tombstone] deleted_records missing? run supabase_patch_v3.sql:", errMsg(e)); }
  }
}

// ── Permission engine ─────────────────────────────────────────────────
const canRead  = (role, t) => !!POLICY[t]?.read.includes(role);
const canWrite = (role, t) => !!POLICY[t]?.write.includes(role);
// PostgREST filter that limits a station role to its own stations; null = unrestricted; false = no access
function scopeFilter(user, table) {
  const pol = POLICY[table];
  if (!pol?.scope || !isStation(user.role)) return null;
  const ids = user.cwsAccess.filter(isSafeId);
  return ids.length ? `${pol.scope}=in.(${ids.map(enc).join(",")})` : false;
}

async function applyWrite(user, table, op, id, data) {
  const pol = POLICY[table];
  if (!pol) throw deny(`Unknown table: ${table}`, 400);
  if (!canWrite(user.role, table)) throw deny(`Role '${user.role}' may not modify ${table}`);
  if (!isSafeId(id)) throw deny("Invalid id", 400);

  const station = isStation(user.role);
  const scoped  = pol.scope && station;
  const d = toSnake(data) || {};              // client sends camelCase; permission checks use column names
  let existing = null;
  if (scoped || pol.special === "fund") {
    const cols = ["id", ...(pol.scope ? [pol.scope] : []), ...(pol.special === "fund" ? ["status"] : [])].join(",");
    existing = (await sbFetch(`/${table}?id=eq.${enc(id)}&select=${cols}`))?.[0] || null;
  }
  if (scoped) {
    if (existing && !user.cwsAccess.includes(existing[pol.scope])) throw deny("Record belongs to another station");
    if (op !== "DELETE" && !user.cwsAccess.includes(d[pol.scope])) throw deny("You can only write records for your own station");
  }
  if (pol.special === "letter") {
    const ex = (await sbFetch(`/letters?id=eq.${enc(id)}&select=id,created_by`))?.[0] || null;
    if (ex && ex.created_by !== user.id && !ADMINS.includes(user.role)) throw deny("Only the author can change this letter");
    if (op !== "DELETE") { if (!ex) { d.created_by = user.id; d.created_by_name = user.name; } else { delete d.created_by; delete d.created_by_name; } data = d; }
  }
  if (pol.special === "fund") {
    if (op === "DELETE") { if (!ADMINS.includes(user.role)) throw deny("Only admins can delete fund requests"); }
    else {
      const ns = d.status;
      if (station) {
        if (existing && ns !== "confirmed") throw deny("Stations may only confirm receipt of an existing fund request");
        if (!existing && ns !== "pending_verification") throw deny("New fund requests must start as pending_verification");
      }
      const allowed = FUND_STATUS_ROLES[ns];
      if (ns && (allowed ? !allowed.includes(user.role) : !ADMINS.includes(user.role)))
        throw deny(`Role '${user.role}' may not set fund request status '${ns}'`);
    }
  }

  if (op === "DELETE") {
    await sbFetch(`/${table}?id=eq.${enc(id)}`, { method: "DELETE", prefer: "return=minimal" });
    await recordDelete(table, id, user.id);
  } else {
    const row = { ...toSnake(data), id, updated_at: new Date().toISOString() };
    await sbFetch(`/${table}`, { method: "POST", prefer: "resolution=merge-duplicates,return=minimal", body: JSON.stringify(row) });
  }
  await logAudit(user.id, op === "DELETE" ? "DELETE" : "SAVE", table, id, op === "DELETE" ? null : data);
}

// ── Auth routes ───────────────────────────────────────────────────────
const profileOut = (p, email) => ({
  id: p.id, email, name: p.name, role: p.role, cwsAccess: p.cws_access || [],
  machineId: p.machine_id || null, avatar: p.avatar || (email || "??").slice(0, 2).toUpperCase(), active: p.active !== false,
});

app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body || {};
  if (typeof email !== "string" || typeof password !== "string" || !email || !password)
    return res.status(400).json({ error: "Email and password required" });
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
      method: "POST", headers: { apikey: ANON_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.access_token) return res.status(401).json({ error: "Invalid email or password" });
    const p = (await sbFetch(`/profiles?id=eq.${data.user.id}&select=*`))?.[0];
    if (!p || !ROLES.includes(p.role)) return res.status(403).json({ error: "No profile for this account — contact an administrator" });
    if (p.active === false) return res.status(403).json({ error: "Account disabled" });
    res.json({ token: data.access_token, refresh_token: data.refresh_token, expires_in: data.expires_in,
               user: profileOut({ ...p, id: data.user.id }, data.user.email) });
  } catch (e) { console.error("[login] error:", errMsg(e)); res.status(500).json({ error: "Login failed" }); }
});

app.get("/api/auth/me", auth, (req, res) => {
  const u = req.user;
  res.json({ id: u.id, email: u.email, name: u.name, role: u.role, cwsAccess: u.cwsAccess,
             machineId: u.machineId || null, avatar: u.avatar || (u.email || "??").slice(0, 2).toUpperCase(), active: true });
});

app.post("/api/auth/refresh", async (req, res) => {
  const { refresh_token } = req.body || {};
  if (!refresh_token) return res.status(400).json({ error: "refresh_token required" });
  try {
    const r = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=refresh_token`, {
      method: "POST", headers: { apikey: ANON_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token }),
    });
    const data = await r.json().catch(() => ({}));
    if (!r.ok || !data.access_token) return res.status(401).json({ error: "Session expired" });
    res.json({ token: data.access_token, refresh_token: data.refresh_token, expires_in: data.expires_in });
  } catch { res.status(500).json({ error: "Refresh failed" }); }
});

// ── Users ─────────────────────────────────────────────────────────────
const randomPassword = () => crypto.randomBytes(9).toString("base64url");
const PRIVILEGED = ["sudo", "md", "admin"];

async function createUser(req, res) {
  const { name, email, password, role = "clerk", cwsAccess = [], machineId, avatar } = req.body || {};
  if (!name || !email) return res.status(400).json({ error: "name and email required" });
  if (!ROLES.includes(role)) return res.status(400).json({ error: "Invalid role" });
  if (PRIVILEGED.includes(role) && req.user.role !== "sudo")
    return res.status(403).json({ error: "Only sudo can create sudo/md/admin accounts" });
  if (password && String(password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  const pw = password || randomPassword();
  const av = avatar || String(name).slice(0, 2).toUpperCase();
  try {
    const authUser = await sbAuth("/admin/users", { email, password: pw, email_confirm: true, user_metadata: { name, avatar: av } });
    await sbFetch("/profiles", { method: "POST", prefer: "return=minimal", body: JSON.stringify({
      id: authUser.id, name, email, role, cws_access: Array.isArray(cwsAccess) ? cwsAccess : [],
      machine_id: machineId || null, avatar: av, active: true }) });
    await logAudit(req.user.id, "CREATE_USER", "profiles", authUser.id, { email, role });
    res.status(201).json({ ok: true, id: authUser.id, ...(password ? {} : { tempPassword: pw }) });
  } catch (e) { fail(res, e); }
}
app.post("/api/auth/signup", auth, requireRoles(...ADMINS), createUser);   // no longer public
app.post("/api/users",       auth, requireRoles(...ADMINS), createUser);

app.get("/api/users", auth, async (req, res) => {
  try {
    const rows = await sbFetch("/profiles?select=id,name,email,role,cws_access,machine_id,avatar,created_at,updated_at,active&order=name");
    res.json(rows.map(toCamel));
  } catch (e) { fail(res, e); }
});

app.put("/api/users/:id", auth, async (req, res) => {
  try {
    const { name, role, cwsAccess, machineId, avatar, active, email, password } = req.body || {};
    const isAdmin = ADMINS.includes(req.user.role);
    const paramId = req.params.id;

    let targetId = null;
    if (UUID_RE.test(paramId)) targetId = paramId;
    else if (email) {
      const r = await sbFetch(`/profiles?email=eq.${enc(String(email))}&select=id`);
      if (!r?.length) return res.status(404).json({ error: "Profile not found" });
      targetId = r[0].id;
    } else return res.status(400).json({ error: "Provide a user UUID or email" });

    const isSelf = targetId === req.user.id;
    if (!isSelf && !isAdmin) return res.status(403).json({ error: "Forbidden" });

    const target = (await sbFetch(`/profiles?id=eq.${targetId}&select=role`))?.[0];
    if (!target) return res.status(404).json({ error: "Profile not found" });
    if (PRIVILEGED.includes(target.role) && req.user.role !== "sudo" && !isSelf)
      return res.status(403).json({ error: "Only sudo can modify sudo/md/admin accounts" });

    const payload = { updated_at: new Date().toISOString() };
    if (name != null)   payload.name = name;
    if (avatar != null) payload.avatar = avatar;
    if (isAdmin) {                                   // privileged fields: admins only, never self-service
      if (role != null) {
        if (!ROLES.includes(role)) return res.status(400).json({ error: "Invalid role" });
        if (PRIVILEGED.includes(role) && req.user.role !== "sudo") return res.status(403).json({ error: "Only sudo can grant sudo/md/admin" });
        if (isSelf && role !== target.role) return res.status(403).json({ error: "You cannot change your own role" });
        payload.role = role;
      }
      if (cwsAccess !== undefined) payload.cws_access = Array.isArray(cwsAccess) ? cwsAccess : [];
      if (machineId !== undefined) payload.machine_id = machineId || null;
      if (active !== undefined) {
        if (isSelf && active === false) return res.status(400).json({ error: "You cannot deactivate yourself" });
        payload.active = !!active;
      }
    }
    await sbFetch(`/profiles?id=eq.${targetId}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify(payload) });
    if (password) {
      if (String(password).trim().length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
      await sbAuth(`/admin/users/${targetId}`, { password: String(password).trim() }, "PUT");
    }
    authCache.clear();                               // role/active changes apply immediately
    await logAudit(req.user.id, "UPDATE_USER", "profiles", targetId, { ...payload, password: password ? "***" : undefined });
    res.json({ ok: true, supabaseId: targetId });
  } catch (e) { fail(res, e); }
});

app.post("/api/seed-profiles", auth, requireRoles("sudo"), async (req, res) => {
  const { users } = req.body || {};
  if (!Array.isArray(users)) return res.status(400).json({ error: "users[] required" });
  const results = [];
  for (const u of users) {
    try {
      if (!u?.email || !ROLES.includes(u.role)) { results.push({ email: u?.email, ok: false, error: "invalid user" }); continue; }
      const ex = await sbFetch(`/profiles?email=eq.${enc(u.email)}&select=id`);
      const base = { name: u.name, role: u.role, cws_access: u.cwsAccess || [], machine_id: u.machineId || null,
                     avatar: u.avatar || String(u.name || "?").slice(0, 2).toUpperCase(), updated_at: new Date().toISOString() };
      if (ex?.length) {
        await sbFetch(`/profiles?id=eq.${ex[0].id}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify({ ...base, active: u.active !== false }) });
        results.push({ email: u.email, ok: true, action: "updated" });
      } else {
        const pw = u.password && String(u.password).length >= 8 ? u.password : randomPassword();
        const a = await sbAuth("/admin/users", { email: u.email, password: pw, email_confirm: true, user_metadata: { name: u.name, avatar: base.avatar } });
        await sbFetch("/profiles", { method: "POST", prefer: "return=minimal", body: JSON.stringify({ id: a.id, email: u.email, ...base, active: true }) });
        results.push({ email: u.email, ok: true, action: "created" });
      }
    } catch (e) { results.push({ email: u?.email, ok: false, error: errMsg(e) }); }
  }
  res.json({ ok: true, results });
});

// ── Generic CRUD (permission + station scoped) ────────────────────────
TABLES.forEach(table => {
  const route = `/api/${table.replace(/_/g, "-")}`;
  const guardRead = (req, res, next) => canRead(req.user.role, table) ? next() : res.status(403).json({ error: `Role '${req.user.role}' may not read ${table}` });

  app.get(route, auth, guardRead, async (req, res) => {
    try {
      const sf = scopeFilter(req.user, table);
      if (sf === false) return res.json([]);
      const parts = ["order=updated_at.asc,id.asc"];
      if (sf) parts.push(sf);
      if (req.query.since) parts.push(`updated_at=gte.${enc(String(req.query.since))}`);
      res.json(visibleRows(req.user, table, await sbFetch(`/${table}?${parts.join("&")}`)).map(toCamel));
    } catch (e) { fail(res, e); }
  });

  app.get(`${route}/:id`, auth, guardRead, async (req, res) => {
    if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
    try {
      const sf = scopeFilter(req.user, table);
      if (sf === false) return res.status(404).json({ error: "Not found" });
      const rows = await sbFetch(`/${table}?id=eq.${enc(req.params.id)}${sf ? "&" + sf : ""}`);
      const vis = visibleRows(req.user, table, rows);
      if (!vis.length) return res.status(404).json({ error: "Not found" });
      res.json(toCamel(vis[0]));
    } catch (e) { fail(res, e); }
  });

  app.post(route, auth, async (req, res) => {
    try {
      const id = req.body?.id;
      if (!id) return res.status(400).json({ error: "id required" });
      await applyWrite(req.user, table, "SAVE", id, req.body);
      res.json({ ok: true, id });
    } catch (e) { fail(res, e); }
  });

  app.put(`${route}/:id`, auth, async (req, res) => {
    try {
      await applyWrite(req.user, table, "SAVE", req.params.id, { ...req.body, id: req.params.id });
      res.json({ ok: true });
    } catch (e) { fail(res, e); }
  });

  app.delete(`${route}/:id`, auth, async (req, res) => {
    try { await applyWrite(req.user, table, "DELETE", req.params.id, null); res.json({ ok: true }); }
    catch (e) { fail(res, e); }
  });
});

// ── Batch sync (offline queue) — per-operation results ────────────────
app.post("/api/sync", auth, async (req, res) => {
  const { operations } = req.body || {};
  if (!Array.isArray(operations)) return res.status(400).json({ error: "operations[] required" });
  if (operations.length > 500) return res.status(413).json({ error: "Too many operations in one request (max 500)" });
  const results = [];
  for (const op of operations) {
    const { table, method, data } = op || {};
    const id = op?.id ?? data?.id;
    try {
      if (!TABLES.includes(table)) throw deny(`Unknown table: ${table}`, 400);
      const m = String(method || "SAVE").toUpperCase();
      await applyWrite(req.user, table, m === "DELETE" ? "DELETE" : "SAVE", id, m === "DELETE" ? null : { ...(data || {}), id });
      results.push({ id, ok: true });
    } catch (e) {
      console.warn(`[sync] ${op?.method} ${op?.table} ${id} rejected: ${errMsg(e)}`);
      results.push({ id, ok: false, status: httpStatus(e), error: errMsg(e) });
    }
  }
  const failed = results.filter(r => !r.ok).length;
  res.json({ ok: failed === 0, synced: results.length - failed, failed, results });
});

// ── Delta pull (permission-filtered, stable paging, delete tombstones) ─
async function fetchAllRows(table, since, sf) {
  const PAGE = 1000, all = [];
  for (let offset = 0; ; offset += PAGE) {
    const q = [`updated_at=gte.${enc(since)}`, "order=updated_at.asc,id.asc", `limit=${PAGE}`, `offset=${offset}`];
    if (sf) q.push(sf);
    const rows = await sbFetch(`/${table}?${q.join("&")}`);
    if (!Array.isArray(rows) || !rows.length) break;
    all.push(...rows);
    if (rows.length < PAGE) break;
  }
  return all;
}
app.get("/api/pull", auth, async (req, res) => {
  const since = req.query.since || "1970-01-01T00:00:00.000Z";
  if (Number.isNaN(Date.parse(since))) return res.status(400).json({ error: "Invalid 'since'" });
  const delta = {}, deleted = {}, errors = [];
  await Promise.all(TABLES.map(async t => {
    if (!canRead(req.user.role, t)) { delta[t] = []; return; }
    const sf = scopeFilter(req.user, t);
    if (sf === false) { delta[t] = []; return; }
    try { delta[t] = visibleRows(req.user, t, await fetchAllRows(t, since, sf)).map(toCamel); }
    catch (e) { delta[t] = []; errors.push(t); console.warn(`[pull] ${t} failed: ${errMsg(e)}`); }
  }));
  try {
    const tombs = await sbFetch(`/deleted_records?deleted_at=gte.${enc(since)}&select=table_name,record_id&limit=5000`);
    for (const d of tombs || []) if (canRead(req.user.role, d.table_name)) (deleted[d.table_name] ||= []).push(d.record_id);
  } catch { /* table not created yet */ }
  res.json({ since, pulledAt: new Date().toISOString(), delta, deleted, ...(errors.length ? { partial: errors } : {}) });
});

// ── System config ─────────────────────────────────────────────────────
app.get("/api/system", auth, async (req, res) => {
  try {
    const cfg = {};
    (await sbFetch("/system_config?select=key,value")).forEach(r => { try { cfg[r.key] = JSON.parse(r.value); } catch { cfg[r.key] = r.value; } });
    res.json(cfg);
  } catch (e) { fail(res, e); }
});
app.put("/api/system", auth, requireRoles("sudo"), async (req, res) => {
  const b = req.body;
  if (!b || typeof b !== "object" || Array.isArray(b) || Object.keys(b).length > 100) return res.status(400).json({ error: "Invalid config" });
  try {
    const rows = Object.entries(b).map(([key, value]) => ({ key, value: JSON.stringify(value), updated_at: new Date().toISOString() }));
    await sbFetch("/system_config", { method: "POST", prefer: "resolution=merge-duplicates,return=minimal", body: JSON.stringify(rows) });
    await logAudit(req.user.id, "SYSTEM_CONFIG", "system_config", "", Object.keys(b));
    res.json({ ok: true });
  } catch (e) { fail(res, e); }
});

// ── Audit log ─────────────────────────────────────────────────────────
app.get("/api/audit", auth, requireRoles("sudo", "md", "admin"), async (req, res) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 500, 1), 2000);
    const t = req.query.table;
    if (t && !TABLES.includes(t) && !["profiles", "system_config"].includes(t)) return res.status(400).json({ error: "Invalid table" });
    res.json(await sbFetch(`/audit_log?order=created_at.desc&limit=${limit}${t ? `&table_name=eq.${enc(t)}` : ""}`));
  } catch (e) { fail(res, e); }
});

// ── MD Loans (sudo, md, hq_finance, hq_accountant) ─────────────────────
const LOAN_COLS = ["borrower_name","phone","email","address","category","affiliation","amount","currency","interest_rate",
  "interest_type","issued_date","due_date","purpose","collateral","witness_name","witness_phone","notes"];
const REPAY_COLS = ["amount","date","method","reference","notes"];
function loanCalc(l, repayments) {
  const principal = +l.amount || 0, rate = +l.interest_rate || 0;
  let interest = 0;
  if (rate > 0) {
    if (l.interest_type === "flat") interest = principal * rate / 100;
    else {
      const months = l.due_date && l.issued_date ? Math.max(1, Math.round((new Date(l.due_date) - new Date(l.issued_date)) / 2592000000)) : 1;
      interest = principal * Math.pow(1 + rate / 100, months) - principal;
    }
  }
  const repaid = repayments.reduce((s, r) => s + (+r.amount || 0), 0);
  const balance = Math.max(0, principal + interest - repaid);
  const status = balance <= 0 ? "settled" : (l.due_date && new Date(l.due_date) < new Date() ? "overdue" : "active");
  return { balance, total_repaid: repaid, status };
}
// Loans: sudo, md, hq_finance and hq_accountant may all view AND manage
// (every mutating route below re-checks requireRoles(...LOAN_MANAGERS) explicitly).
const LOAN_VIEWERS = [...OWNERS, "hq_finance", "hq_accountant"];
const LOAN_MANAGERS = LOAN_VIEWERS;
const loans = express.Router();
app.use("/api/loans", auth, requireRoles(...LOAN_VIEWERS), loans);

loans.get("/", async (req, res) => {
  try {
    const [ls, rs] = await Promise.all([sbFetch("/loans?order=updated_at.desc"), sbFetch("/loan_repayments?order=date.asc,created_at.asc")]);
    const by = {}; rs.forEach(r => (by[r.loan_id] ||= []).push(r));
    res.json(ls.map(l => ({ ...l, repayments: by[l.id] || [], ...loanCalc(l, by[l.id] || []) })));
  } catch (e) { fail(res, e); }
});
const saveLoan = async (req, res) => {
  const id = req.params.id || req.body?.id || crypto.randomUUID();
  if (!isSafeId(id)) return res.status(400).json({ error: "Invalid id" });
  const b = pick(toSnake(req.body || {}), LOAN_COLS);
  if (!req.params.id && (!b.borrower_name || !(+b.amount > 0) || !b.issued_date)) return res.status(400).json({ error: "borrower name, amount and issued date are required" });
  try {
    b.updated_at = new Date().toISOString();
    if (req.params.id) await sbFetch(`/loans?id=eq.${enc(id)}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify(b) });
    else await sbFetch("/loans", { method: "POST", prefer: "return=minimal", body: JSON.stringify({ ...b, id, created_by: req.user.id }) });
    await logAudit(req.user.id, req.params.id ? "UPDATE" : "CREATE", "loans", id, b);
    res.status(req.params.id ? 200 : 201).json({ ok: true, id });
  } catch (e) { fail(res, e); }
};
loans.post("/", requireRoles(...LOAN_MANAGERS), saveLoan);
loans.put("/:id", requireRoles(...LOAN_MANAGERS), saveLoan);
loans.delete("/:id", requireRoles(...LOAN_MANAGERS), async (req, res) => {
  if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
  try { await sbFetch(`/loans?id=eq.${enc(req.params.id)}`, { method: "DELETE", prefer: "return=minimal" });
        await logAudit(req.user.id, "DELETE", "loans", req.params.id, null); res.json({ ok: true }); }
  catch (e) { fail(res, e); }
});
async function loanSummary(loanId) {
  const [l, rs] = await Promise.all([sbFetch(`/loans?id=eq.${enc(loanId)}`), sbFetch(`/loan_repayments?loan_id=eq.${enc(loanId)}`)]);
  if (!l.length) throw deny("Loan not found", 404);
  const { balance, status } = loanCalc(l[0], rs);
  return { balance, status };
}
loans.post("/:id/repayments", requireRoles(...LOAN_MANAGERS), async (req, res) => {
  const loanId = req.params.id, rid = req.body?.id || crypto.randomUUID();
  if (!isSafeId(loanId) || !isSafeId(rid)) return res.status(400).json({ error: "Invalid id" });
  const b = pick(req.body || {}, REPAY_COLS);
  if (!(+b.amount > 0) || !b.date) return res.status(400).json({ error: "amount and date are required" });
  try {
    const before = await loanSummary(loanId);
    if (+b.amount > before.balance + 0.01) return res.status(400).json({ error: "Amount exceeds outstanding balance" });
    await sbFetch("/loan_repayments", { method: "POST", prefer: "return=minimal", body: JSON.stringify({ ...b, id: rid, loan_id: loanId, recorded_by: req.user.id }) });
    await logAudit(req.user.id, "CREATE", "loan_repayments", rid, { loanId, ...b });
    res.status(201).json({ ok: true, id: rid, ...(await loanSummary(loanId)) });
  } catch (e) { fail(res, e); }
});
loans.delete("/:id/repayments/:rid", requireRoles(...LOAN_MANAGERS), async (req, res) => {
  const { id: loanId, rid } = req.params;
  if (!isSafeId(loanId) || !isSafeId(rid)) return res.status(400).json({ error: "Invalid id" });
  try {
    await sbFetch(`/loan_repayments?id=eq.${enc(rid)}&loan_id=eq.${enc(loanId)}`, { method: "DELETE", prefer: "return=minimal" });
    await logAudit(req.user.id, "DELETE", "loan_repayments", rid, null);
    res.json({ ok: true, ...(await loanSummary(loanId)) });
  } catch (e) { fail(res, e); }
});

// ── Export contracts (sudo + md only) ─────────────────────────────────
const CONTRACT_COLS = ["contract_ref","company_name","company_country","contact_person","contact_email","contact_phone","grade",
  "agreed_tonnes","rate_per_kg","currency","total_value","contract_date","delivery_date","delivery_port","payment_terms","status","notes"];
const DELIV_COLS = ["delivered_tonnes","grade","shipment_ref","bl_number","date","notes","recorded_at"];
const contracts = express.Router();
app.use("/api/contracts", auth, requireRoles(...OWNERS), contracts);

contracts.get("/", async (req, res) => {
  try { res.json((await sbFetch("/contracts?order=contract_date.desc,created_at.desc")).map(toCamel)); }
  catch (e) { fail(res, e); }
});
const saveContract = async (req, res) => {
  const id = req.params.id || req.body?.id || crypto.randomUUID();
  if (!isSafeId(id)) return res.status(400).json({ error: "Invalid id" });
  const b = pick(toSnake(req.body || {}), CONTRACT_COLS);
  if (!req.params.id && (!b.company_name || !(+b.agreed_tonnes > 0) || !(+b.rate_per_kg > 0) || !b.contract_date))
    return res.status(400).json({ error: "company, tonnes, rate and contract date are required" });
  try {
    b.updated_at = new Date().toISOString();
    if (req.params.id) await sbFetch(`/contracts?id=eq.${enc(id)}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify(b) });
    else await sbFetch("/contracts", { method: "POST", prefer: "return=minimal", body: JSON.stringify({ ...b, id, created_by: req.user.id }) });
    await logAudit(req.user.id, req.params.id ? "UPDATE" : "CREATE", "contracts", id, b);
    res.status(req.params.id ? 200 : 201).json({ ok: true, id });
  } catch (e) { fail(res, e); }
};
contracts.post("/", saveContract);
contracts.put("/:id", saveContract);
contracts.delete("/:id", async (req, res) => {
  if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
  try { await sbFetch(`/contracts?id=eq.${enc(req.params.id)}`, { method: "DELETE", prefer: "return=minimal" });
        await logAudit(req.user.id, "DELETE", "contracts", req.params.id, null); res.json({ ok: true }); }
  catch (e) { fail(res, e); }
});
const delivOut = r => ({ ...toCamel(r), bl_number: r.bl_number });   // UI reads d.bl_number
contracts.get("/:id/deliveries", async (req, res) => {
  if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
  try { res.json((await sbFetch(`/contract_deliveries?contract_id=eq.${enc(req.params.id)}&order=date.asc,created_at.asc`)).map(delivOut)); }
  catch (e) { fail(res, e); }
});
contracts.post("/:id/deliveries", async (req, res) => {
  const cid = req.params.id, did = req.body?.id || crypto.randomUUID();
  if (!isSafeId(cid) || !isSafeId(did)) return res.status(400).json({ error: "Invalid id" });
  const b = pick(toSnake(req.body || {}), DELIV_COLS);
  if (!(+b.delivered_tonnes > 0) || !b.date) return res.status(400).json({ error: "delivered tonnes and date are required" });
  try {
    const [c, ds] = await Promise.all([sbFetch(`/contracts?id=eq.${enc(cid)}&select=agreed_tonnes`), sbFetch(`/contract_deliveries?contract_id=eq.${enc(cid)}&select=delivered_tonnes`)]);
    if (!c.length) return res.status(404).json({ error: "Contract not found" });
    const pending = (+c[0].agreed_tonnes || 0) - ds.reduce((s, d) => s + (+d.delivered_tonnes || 0), 0);
    if (+b.delivered_tonnes > pending + 0.001) return res.status(400).json({ error: `Exceeds pending quantity (${pending.toFixed(3)} T)` });
    await sbFetch("/contract_deliveries", { method: "POST", prefer: "return=minimal",
      body: JSON.stringify({ ...b, id: did, contract_id: cid, recorded_by: req.user.id, recorded_at: b.recorded_at || new Date().toISOString() }) });
    await logAudit(req.user.id, "CREATE", "contract_deliveries", did, { contractId: cid, ...b });
    res.status(201).json({ ok: true, id: did });
  } catch (e) { fail(res, e); }
});
contracts.delete("/:id/deliveries/:did", async (req, res) => {
  const { id: cid, did } = req.params;
  if (!isSafeId(cid) || !isSafeId(did)) return res.status(400).json({ error: "Invalid id" });
  try { await sbFetch(`/contract_deliveries?id=eq.${enc(did)}&contract_id=eq.${enc(cid)}`, { method: "DELETE", prefer: "return=minimal" });
        await logAudit(req.user.id, "DELETE", "contract_deliveries", did, null); res.json({ ok: true }); }
  catch (e) { fail(res, e); }
});

// ── Coffee market feed (no data provider configured) ──────────────────
// The UI already handles failure and offers a manual price field.
app.get("/api/market/coffee", auth, (req, res) =>
  res.status(501).json({ error: "Live coffee price feed is not configured. Enter the price manually." }));

// ── Chat ──────────────────────────────────────────────────────────────
// Auto rooms (hq_general, station_<cws>, driver_<id>) are built client-side and have no chat_rooms row;
// their access rules are derived here. Custom rooms use chat_rooms.member_ids.
async function canAccessRoom(user, roomId) {
  if (!isSafeId(roomId)) return false;
  if (ADMINS.includes(user.role)) return true;
  if (roomId === "hq_general") return HQ.includes(user.role);
  if (roomId.startsWith("station_")) return HQ.includes(user.role) || user.cwsAccess.includes(roomId.slice(8));
  if (roomId.startsWith("driver_")) return HQ.includes(user.role) || roomId === `driver_${user.id}`;
  const r = await sbFetch(`/chat_rooms?id=eq.${enc(roomId)}&select=member_ids`);
  return !!r[0] && (r[0].member_ids || []).includes(user.id);
}
const roomOut = r => ({ ...r, memberIds: r.member_ids || [] });

app.get("/api/chat/rooms", auth, async (req, res) => {
  try {
    const rows = await sbFetch("/chat_rooms?select=*&order=created_at.asc");
    res.json(rows.filter(r => ADMINS.includes(req.user.role) || (r.member_ids || []).includes(req.user.id)).map(roomOut));
  } catch (e) { fail(res, e); }
});
app.post("/api/chat/rooms", auth, requireRoles(...ADMINS), async (req, res) => {
  try {
    const b = req.body || {};
    const id = b.id || crypto.randomUUID();
    if (!isSafeId(id) || !b.name) return res.status(400).json({ error: "valid id and name required" });
    const row = { id, name: String(b.name).slice(0, 80), icon: b.icon || "💬", type: b.type || "custom", color: b.color || "#9A5EE0",
                  member_ids: b.memberIds || b.member_ids || [], created_by: req.user.id };
    await sbFetch("/chat_rooms", { method: "POST", prefer: "return=minimal", body: JSON.stringify(row) });
    res.status(201).json(roomOut(row));
  } catch (e) { fail(res, e); }
});
app.put("/api/chat/rooms/:id", auth, requireRoles(...ADMINS), async (req, res) => {
  if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
  try {
    const m = req.body?.memberIds || req.body?.member_ids;
    if (!Array.isArray(m)) return res.status(400).json({ error: "memberIds[] required" });
    await sbFetch(`/chat_rooms?id=eq.${enc(req.params.id)}`, { method: "PATCH", prefer: "return=minimal", body: JSON.stringify({ member_ids: m, updated_at: new Date().toISOString() }) });
    res.json({ ok: true });
  } catch (e) { fail(res, e); }
});
app.delete("/api/chat/rooms/:id", auth, requireRoles(...ADMINS), async (req, res) => {
  if (!isSafeId(req.params.id)) return res.status(400).json({ error: "Invalid id" });
  try {
    await sbFetch(`/chat_messages?room_id=eq.${enc(req.params.id)}`, { method: "DELETE", prefer: "return=minimal" });
    await sbFetch(`/chat_rooms?id=eq.${enc(req.params.id)}`, { method: "DELETE", prefer: "return=minimal" });
    res.json({ ok: true });
  } catch (e) { fail(res, e); }
});
app.get("/api/chat/rooms/:id/messages", auth, async (req, res) => {
  try {
    if (!(await canAccessRoom(req.user, req.params.id))) return res.status(403).json({ error: "Not a member of this room" });
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 100, 1), 200);
    const rows = await sbFetch(`/chat_messages?room_id=eq.${enc(req.params.id)}&order=created_at.desc&limit=${limit}`);
    res.json(rows.reverse().map(m => ({ id: m.id, roomId: m.room_id, senderId: m.sender_id, senderName: m.sender_name,
      senderRole: m.sender_role, senderAvatar: m.sender_avatar || "", text: m.text, ts: new Date(m.created_at).getTime(), createdAt: m.created_at })));
  } catch (e) { fail(res, e); }
});
app.post("/api/chat/rooms/:id/messages", auth, async (req, res) => {
  try {
    if (!(await canAccessRoom(req.user, req.params.id))) return res.status(403).json({ error: "Not a member of this room" });
    const text = String(req.body?.text ?? "").trim();
    if (!text || text.length > 4000) return res.status(400).json({ error: "Message must be 1–4000 characters" });
    const id = req.body?.id && isSafeId(req.body.id) ? req.body.id : crypto.randomUUID();
    // sender identity always comes from the authenticated user — never from the request body
    await sbFetch("/chat_messages", { method: "POST", prefer: "resolution=ignore-duplicates,return=minimal", body: JSON.stringify({
      id, room_id: req.params.id, sender_id: req.user.id, sender_name: req.user.name, sender_role: req.user.role,
      sender_avatar: req.user.avatar || "", text }) });
    res.status(201).json({ ok: true, id });
  } catch (e) { fail(res, e); }
});

// ── Health ────────────────────────────────────────────────────────────
app.get("/api/health", (_, res) => res.json({ ok: true, time: new Date().toISOString() }));
app.all("/api/*", (req, res) => res.status(404).json({ error: "Not found" }));   // never return HTML for API typos

// ── Static PWA files ──────────────────────────────────────────────────
// HTML/JS/manifest revalidate on every load (cheap 304s) so deploys reach users immediately.
app.use(express.static(PUBLIC_DIR, {
  etag: true,
  setHeaders(res, filePath) {
    if (/\.(html|js|json)$/.test(filePath)) res.setHeader("Cache-Control", "no-cache");
    else res.setHeader("Cache-Control", "public, max-age=86400");
    if (filePath.endsWith("sw.js")) res.setHeader("Service-Worker-Allowed", "/");
  },
}));
app.get("*", (_, res) => res.sendFile(path.join(PUBLIC_DIR, "index.html")));

// ── Error handling ────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err?.type === "entity.parse.failed") return res.status(400).json({ error: "Invalid JSON" });
  if (err?.type === "entity.too.large")    return res.status(413).json({ error: "Payload too large" });
  console.error("[unhandled]", err); res.status(500).json({ error: "Server error" });
});
process.on("unhandledRejection", e => console.error("[unhandledRejection]", e));

app.listen(PORT, () => console.log(`Bender Exports server v2.1 listening on :${PORT}`));
