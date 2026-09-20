/**
 * HostPilot Phase 2 — Backend API (Node HTTP natif)
 * Multi-tenant · Auth JWT · DB fichier JSON persistante
 * Aucune dépendance native requise (bcryptjs si dispo, sinon crypto)
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

/** Charge .env local si présent (pas de dépendance dotenv) — n'écrase pas l'env process */
function loadEnvFile() {
  try {
    const envPath = path.join(__dirname, '../.env');
    if (!fs.existsSync(envPath)) return;
    const lines = fs.readFileSync(envPath, 'utf8').split(/\r?\n/);
    for (const line of lines) {
      const t = line.trim();
      if (!t || t.startsWith('#')) continue;
      const i = t.indexOf('=');
      if (i < 1) continue;
      const key = t.slice(0, i).trim();
      let val = t.slice(i + 1).trim();
      if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) val = val.slice(1, -1);
      if (process.env[key] === undefined) process.env[key] = val;
    }
  } catch (e) {
    console.warn('[env]', e.message);
  }
}
loadEnvFile();

/** Chiffrement tokens OAuth (AES-256-GCM). Clé: OAUTH_ENCRYPTION_KEY (32 bytes hex ou string) */
function getOauthKey() {
  const raw = process.env.OAUTH_ENCRYPTION_KEY || '';
  if (!raw || raw.length < 16) return null;
  return crypto.createHash('sha256').update(raw).digest(); // 32 bytes
}
function encryptSecret(plain) {
  if (plain == null || plain === '') return null;
  const key = getOauthKey();
  if (!key) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const enc = Buffer.concat([cipher.update(String(plain), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return 'v1:' + iv.toString('base64') + ':' + tag.toString('base64') + ':' + enc.toString('base64');
}
function decryptSecret(blob) {
  if (!blob) return null;
  if (!String(blob).startsWith('v1:')) return null; // refuse plaintext tokens
  const key = getOauthKey();
  if (!key) return null;
  try {
    const parts = String(blob).split(':');
    if (parts.length !== 4) return null;
    const iv = Buffer.from(parts[1], 'base64');
    const tag = Buffer.from(parts[2], 'base64');
    const data = Buffer.from(parts[3], 'base64');
    const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}
function oauthCryptoReady() {
  return !!getOauthKey();
}



const PORT = process.env.PORT || 3001;
const DATA_FILE = path.join(__dirname, '../data/db.json');
const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const WEAK_JWT = new Set(['', 'change-me', 'secret', 'hostpilot-dev-secret-change-me-in-prod', 'CHANGE_ME_WITH_A_LONG_RANDOM_SECRET']);
let JWT_SECRET = process.env.JWT_SECRET || '';
if (!JWT_SECRET || WEAK_JWT.has(JWT_SECRET) || JWT_SECRET.length < 32) {
  if (IS_PROD) {
    console.error('FATAL: JWT_SECRET manquant, trop court (<32) ou valeur faible. Définissez un secret long aléatoire.');
    process.exit(1);
  }
  JWT_SECRET = JWT_SECRET || 'hostpilot-dev-secret-change-me-in-prod';
  if (WEAK_JWT.has(JWT_SECRET) || JWT_SECRET.length < 32) {
    console.warn('⚠️  JWT_SECRET faible ou absent — acceptable en développement uniquement');
  }
}
const PUBLIC_DIR = path.join(__dirname, '../public');

// ─── Minimal bcrypt-compatible hash (scrypt) ───────────────────
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `scrypt:${salt}:${hash}`;
}
function verifyPassword(password, stored) {
  try {
    if (stored.startsWith('scrypt:')) {
      const [, salt, hash] = stored.split(':');
      const test = crypto.scryptSync(password, salt, 64).toString('hex');
      return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(test, 'hex'));
    }
    // fallback bcryptjs if available
    try {
      const bcrypt = require('bcryptjs');
      return bcrypt.compareSync(password, stored);
    } catch { return false; }
  } catch { return false; }
}

function uid() {
  return crypto.randomBytes(12).toString('hex');
}

// ─── JWT simple (HMAC SHA256) ──────────────────────────────────
function b64url(buf) {
  return Buffer.from(buf).toString('base64url');
}
function signJWT(payload, expiresInSec = 7 * 24 * 3600) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const body = b64url(JSON.stringify({ ...payload, exp: Math.floor(Date.now() / 1000) + expiresInSec }));
  const sig = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}
function verifyJWT(token) {
  try {
    const [header, body, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', JWT_SECRET).update(`${header}.${body}`).digest('base64url');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

// ─── Database (JSON file, multi-tenant) ────────────────────────
function emptyDb() {
  return {
    users: [],
    organizations: [],
    organization_members: [],
    properties: [],
    property_knowledge: [],
    guests: [],
    reservations: [],
    conversations: [],
    messages: [],
    cleaning_tasks: [],
    cleaning_checklists: [],
    incidents: [],
    automations: [],
    automation_runs: [],
    notifications: [],
    audit_logs: [],
    subscriptions: [],
    integrations: [],
    jobs: [],
    checkin_tokens: [],
    cleaning_photos: [],
    notification_preferences: [],
    devices: [],
    stripe_events: [],
    pricing_history: [],
    review_requests: [],
    review_responses: [],
    reviews: [],
    onboarding_state: [],
    pricing_recommendations: [],
    pricing_rules: [],
    password_resets: [],
    notification_deliveries: [],
  };
}

function loadDb() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      return { ...emptyDb(), ...JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) };
    }
  } catch (e) {
    console.error('DB load error', e.message);
  }
  return emptyDb();
}


function rotateBackup() {
  try {
    if (!fs.existsSync(DATA_FILE)) return;
    const dir = path.join(path.dirname(DATA_FILE), 'backups');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    const ts = new Date().toISOString().replace(/[:.]/g, '-');
    const dest = path.join(dir, 'db-' + ts + '.json');
    fs.copyFileSync(DATA_FILE, dest);
    const files = fs.readdirSync(dir).filter(f => f.startsWith('db-') && f.endsWith('.json')).sort().reverse();
    for (const f of files.slice(14)) {
      try { fs.unlinkSync(path.join(dir, f)); } catch (_) {}
    }
    console.log('[backup]', dest);
  } catch (e) {
    console.error('[backup]', e.message);
  }
}

function saveDb(db) {
  const dir = path.dirname(DATA_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const tmp = DATA_FILE + '.tmp';
  const payload = JSON.stringify(db, null, 2);
  try {
    fs.writeFileSync(tmp, payload);
    try {
      fs.renameSync(tmp, DATA_FILE);
    } catch (e) {
      fs.writeFileSync(DATA_FILE, payload);
      try { fs.unlinkSync(tmp); } catch (_) {}
    }
    // Backup rotatif (dernier snapshot)
    try {
      const bak = DATA_FILE + '.bak';
      fs.writeFileSync(bak, payload);
    } catch (_) {}
  } catch (e) {
    console.error('[saveDb]', e.message);
    try { fs.writeFileSync(DATA_FILE, payload); } catch (e2) { console.error('[saveDb-fallback]', e2.message); }
  }
}

let DB = loadDb();

function audit(orgId, userId, action, entityType, entityId, metadata) {
  DB.audit_logs.push({
    id: uid(),
    organization_id: orgId || null,
    user_id: userId || null,
    action,
    entity_type: entityType || null,
    entity_id: entityId || null,
    metadata: metadata || null,
    created_at: new Date().toISOString(),
  });
  saveDb(DB);
}


const rateBuckets = new Map();
const loginFailures = new Map();
function rateLimit(key, limit, windowMs) {
  const now = Date.now();
  let b = rateBuckets.get(key);
  if (!b || now > b.reset) b = { count: 0, reset: now + windowMs };
  b.count++;
  rateBuckets.set(key, b);
  return b.count <= limit;
}
function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
}

function corsOrigin(req) {
  const configured = (process.env.CORS_ORIGIN || '').trim();
  const reqOrigin = req.headers.origin || '';
  if (IS_PROD) {
    if (!configured || configured === '*') {
      // Strict: no wildcard in production — echo APP_URL origin if set
      try {
        return process.env.APP_URL ? new URL(process.env.APP_URL).origin : 'null';
      } catch { return 'null'; }
    }
    // Allow comma-separated list
    const allowed = configured.split(',').map(x => x.trim()).filter(Boolean);
    if (reqOrigin && allowed.includes(reqOrigin)) return reqOrigin;
    return allowed[0] || 'null';
  }
  // Development
  if (!configured || configured === '*') return reqOrigin || '*';
  const allowed = configured.split(',').map(x => x.trim()).filter(Boolean);
  if (reqOrigin && allowed.includes(reqOrigin)) return reqOrigin;
  return allowed[0] || '*';
}


// ─── Helpers HTTP ──────────────────────────────────────────────
function resolveCorsHeader(req) {
  try {
    return corsOrigin(req || { headers: {} });
  } catch {
    return IS_PROD ? 'null' : '*';
  }
}

function json(res, status, data, req) {
  const body = JSON.stringify(data);
  const headers = {
    'Content-Type': 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Access-Control-Allow-Origin': resolveCorsHeader(req),
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
  };
  if (IS_PROD && process.env.CORS_ORIGIN && process.env.CORS_ORIGIN !== '*') {
    headers['Vary'] = 'Origin';
  }
  res.writeHead(status, headers);
  res.end(body);
}

function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', chunk => {
      chunks.push(chunk);
      if (chunks.reduce((n, c) => n + c.length, 0) > 2e6) reject(new Error('too large'));
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function readBody(req) {
  return readRawBody(req).then(buf => {
    const data = buf.toString('utf8');
    try { return data ? JSON.parse(data) : {}; }
    catch { throw new Error('JSON invalide'); }
  });
}

/** Vérification signature Stripe (HMAC SHA256) — https://stripe.com/docs/webhooks/signatures */
function verifyStripeSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;
  const parts = {};
  for (const item of String(signatureHeader).split(',')) {
    const [k, v] = item.split('=');
    if (k && v) {
      if (!parts[k]) parts[k] = [];
      parts[k].push(v);
    }
  }
  const timestamp = parts.t && parts.t[0];
  const v1list = parts.v1 || [];
  if (!timestamp || !v1list.length) return false;
  const age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > 300) return false; // 5 min tolerance
  const payload = timestamp + '.' + rawBody.toString('utf8');
  const expected = crypto.createHmac('sha256', secret).update(payload, 'utf8').digest('hex');
  return v1list.some(sig => {
    try {
      const a = Buffer.from(expected, 'hex');
      const b = Buffer.from(sig, 'hex');
      return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
  });
}

function getAuth(req) {
  const h = req.headers.authorization || '';
  if (!h.startsWith('Bearer ')) return null;
  return verifyJWT(h.slice(7));
}

function requireAuth(req, res) {
  const payload = getAuth(req);
  if (!payload || !payload.sub) {
    json(res, 401, { error: 'Non authentifié' });
    return null;
  }
  const user = DB.users.find(u => u.id === payload.sub);
  if (!user || user.status !== 'active') {
    json(res, 401, { error: 'Session invalide' });
    return null;
  }
  return user;
}

function getUserOrg(userId) {
  const membership = DB.organization_members.find(m => m.user_id === userId);
  if (!membership) return null;
  const org = DB.organizations.find(o => o.id === membership.organization_id);
  return org ? { org, role: membership.role } : null;
}

function requireOrg(user, res) {
  const ctx = getUserOrg(user.id);
  if (!ctx) {
    json(res, 403, { error: 'Aucune organisation' });
    return null;
  }
  return ctx;
}

function canAccessOrg(user, orgId) {
  return DB.organization_members.some(m => m.user_id === user.id && m.organization_id === orgId);
}

// ─── Automation engine ─────────────────────────────────────────

const AUTOMATION_EVENTS = [
  'RESERVATION_CREATED','RESERVATION_UPDATED','RESERVATION_CANCELLED',
  'CHECK_IN_APPROACHING','CHECK_IN_TODAY','CHECK_OUT_APPROACHING','CHECK_OUT_TODAY','CHECK_OUT_COMPLETED',
  'CLEANING_COMPLETED','CLEANING_PROBLEM_REPORTED','INCIDENT_CREATED','INCIDENT_RESOLVED',
  'GUEST_MESSAGE_RECEIVED','GUEST_MESSAGE_UNANSWERED','REVIEW_RECEIVED',
  'reservation.created','checkout.completed','cleaning.completed','incident.created'
];

function interpolate(template, ctx) {
  if (!template) return '';
  return String(template).replace(/\{\{(\w+)\}\}/g, (_, key) => {
    const v = ctx[key];
    return (v === undefined || v === null || v === 'undefined') ? '' : String(v);
  });
}

function buildVarContext(orgId, context) {
  const prop = context.property_id ? DB.properties.find(x => x.id === context.property_id) : null;
  const res = context.reservation_id ? DB.reservations.find(x => x.id === context.reservation_id) : null;
  const guest = res?.guest_id ? DB.guests.find(g => g.id === res.guest_id) : null;
  return {
    guest_first_name: guest?.first_name || context.guest_first_name || '',
    guest_last_name: guest?.last_name || '',
    property_name: prop?.name || '',
    property_address: prop?.address || '',
    check_in_date: res?.check_in || context.check_in || '',
    check_in_time: prop?.checkin_time || '15h00',
    check_out_date: res?.check_out || context.check_out || '',
    check_out_time: prop?.checkout_time || '11h00',
    wifi_name: prop?.wifi_name || '',
    wifi_password: prop?.wifi_password || '',
    door_code: prop?.entry_code || '',
    booking_reference: res?.external_id || res?.id || '',
    number_of_guests: res?.number_of_guests || context.number_of_guests || '',
  };
}

function matchConditions(conditions, context, vars) {
  if (!conditions || !conditions.length) return true;
  for (const c of conditions) {
    if (c.field === 'property_id' && c.value && context.property_id !== c.value) return false;
    if (c.field === 'platform' && c.value && context.platform !== c.value) return false;
    if (c.field === 'status' && c.value && context.status !== c.value) return false;
    if (c.field === 'min_guests' && (Number(vars.number_of_guests) || 0) < Number(c.value)) return false;
  }
  return true;
}

function scheduleJob(job) {
  DB.jobs = DB.jobs || [];
  // idempotence: skip if same key pending/completed
  const exists = DB.jobs.find(j => j.idempotency_key && j.idempotency_key === job.idempotency_key && j.status !== 'failed' && j.status !== 'cancelled');
  if (exists) return exists;
  DB.jobs.push(job);
  return job;
}

function executeAction(action, orgId, context, vars, runId) {
  const result = { action_type: action.type, status: 'completed', detail: null, error: null };
  try {
    if (action.type === 'create_cleaning_task' && context.property_id) {
      let existing = null;
      if (context.reservation_id) {
        existing = (DB.cleaning_tasks || []).find(
          t => t.reservation_id === context.reservation_id && t.organization_id === orgId
        );
      }
      if (existing) {
        result.detail = 'Tâche ménage déjà existante ' + existing.id + ' (idempotent)';
      } else {
        const taskId = uid();
        DB.cleaning_tasks.push({
          id: taskId, organization_id: orgId, property_id: context.property_id,
          reservation_id: context.reservation_id || null, assigned_to: action.assigned_to || null,
          scheduled_at: context.check_out || new Date().toISOString(), status: 'pending', notes: null,
          created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        });
        for (const title of (action.checklist || ['Cuisine','Salle de bain','Draps','Serviettes','Sol','Poubelles'])) {
          DB.cleaning_checklists.push({ id: uid(), cleaning_task_id: taskId, title, completed: 0, completed_at: null });
        }
        result.detail = 'Tâche ménage ' + taskId;
      }
    } else if (action.type === 'notify') {
      const title = interpolate(action.title || 'Notification', vars);
      const message = interpolate(action.message || '', vars);
      const members = DB.organization_members.filter(m => m.organization_id === orgId);
      for (const m of members) {
        if (action.role && m.role !== action.role && m.role !== 'owner') continue;
        DB.notifications.push({
          id: uid(), organization_id: orgId, user_id: m.user_id, type: action.notifyType || 'automation',
          title, message, read_at: null, created_at: new Date().toISOString(),
        });
      }
      result.detail = 'Notification: ' + title;
    } else if (action.type === 'send_message') {
      // Message interne / conversation — envoi plateforme = Configuration requise si pas d'intégration
      const content = interpolate(action.template || action.content || '', vars);
      if (context.reservation_id) {
        let conv = DB.conversations.find(c => c.reservation_id === context.reservation_id);
        if (!conv) {
          conv = {
            id: uid(), organization_id: orgId, property_id: context.property_id,
            reservation_id: context.reservation_id, guest_id: context.guest_id || null,
            status: 'open', ai_enabled: 1, human_controlled: 0,
            created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
          };
          DB.conversations.push(conv);
        }
        if (conv.human_controlled) {
          result.status = 'cancelled';
          result.detail = 'Message non envoyé — contrôle humain actif';
        } else {
          DB.messages.push({
            id: uid(), conversation_id: conv.id, sender_type: 'ai', content,
            channel: 'internal', read_at: null, created_at: new Date().toISOString(),
          });
          result.detail = 'Message enregistré (canal interne). Envoi Airbnb/Booking: Configuration requise si non connecté.';
        }
      } else {
        result.status = 'failed';
        result.error = 'Pas de réservation pour envoyer le message';
      }
    } else if (action.type === 'generate_checkin_link') {
      if (context.reservation_id) {
        const r = DB.reservations.find(x => x.id === context.reservation_id);
        if (r) {
          const _ct = createCheckinToken(r.id, r.organization_id);
          result.detail = '/checkin.html?token=' + _ct.token;
        }
      }
    } else if (action.type === 'create_incident') {
      DB.incidents.push({
        id: uid(), organization_id: orgId, property_id: context.property_id,
        reservation_id: context.reservation_id || null, reported_by: null,
        title: interpolate(action.title || 'Incident auto', vars),
        description: interpolate(action.description || '', vars),
        category: action.category || 'other', severity: action.severity || 'medium',
        status: 'open', resolved_at: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      });
      result.detail = 'Incident créé';
    } else if (action.type === 'send_email') {
      result.status = 'failed';
      result.error = 'Configuration requise — service email non configuré (SMTP / provider)';
    } else {
      result.status = 'failed';
      result.error = 'Action inconnue: ' + action.type;
    }
  } catch (e) {
    result.status = 'failed';
    result.error = e.message;
  }
  return result;
}

function runAutomations(eventType, orgId, context) {
  DB.jobs = DB.jobs || [];
  function normEvent(e) {
    return String(e || '').toUpperCase().replace(/\./g, '_');
  }
  const autos = DB.automations.filter(a => a.organization_id === orgId && a.enabled && normEvent(a.event_type) === normEvent(eventType));
  const results = [];
  const vars = buildVarContext(orgId, context);

  for (const auto of autos) {
    let conditions = [];
    try { conditions = JSON.parse(auto.conditions_json || '[]'); } catch {}
    if (!matchConditions(conditions, context, vars)) {
      results.push({ automation_id: auto.id, status: 'skipped_conditions', trigger_event: eventType });
      continue;
    }
    let actions = [];
    try { actions = JSON.parse(auto.actions_json || '[]'); } catch {}
    const run = {
      id: uid(),
      automation_id: auto.id,
      organization_id: orgId,
      trigger_event: eventType,
      status: 'running',
      started_at: new Date().toISOString(),
      completed_at: null,
      error_message: null,
      action_results: [],
      reservation_id: context.reservation_id || null,
      property_id: context.property_id || null,
    };
    let anyFail = false;
    for (let i = 0; i < actions.length; i++) {
      const action = actions[i];
      const delayMin = Number(action.delay_minutes || 0);
      const delayHours = Number(action.delay_hours || 0);
      const delayMs = (delayMin * 60 + delayHours * 3600) * 1000;

      if (delayMs > 0) {
        const runAt = new Date(Date.now() + delayMs).toISOString();
        const idem = `${auto.id}:${eventType}:${context.reservation_id || context.property_id || 'x'}:${i}:${action.type}`;
        scheduleJob({
          id: uid(),
          organization_id: orgId,
          automation_id: auto.id,
          run_id: run.id,
          action_index: i,
          action_json: JSON.stringify(action),
          context_json: JSON.stringify(context),
          idempotency_key: idem,
          status: 'pending',
          run_at: runAt,
          executed_at: null,
          result: null,
          error_message: null,
          created_at: new Date().toISOString(),
        });
        run.action_results.push({ action_type: action.type, status: 'pending', detail: 'Planifié pour ' + runAt });
      } else {
        const ar = executeAction(action, orgId, context, vars, run.id);
        run.action_results.push(ar);
        if (ar.status === 'failed') anyFail = true;
      }
    }
    run.status = anyFail ? 'failed' : 'completed';
    run.completed_at = new Date().toISOString();
    if (anyFail) run.error_message = run.action_results.filter(a => a.error).map(a => a.error).join('; ');
    DB.automation_runs.push(run);
    results.push(run);
  }
  if (results.length) saveDb(DB);
  return results;
}


// ── AI Messaging Service (provider-agnostic) ─────────────────
function getPropertyKnowledge(propertyId) {
  return (DB.property_knowledge || []).filter(k => k.property_id === propertyId && k.is_active !== 0);
}

function buildKnowledgeText(propertyId) {
  const prop = DB.properties.find(x => x.id === propertyId);
  if (!prop) return '';
  const lines = [
    `Nom: ${prop.name || ''}`,
    `Adresse: ${prop.address || ''}`,
    `Check-in: ${prop.checkin_time || ''}`,
    `Check-out: ${prop.checkout_time || ''}`,
    `Wi-Fi: ${prop.wifi_name || ''} / ${prop.wifi_password || ''}`,
    `Code d'entrée: ${prop.entry_code || ''}`,
    `Parking: ${prop.parking_information || ''}`,
    `Règles: ${prop.house_rules || ''}`,
  ];
  for (const k of getPropertyKnowledge(propertyId)) {
    lines.push(`${k.category || ''}: ${k.title || ''} — ${k.content || ''}`);
  }
  return lines.filter(l => !l.endsWith(': ') && !l.includes(': null')).join('\n');
}

function detectUrgency(text) {
  const t = (text || '').toLowerCase();
  const keys = ['fuite', 'incendie', 'feu', 'urgence', 'danger', 'bloqué', 'bloquee', 'serrure', 'cambriol', 'gaz', 'électroc', 'electroc', 'sang', 'blessé', 'blesse', 'police', 'pompiers'];
  return keys.some(k => t.includes(k));
}

function detectEscalation(text) {
  const t = (text || '').toLowerCase();
  const reasons = [
    { k: ['rembours', 'rembourse', 'argent', 'facture', 'payer trop'], reason: 'demande_financiere' },
    { k: ['plainte', 'inadmissible', 'scandale', 'avocat'], reason: 'plainte' },
    { k: ['annul', 'modifier réservation', 'changer les dates', 'prolonger'], reason: 'modification_reservation' },
    { k: ['rembours', 'refund'], reason: 'remboursement' },
  ];
  for (const r of reasons) {
    if (r.k.some(x => t.includes(x))) return r.reason;
  }
  if (detectUrgency(text)) return 'urgence';
  return null;
}

/** Réponses déterministes depuis données réelles uniquement — jamais d'invention */
function ruleBasedReply(message, propertyId, reservation) {
  const t = (message || '').toLowerCase();
  const prop = DB.properties.find(x => x.id === propertyId);
  if (!prop) return { reply: null, confidence: 0, reason: 'logement_inconnu' };

  const has = (keys) => keys.some(k => t.includes(k));

  if (has(['wifi', 'wi-fi', 'wi fi', 'mot de passe wifi', 'password'])) {
    if (prop.wifi_name || prop.wifi_password) {
      return {
        reply: `Le réseau Wi-Fi s'appelle « ${prop.wifi_name || '—'} »${prop.wifi_password ? ` et le mot de passe est « ${prop.wifi_password} »` : ''}.`,
        confidence: 0.95,
        reason: 'wifi',
      };
    }
    return { reply: null, confidence: 0, reason: 'wifi_absent' };
  }
  if (has(['code', 'clé', 'cle', 'entrée', 'entree', 'accès', 'acces', 'serrure', 'digicode', 'boîte', 'boite'])) {
    if (prop.entry_code) {
      return { reply: `Le code d'accès est : ${prop.entry_code}.`, confidence: 0.95, reason: 'entry_code' };
    }
    return { reply: null, confidence: 0, reason: 'code_absent' };
  }
  if (has(['check-in', 'checkin', 'arrivée', 'arrivee', 'horaire d\'arrivée', 'heure d\'arrivée'])) {
    return {
      reply: `L'heure d'arrivée (check-in) est à partir de ${prop.checkin_time || '15h00'}${reservation?.check_in ? ` le ${String(reservation.check_in).slice(0, 10)}` : ''}.`,
      confidence: 0.9,
      reason: 'checkin',
    };
  }
  if (has(['check-out', 'checkout', 'départ', 'depart', 'heure de départ'])) {
    return {
      reply: `L'heure de départ (check-out) est jusqu'à ${prop.checkout_time || '11h00'}${reservation?.check_out ? ` le ${String(reservation.check_out).slice(0, 10)}` : ''}.`,
      confidence: 0.9,
      reason: 'checkout',
    };
  }
  if (has(['adresse', 'où est', 'ou est', 'localiser', 'situation', 'trouver le logement'])) {
    if (prop.address) {
      return { reply: `Le logement se situe au : ${prop.address}.`, confidence: 0.95, reason: 'address' };
    }
    return { reply: null, confidence: 0, reason: 'adresse_absente' };
  }
  if (has(['parking', 'garer', 'stationnement', 'voiture'])) {
    if (prop.parking_information) {
      return { reply: prop.parking_information, confidence: 0.9, reason: 'parking' };
    }
    return { reply: null, confidence: 0, reason: 'parking_absent' };
  }
  if (has(['règle', 'regle', 'interdit', 'animaux', 'fumer'])) {
    if (prop.house_rules) {
      return { reply: prop.house_rules, confidence: 0.85, reason: 'rules' };
    }
    return { reply: null, confidence: 0, reason: 'rules_absent' };
  }

  // Knowledge base entries
  for (const k of getPropertyKnowledge(propertyId)) {
    const blob = `${k.category} ${k.title} ${k.content}`.toLowerCase();
    const words = t.split(/\s+/).filter(w => w.length > 3);
    if (words.some(w => blob.includes(w))) {
      return { reply: k.content, confidence: 0.8, reason: 'knowledge:' + (k.category || '') };
    }
  }

  return { reply: null, confidence: 0, reason: 'inconnu' };
}

async function aiServiceGenerateReply({ message, propertyId, reservation, conversation }) {
  const provider = process.env.AI_PROVIDER || '';
  const apiKey = process.env.AI_API_KEY || '';
  const model = process.env.AI_MODEL || 'gpt-4o-mini';

  // 1) Règles strictes sur données réelles
  const rule = ruleBasedReply(message, propertyId, reservation);
  if (rule.confidence >= 0.85 && rule.reply) {
    return { text: rule.reply, confidence: rule.confidence, source: 'knowledge_base', provider: 'rules' };
  }

  // 2) Escalade si info absente / sensible sans données
  const esc = detectEscalation(message);
  if (esc || rule.confidence < 0.5) {
    return {
      text: null,
      confidence: rule.confidence,
      source: 'escalation',
      escalate: true,
      escalateReason: esc || rule.reason || 'information_inconnue',
      provider: 'rules',
    };
  }

  // 3) Fournisseur IA externe uniquement si configuré — contexte limité à la knowledge
  if (!apiKey || !provider) {
    return {
      text: null,
      confidence: 0,
      source: 'config',
      escalate: true,
      escalateReason: 'configuration_requise_ia',
      provider: null,
      message: 'Configuration requise — définissez AI_PROVIDER et AI_API_KEY côté serveur',
    };
  }

  const knowledge = buildKnowledgeText(propertyId);
  const system = `Tu es l'assistant du propriétaire d'un logement en location courte durée.
Tu réponds UNIQUEMENT avec les informations fournies ci-dessous. Si l'information n'y est pas, dis que tu vas vérifier avec l'équipe. N'invente jamais de codes, prix, horaires ou équipements.
---
${knowledge}
---`;

  try {
    if (provider === 'openai' || provider === 'xai') {
      const base = provider === 'xai' ? 'https://api.x.ai/v1' : 'https://api.openai.com/v1';
      const res = await fetch(`${base}/chat/completions`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model: provider === 'xai' ? (process.env.AI_MODEL || 'grok-beta') : model,
          messages: [
            { role: 'system', content: system },
            { role: 'user', content: message },
          ],
          temperature: 0.2,
          max_tokens: 400,
        }),
      });
      if (!res.ok) {
        return { text: null, confidence: 0, escalate: true, escalateReason: 'ai_provider_error', provider };
      }
      const data = await res.json();
      const text = data.choices?.[0]?.message?.content?.trim();
      if (!text) return { text: null, confidence: 0, escalate: true, escalateReason: 'ai_empty', provider };
      return { text, confidence: 0.7, source: 'ai', provider };
    }
    return { text: null, confidence: 0, escalate: true, escalateReason: 'provider_inconnu', message: 'AI_PROVIDER non supporté' };
  } catch (e) {
    return { text: null, confidence: 0, escalate: true, escalateReason: 'ai_network', error: e.message };
  }
}

async function handleInboundGuestMessage(conversationId, content, channel) {
  const conv = DB.conversations.find(c => c.id === conversationId);
  if (!conv) return { error: 'Conversation introuvable' };

  const msg = {
    id: uid(),
    conversation_id: conversationId,
    sender_type: 'guest',
    content,
    channel: channel || 'internal',
    delivery_status: 'received',
    read_at: null,
    created_at: new Date().toISOString(),
  };
  DB.messages.push(msg);
  conv.updated_at = new Date().toISOString();

  // Human control → no AI
  if (conv.human_controlled || !conv.ai_enabled) {
    conv.status = 'intervention_required';
    saveDb(DB);
    return { message: msg, ai: null, escalated: true, reason: 'human_control' };
  }

  if (detectUrgency(content)) {
    conv.status = 'intervention_required';
    conv.ai_enabled = 0;
    const members = DB.organization_members.filter(m => m.organization_id === conv.organization_id);
    for (const m of members) {
      if (['owner', 'admin', 'manager'].includes(m.role)) {
        DB.notifications.push({
          id: uid(), organization_id: conv.organization_id, user_id: m.user_id,
          type: 'urgency', title: 'Urgence voyageur', message: content.slice(0, 120),
          read_at: null, created_at: new Date().toISOString(),
        });
      }
    }
    saveDb(DB);
    audit(conv.organization_id, null, 'message.urgency', 'conversation', conversationId);
    return { message: msg, ai: null, escalated: true, reason: 'urgence' };
  }

  const reservation = conv.reservation_id ? DB.reservations.find(r => r.id === conv.reservation_id) : null;
  const ai = await aiServiceGenerateReply({
    message: content,
    propertyId: conv.property_id,
    reservation,
    conversation: conv,
  });

  if (ai.escalate || !ai.text) {
    conv.status = 'intervention_required';
    for (const m of DB.organization_members.filter(x => x.organization_id === conv.organization_id)) {
      if (['owner', 'admin', 'manager'].includes(m.role)) {
        DB.notifications.push({
          id: uid(), organization_id: conv.organization_id, user_id: m.user_id,
          type: 'intervention', title: 'Intervention requise',
          message: ai.escalateReason || 'Message voyageur',
          read_at: null, created_at: new Date().toISOString(),
        });
      }
    }
    saveDb(DB);
    return { message: msg, ai, escalated: true, reason: ai.escalateReason };
  }

  // Réponse IA enregistrée — envoi plateforme = pending tant que pas d'API
  const reply = {
    id: uid(),
    conversation_id: conversationId,
    sender_type: 'ai',
    content: ai.text,
    channel: channel || 'internal',
    delivery_status: channel && channel !== 'internal' ? 'pending' : 'sent',
    delivery_note: channel && channel !== 'internal'
      ? 'Configuration requise — intégration plateforme pour envoi officiel'
      : null,
    created_at: new Date().toISOString(),
  };
  DB.messages.push(reply);
  conv.updated_at = new Date().toISOString();
  saveDb(DB);
  runAutomations('GUEST_MESSAGE_RECEIVED', conv.organization_id, {
    property_id: conv.property_id,
    reservation_id: conv.reservation_id,
  });
  return { message: msg, reply, ai, escalated: false };
}




// ── Billing / Stripe (officiel uniquement) ───────────────────



// ── Onboarding ───────────────────────────────────────────────
function getOnboardingState(userId, orgId) {
  DB.onboarding_state = DB.onboarding_state || [];
  let row = DB.onboarding_state.find(o => o.user_id === userId && o.organization_id === orgId);
  if (!row) {
    row = {
      id: uid(),
      user_id: userId,
      organization_id: orgId,
      step: 1,
      completed: 0,
      completed_at: null,
      flags: {},
      updated_at: new Date().toISOString(),
    };
    DB.onboarding_state.push(row);
  }
  return row;
}

function computeOnboardingChecklist(orgId, userId) {
  const org = DB.organizations.find(o => o.id === orgId);
  const props = DB.properties.filter(p => p.organization_id === orgId);
  const hasProp = props.length > 0;
  const prop = props[0];
  let knowledgePct = 0;
  if (prop) {
    const fields = [prop.address, prop.wifi_name, prop.entry_code, prop.parking_information, prop.house_rules, prop.checkin_time, prop.checkout_time];
    const filled = fields.filter(Boolean).length;
    const kb = (DB.property_knowledge || []).filter(k => k.property_id === prop.id).length;
    knowledgePct = Math.min(100, Math.round(((filled / fields.length) * 70) + Math.min(30, kb * 10)));
  }
  const integ = (DB.integrations || []).filter(i => i.organization_id === orgId && i.status === 'connected');
  const autos = (DB.automations || []).filter(a => a.organization_id === orgId && a.enabled);
  const prefs = (DB.notification_preferences || []).find(p => p.user_id === userId);
  const pricing = prop ? (DB.pricing_rules || []).find(r => r.property_id === prop.id) : null;
  const cleaningConfigured = (DB.cleaning_tasks || []).some(t => t.organization_id === orgId) ||
    (prop && prop.checkout_time); // basic: checkout time implies cleaning window awareness

  const items = [
    { key: 'account', label: 'Compte créé', done: true },
    { key: 'organization', label: 'Organisation configurée', done: !!(org && org.name) },
    { key: 'property', label: 'Logement ajouté', done: hasProp },
    { key: 'knowledge', label: 'Base de connaissances', done: knowledgePct >= 50, detail: knowledgePct + '%' },
    { key: 'integrations', label: 'Plateforme connectée', done: integ.length > 0, detail: integ.length ? 'connecté' : 'non connecté' },
    { key: 'automations', label: 'Automatisations', done: autos.length > 0 },
    { key: 'notifications', label: 'Notifications', done: !!prefs },
    { key: 'pricing', label: 'Tarification', done: !!pricing },
    { key: 'cleaning', label: 'Ménage configuré', done: !!cleaningConfigured },
  ];
  const doneCount = items.filter(i => i.done).length;
  const percent = Math.round((doneCount / items.length) * 100);
  return { items, percent, knowledgePct, property_id: prop?.id || null };
}


// ── Reviews & reputation ─────────────────────────────────────
function analyzeReviewText(text, rating) {
  const t = (text || '').toLowerCase();
  const topics = [];
  const map = [
    ['proprete', ['propre', 'propreté', 'proprete', 'sale', 'ménage', 'menage', 'poussière', 'salle de bain']],
    ['emplacement', ['emplacement', 'quartier', 'localisation', 'situé', 'centre', 'transport']],
    ['communication', ['communication', 'hôte', 'hote', 'réponse', 'reponse', 'accueil']],
    ['arrivee', ['arrivée', 'arrivee', 'check-in', 'checkin', 'clés', 'cles', 'accès', 'acces']],
    ['equipement', ['équipement', 'equipement', 'wifi', 'cuisine', 'lave', 'clim', 'chauffage']],
    ['confort', ['confort', 'lit', 'sommeil', 'bruit', 'calme', 'spacieux']],
    ['qualite_prix', ['rapport', 'qualité/prix', 'qualite', 'cher', 'prix']],
    ['technique', ['panne', 'cassé', 'casse', 'fonctionne pas', 'fuite', 'électricité']],
  ];
  for (const [topic, keys] of map) {
    if (keys.some(k => t.includes(k))) topics.push(topic);
  }
  let sentiment = 'neutre';
  if (rating != null) {
    if (rating >= 4) sentiment = 'positif';
    else if (rating <= 2) sentiment = 'negatif';
  }
  const negWords = ['déçu', 'deçu', 'horrible', 'inadmissible', 'jamais', 'rembours', 'plainte', 'danger', 'fuite'];
  const posWords = ['parfait', 'excellent', 'super', 'génial', 'recommande', 'agréable', 'top'];
  if (negWords.some(w => t.includes(w))) sentiment = 'negatif';
  else if (posWords.some(w => t.includes(w)) && sentiment !== 'negatif') sentiment = 'positif';

  const sensitive = [
    'avocat', 'tribunal', 'discrimination', 'fraude', 'vol', 'agression', 'médical', 'medical',
    'remboursement intégral', 'police', 'menace', 'harcèlement'
  ].some(w => t.includes(w));

  return {
    sentiment,
    topics,
    sensitive,
    summary: topics.length
      ? `Sujets détectés : ${topics.join(', ')}. Ton ${sentiment}.`
      : `Aucun sujet spécifique détecté. Ton ${sentiment}.`,
  };
}

function generateReviewReply(review, property) {
  const analysis = review.analysis || analyzeReviewText(review.comment, review.rating);
  if (analysis.sensitive) {
    return {
      draft: null,
      blocked: true,
      reason: 'Intervention humaine recommandée — contenu sensible détecté',
    };
  }
  const name = property?.name || 'notre logement';
  if (analysis.sentiment === 'positif' || (review.rating != null && review.rating >= 4)) {
    return {
      draft: `Merci beaucoup pour votre retour concernant ${name}. Nous sommes ravis que votre séjour se soit bien passé et espérons vous accueillir à nouveau.`,
      blocked: false,
    };
  }
  if (analysis.sentiment === 'negatif' || (review.rating != null && review.rating <= 2)) {
    return {
      draft: `Merci d'avoir partagé votre expérience concernant ${name}. Nous prenons vos remarques au sérieux et allons examiner les points mentionnés afin d'améliorer les séjours futurs.`,
      blocked: false,
    };
  }
  return {
    draft: `Merci pour votre avis concernant ${name}. Vos commentaires nous aident à progresser.`,
    blocked: false,
  };
}


// ── Pricing / Revenue management ─────────────────────────────
function getPricingRules(orgId, propertyId) {
  DB.pricing_rules = DB.pricing_rules || [];
  let rules = DB.pricing_rules.find(r => r.organization_id === orgId && r.property_id === propertyId);
  if (!rules) {
    rules = {
      id: uid(),
      organization_id: orgId,
      property_id: propertyId,
      base_price: 100,
      min_price: 60,
      max_price: 250,
      max_increase_pct: 30,
      max_decrease_pct: 25,
      weekend_pct: 10,
      auto_apply: 0,
      long_stay_nights: 7,
      long_stay_discount_pct: 5,
      updated_at: new Date().toISOString(),
    };
    DB.pricing_rules.push(rules);
  }
  return rules;
}

function clampPrice(price, rules) {
  let p = Math.round(Number(price) || 0);
  if (p < 1) p = 1;
  p = Math.max(rules.min_price, Math.min(rules.max_price, p));
  return p;
}

function computeOccupancyForward(orgId, propertyId, days) {
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const end = new Date(today);
  end.setDate(end.getDate() + days);
  const resas = DB.reservations.filter(r =>
    r.organization_id === orgId &&
    r.property_id === propertyId &&
    r.status !== 'cancelled'
  );
  let occupied = 0;
  for (let i = 0; i < days; i++) {
    const d = new Date(today);
    d.setDate(today.getDate() + i);
    const ds = d.toISOString().slice(0, 10);
    const busy = resas.some(r => {
      const ci = String(r.check_in).slice(0, 10);
      const co = String(r.check_out).slice(0, 10);
      return ci <= ds && co > ds;
    });
    if (busy) occupied++;
  }
  return { occupied, days, rate: days ? Math.round((occupied / days) * 1000) / 10 : 0 };
}

function generateRecommendation(orgId, propertyId) {
  const rules = getPricingRules(orgId, propertyId);
  const occ14 = computeOccupancyForward(orgId, propertyId, 14);
  const occ7 = computeOccupancyForward(orgId, propertyId, 7);
  const upcoming = DB.reservations.filter(r =>
    r.organization_id === orgId && r.property_id === propertyId && r.status !== 'cancelled' &&
    String(r.check_in).slice(0, 10) >= new Date().toISOString().slice(0, 10)
  );
  const nightsBooked = upcoming.reduce((s, r) => {
    const n = Math.max(0, (new Date(r.check_out) - new Date(r.check_in)) / 86400000);
    return s + n;
  }, 0);
  const revenueExpected = upcoming.reduce((s, r) => s + (Number(r.total_amount) || 0), 0);
  const hist = upcoming.length ? revenueExpected / Math.max(1, nightsBooked) : rules.base_price;
  const adr = Math.round(hist) || rules.base_price;

  let recommended = rules.base_price;
  let reason = 'Prix de base';
  const factors = [];

  if (occ14.rate >= 80) {
    const up = Math.min(rules.max_increase_pct, 15 + Math.round((occ14.rate - 80) / 2));
    recommended = rules.base_price * (1 + up / 100);
    reason = `Occupation élevée (${occ14.rate} % sur 14 jours)`;
    factors.push('occupation_haute');
  } else if (occ7.rate <= 30) {
    const down = Math.min(rules.max_decrease_pct, 10 + Math.round((30 - occ7.rate) / 3));
    recommended = rules.base_price * (1 - down / 100);
    reason = `Faible occupation à court terme (${occ7.rate} % sur 7 jours)`;
    factors.push('occupation_basse');
  } else {
    recommended = rules.base_price;
    reason = `Occupation modérée (${occ14.rate} % sur 14 jours) — maintien proche du prix de base`;
    factors.push('stable');
  }

  // weekend hint (not market invention)
  const dow = new Date().getDay();
  if (rules.weekend_pct && (dow === 5 || dow === 6)) {
    recommended *= (1 + rules.weekend_pct / 100);
    factors.push('weekend');
    reason += ` · majoration week-end ${rules.weekend_pct}%`;
  }

  recommended = clampPrice(recommended, rules);
  // respect max increase/decrease from base
  const maxUp = rules.base_price * (1 + rules.max_increase_pct / 100);
  const maxDown = rules.base_price * (1 - rules.max_decrease_pct / 100);
  recommended = Math.round(Math.max(maxDown, Math.min(maxUp, recommended)));
  recommended = clampPrice(recommended, rules);

  return {
    current_price: rules.base_price,
    recommended_price: recommended,
    min_price: rules.min_price,
    max_price: rules.max_price,
    occupancy_14d: occ14.rate,
    occupancy_7d: occ7.rate,
    available_days_14: occ14.days - occ14.occupied,
    upcoming_reservations: upcoming.length,
    nights_booked: Math.round(nightsBooked),
    revenue_expected: Math.round(revenueExpected),
    adr: adr,
    revpar: Math.round(adr * (occ14.rate / 100)),
    reason,
    factors,
    auto_apply: !!rules.auto_apply,
  };
}

function explainRecommendation(rec) {
  // deterministic explanation from real numbers only — no invented market data
  return `Le prix recommandé est de ${rec.recommended_price} € (actuel ${rec.current_price} €). ` +
    `Occupation 14 jours : ${rec.occupancy_14d} %. ` +
    `Nuits réservées à venir : ${rec.nights_booked}. ` +
    `Motif : ${rec.reason}. ` +
    `Aucune donnée concurrentielle ou événement externe n'a été utilisée.`;
}


const PLAN_LIMITS = {
  free: { name: 'Free', max_properties: 1, max_users: 2, max_automations: 2, max_ai_replies: 20, price_label: '0 €' },
  starter: { name: 'Starter', max_properties: 3, max_users: 3, max_automations: 5, max_ai_replies: 100, price_label: 'Config Stripe' },
  pro: { name: 'Pro', max_properties: 15, max_users: 10, max_automations: 50, max_ai_replies: 2000, price_label: 'Config Stripe' },
  business: { name: 'Business', max_properties: 100, max_users: 50, max_automations: 500, max_ai_replies: 20000, price_label: 'Config Stripe' },
};

function stripeConfigured() {
  return !!(process.env.STRIPE_SECRET_KEY && process.env.STRIPE_SECRET_KEY.startsWith('sk_'));
}

function getOrgPlan(orgId) {
  const sub = (DB.subscriptions || []).find(s => s.organization_id === orgId);
  const plan = (sub?.plan || 'starter').toLowerCase();
  const status = sub?.status || 'trialing';
  const limits = PLAN_LIMITS[plan] || PLAN_LIMITS.free;
  const active = ['active', 'trialing'].includes(status);
  return { sub, plan: active ? plan : 'free', status, limits, active };
}

function assertPlanLimit(orgId, resource) {
  const { limits, plan, status } = getOrgPlan(orgId);
  if (resource === 'properties') {
    const count = DB.properties.filter(p => p.organization_id === orgId).length;
    if (count >= limits.max_properties) {
      return { ok: false, error: `Limite atteinte (${limits.max_properties} logements sur le plan ${plan}). Passez à un plan supérieur.`, code: 'plan_limit' };
    }
  }
  if (resource === 'automations') {
    const count = DB.automations.filter(a => a.organization_id === orgId).length;
    if (count >= limits.max_automations) {
      return { ok: false, error: `Limite d'automatisations atteinte pour le plan ${plan}.`, code: 'plan_limit' };
    }
  }
  return { ok: true };
}

async function stripeRequest(path, method, body) {
  const key = process.env.STRIPE_SECRET_KEY;
  if (!key) throw new Error('STRIPE_SECRET_KEY manquant');
  const res = await fetch('https://api.stripe.com/v1' + path, {
    method: method || 'GET',
    headers: {
      Authorization: 'Bearer ' + key,
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: body ? new URLSearchParams(body).toString() : undefined,
  });
  const data = await res.json();
  if (data.error) throw new Error(data.error.message || 'Erreur Stripe');
  return data;
}


// ── Notification service ─────────────────────────────────────
function createNotification({ organization_id, user_id, type, title, message, priority, related, idempotency_key }) {
  DB.notifications = DB.notifications || [];
  if (idempotency_key) {
    const exists = DB.notifications.find(n => n.idempotency_key === idempotency_key);
    if (exists) return exists;
  }
  // preferences
  const prefs = (DB.notification_preferences || []).find(p => p.user_id === user_id);
  if (prefs && prefs.categories && prefs.categories[type] === false) {
    return null; // user disabled this category in-app
  }
  const n = {
    id: uid(),
    organization_id,
    user_id,
    type: type || 'system',
    title: title || 'Notification',
    message: message || '',
    priority: priority || 'normal',
    read: 0,
    read_at: null,
    related_property_id: related?.property_id || null,
    related_reservation_id: related?.reservation_id || null,
    related_cleaning_task_id: related?.cleaning_task_id || null,
    related_incident_id: related?.incident_id || null,
    related_conversation_id: related?.conversation_id || null,
    idempotency_key: idempotency_key || null,
    created_at: new Date().toISOString(),
  };
  DB.notifications.push(n);
  // Email channel — only if configured
  enqueueEmailIfConfigured(user_id, n, prefs);
  return n;
}

function notifyOrgRoles(organization_id, roles, payload) {
  const members = DB.organization_members.filter(m => m.organization_id === organization_id && roles.includes(m.role));
  const created = [];
  for (const m of members) {
    const n = createNotification({ ...payload, organization_id, user_id: m.user_id });
    if (n) created.push(n);
  }
  if (created.length) saveDb(DB);
  return created;
}

function emailConfigured() {
  return !!(process.env.EMAIL_PROVIDER && process.env.EMAIL_API_KEY && process.env.EMAIL_FROM);
}

/** Envoi réel Resend / SendGrid — status=sent uniquement si HTTP 2xx */
async function sendEmailViaProvider({ to, subject, text, html }) {
  const provider = (process.env.EMAIL_PROVIDER || '').toLowerCase().trim();
  const apiKey = process.env.EMAIL_API_KEY;
  const from = process.env.EMAIL_FROM;
  if (!provider || !apiKey || !from) {
    return { ok: false, code: 'EMAIL_NOT_CONFIGURED', error: 'EMAIL_NOT_CONFIGURED' };
  }
  try {
    if (provider === 'resend') {
      const res = await fetch('https://api.resend.com/emails', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          from,
          to: [to],
          subject: subject || 'HostPilot',
          text: text || '',
          html: html || undefined,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        return { ok: false, code: 'PROVIDER_ERROR', error: body.message || ('HTTP ' + res.status), status: res.status };
      }
      return { ok: true, id: body.id || null, provider: 'resend' };
    }
    if (provider === 'sendgrid') {
      const res = await fetch('https://api.sendgrid.com/v3/mail/send', {
        method: 'POST',
        headers: {
          Authorization: 'Bearer ' + apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          personalizations: [{ to: [{ email: to }] }],
          from: { email: from },
          subject: subject || 'HostPilot',
          content: [{ type: 'text/plain', value: text || ' ' }],
        }),
      });
      if (res.status >= 200 && res.status < 300) {
        return { ok: true, id: res.headers.get('x-message-id') || null, provider: 'sendgrid' };
      }
      const body = await res.text().catch(() => '');
      return { ok: false, code: 'PROVIDER_ERROR', error: body.slice(0, 200) || ('HTTP ' + res.status), status: res.status };
    }
    return { ok: false, code: 'EMAIL_NOT_CONFIGURED', error: 'Provider non supporté (utilisez resend ou sendgrid)' };
  } catch (e) {
    return { ok: false, code: 'EMAIL_ERROR', error: e.message };
  }
}

function enqueueEmailIfConfigured(user_id, notification, prefs) {
  if (!emailConfigured()) return;
  if (prefs && prefs.email_categories && prefs.email_categories[notification.type] === false) return;
  const user = DB.users.find(u => u.id === user_id);
  if (!user?.email) return;
  DB.notification_deliveries = DB.notification_deliveries || [];
  // dedupe pending same notification+channel
  const exists = DB.notification_deliveries.find(
    d => d.notification_id === notification.id && d.channel === 'email' && d.status === 'pending'
  );
  if (exists) return;
  DB.notification_deliveries.push({
    id: uid(),
    notification_id: notification.id,
    channel: 'email',
    status: 'pending',
    provider: process.env.EMAIL_PROVIDER,
    to: user.email,
    subject: notification.title || 'HostPilot',
    text: notification.message || '',
    error: null,
    created_at: new Date().toISOString(),
    sent_at: null,
  });
}

async function flushEmailQueue() {
  if (!emailConfigured()) return;
  DB.notification_deliveries = DB.notification_deliveries || [];
  let changed = false;
  for (const d of DB.notification_deliveries) {
    if (d.status !== 'pending' || d.channel !== 'email') continue;
    const result = await sendEmailViaProvider({
      to: d.to,
      subject: d.subject || 'HostPilot',
      text: d.text || '',
    });
    if (result.ok) {
      d.status = 'sent';
      d.sent_at = new Date().toISOString();
      d.provider_id = result.id || null;
      d.error = null;
    } else {
      d.status = 'failed';
      d.error = result.error || result.code || 'send_failed';
    }
    changed = true;
  }
  if (changed) saveDb(DB);
}


function processDueJobs() {
  DB.jobs = DB.jobs || [];
  const now = Date.now();
  let changed = false;
  for (const job of DB.jobs) {
    if (job.status !== 'pending') continue;
    if (new Date(job.run_at).getTime() > now) continue;
    job.status = 'processing';
    changed = true;
    try {
      const action = JSON.parse(job.action_json || '{}');
      const context = JSON.parse(job.context_json || '{}');
      const vars = buildVarContext(job.organization_id, context);
      const ar = executeAction(action, job.organization_id, context, vars, job.run_id);
      job.result = JSON.stringify(ar);
      job.status = ar.status === 'failed' ? 'failed' : 'completed';
      job.error_message = ar.error || null;
      job.executed_at = new Date().toISOString();
      // log on parent run
      const run = DB.automation_runs.find(r => r.id === job.run_id);
      if (run) {
        run.action_results = run.action_results || [];
        run.action_results.push({ ...ar, scheduled: true, executed_at: job.executed_at });
      }
    } catch (e) {
      job.status = 'failed';
      job.error_message = e.message;
      job.executed_at = new Date().toISOString();
    }
  }
  if (changed) saveDb(DB);
}

// Jobs worker — côté serveur, indépendant du navigateur
setInterval(() => { try { processDueJobs(); } catch (e) { console.error('jobs', e.message); } }, 15000);

function createCheckinToken(reservationId, orgId) {
  const token = uid() + uid();
  const hash = crypto.createHash('sha256').update(token).digest('hex');
  const expires = new Date(Date.now() + 30 * 24 * 3600 * 1000).toISOString();
  const row = {
    id: uid(),
    reservation_id: reservationId,
    organization_id: orgId,
    token_hash: hash,
    expires_at: expires,
    used_at: null,
    confirmed_at: null,
    revoked_at: null,
    created_at: new Date().toISOString(),
  };
  DB.checkin_tokens = DB.checkin_tokens || [];
  for (const t of DB.checkin_tokens) {
    if (t.reservation_id === reservationId && !t.revoked_at) t.revoked_at = new Date().toISOString();
  }
  DB.checkin_tokens.push(row);
  const r = DB.reservations.find(x => x.id === reservationId);
  if (r) {
    r.checkin_token_hash = hash;
    delete r.checkin_token; // never store plaintext
  }
  return { token, expires_at: expires, row };
}

function findTokenRecord(token) {
  if (!token || typeof token !== 'string') return null;
  try {
    const hash = crypto.createHash('sha256').update(token).digest('hex');
    const row = (DB.checkin_tokens || []).find(t => t.token_hash === hash && !t.revoked_at);
    if (row) return row;
    // legacy: plain token on reservation (pre-hardening) — accept once then migrate
    const r = DB.reservations.find(x => x.checkin_token === token);
    if (r) {
      r.checkin_token_hash = hash;
      delete r.checkin_token;
      return { reservation_id: r.id, organization_id: r.organization_id, expires_at: null, confirmed_at: r.checkin_confirmed_at || null };
    }
    return null;
  } catch { return null; }
}

function buildCheckinPayload(token) {
  const rec = findTokenRecord(token);
  if (!rec) return { error: 404, body: { error: "Ce lien de check-in n'est plus valide." } };
  const reservationId = rec.reservation_id || rec.id;
  const r = DB.reservations.find(x => x.id === reservationId);
  if (!r || r.status === 'cancelled') return { error: 404, body: { error: "Ce lien de check-in n'est plus valide." } };
  if (rec.expires_at && new Date(rec.expires_at) < new Date()) {
    return { error: 410, body: { error: "Ce lien de check-in n'est plus valide." } };
  }
  if (r.check_out && new Date(r.check_out) < new Date(Date.now() - 24 * 3600 * 1000)) {
    return { error: 410, body: { error: "Ce lien de check-in n'est plus valide." } };
  }
  const prop = DB.properties.find(x => x.id === r.property_id);
  const guest = DB.guests.find(g => g.id === r.guest_id);
  return {
    error: 0,
    body: {
      valid: true,
      guestName: guest ? (guest.first_name + ' ' + (guest.last_name || '')).trim() : '',
      propertyName: prop?.name || '',
      address: prop?.address || '',
      checkIn: r.check_in,
      checkOut: r.check_out,
      checkinTime: prop?.checkin_time || '15h00',
      checkoutTime: prop?.checkout_time || '11h00',
      accessCode: prop?.entry_code || null,
      wifiName: prop?.wifi_name || null,
      wifiPass: prop?.wifi_password || null,
      parking: prop?.parking_information || null,
      rules: prop?.house_rules || null,
      confirmed_at: rec.confirmed_at || r.checkin_confirmed_at || null,
      reservation_id: r.id,
    },
    rec, r,
  };
}





// ─── Router ────────────────────────────────────────────────────
async function handle(req, res) {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': resolveCorsHeader(req),
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PATCH,DELETE,OPTIONS',
      'Vary': 'Origin',
    });
    return res.end();
  }

  const url = new URL(req.url, `http://localhost:${PORT}`);
  const p = url.pathname;
  const method = req.method;

  try {
    // Rate limit global API (hors health/static)
    if (p.startsWith('/api/') && p !== '/api/health' && !p.startsWith('/api/webhooks/')) {
      const ip = clientIp(req);
      if (!rateLimit('api:' + ip, 300, 60 * 1000)) {
        return json(res, 429, { error: 'Trop de requêtes' });
      }
    }

    if (method === 'GET' && p === '/api/security/status') {
      const user = requireAuth(req, res);
      if (!user) return;
      return json(res, 200, {
        password_hashing: 'scrypt',
        jwt: 'HS256',
        multi_tenant: true,
        rate_limit: true,
        login_lockout: true,
        stripe_configured: stripeConfigured(),
        email_configured: !!(process.env.EMAIL_PROVIDER && process.env.EMAIL_API_KEY),
        ai_configured: !!(process.env.AI_API_KEY),
        cors_origin: process.env.CORS_ORIGIN || '*',
        secrets_in_frontend: false,
      });
    }


    // Health
    if (method === 'GET' && p === '/api/health') {
      return json(res, 200, { status: 'ok', product: 'HostPilot', version: '2.0.0', storage: 'json-file', multiTenant: true, note: 'POSTGRESQL_MIGRATION_REQUIRED for multi-node SaaS' });
    }

    // ── AUTH ──
    if (method === 'POST' && p === '/api/auth/register') {
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      const password = body.password || '';
      if (!email || !email.includes('@')) return json(res, 400, { error: 'Email invalide' });
      if (password.length < 8) return json(res, 400, { error: 'Mot de passe min 8 caractères' });
      if (DB.users.find(u => u.email === email)) return json(res, 409, { error: 'Email déjà utilisé' });

      const userId = uid();
      const orgId = uid();
      const user = {
        id: userId,
        email,
        password_hash: hashPassword(password),
        first_name: body.first_name || body.name || email.split('@')[0],
        last_name: body.last_name || '',
        phone: body.phone || null,
        role: 'owner',
        status: 'active',
        last_login_at: new Date().toISOString(),
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      const org = {
        id: orgId,
        name: body.organization_name || `Organisation de ${user.first_name}`,
        owner_id: userId,
        plan: 'starter',
        subscription_status: 'trialing',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.users.push(user);
      DB.organizations.push(org);
      DB.organization_members.push({
        id: uid(),
        organization_id: orgId,
        user_id: userId,
        role: 'owner',
        created_at: new Date().toISOString(),
      });
      DB.subscriptions.push({
        id: uid(),
        organization_id: orgId,
        plan: 'starter',
        status: 'trialing',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      // Default automations
      const defaultAutos = [
        { name: 'Bienvenue nouvelle réservation', event_type: 'RESERVATION_CREATED', actions: [{ type: 'notify', title: 'Nouvelle réservation', message: '{{guest_first_name}} — {{property_name}}' }, { type: 'generate_checkin_link' }, { type: 'send_message', template: 'Bonjour {{guest_first_name}}, bienvenue chez {{property_name}} ! Check-in le {{check_in_date}} à {{check_in_time}}.' }] },
        { name: 'Ménage au départ', event_type: 'CHECK_OUT_COMPLETED', actions: [{ type: 'create_cleaning_task' }] },
      ];
      for (const a of defaultAutos) {
        DB.automations.push({
          id: uid(),
          organization_id: orgId,
          name: a.name,
          description: '',
          enabled: 1,
          event_type: a.event_type,
          conditions_json: null,
          actions_json: JSON.stringify(a.actions),
          created_by: userId,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
        });
      }
      saveDb(DB);
      audit(orgId, userId, 'user.register', 'user', userId);
      const token = signJWT({ sub: userId, email, role: 'owner', org: orgId });
      return json(res, 201, {
        user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, role: 'owner' },
        organization: { id: org.id, name: org.name, plan: org.plan },
        token,
      });
    }

    if (method === 'POST' && p === '/api/auth/login') {
      const ip = clientIp(req);
      if (!rateLimit('login:' + ip, 20, 15 * 60 * 1000)) {
        return json(res, 429, { error: 'Trop de tentatives — réessayez plus tard' });
      }
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      const failKey = 'fail:' + email;
      const fails = loginFailures.get(failKey) || { count: 0, until: 0 };
      if (fails.until && Date.now() < fails.until) {
        return json(res, 429, { error: 'Compte temporairement verrouillé — réessayez plus tard' });
      }
      const user = DB.users.find(u => u.email === email);
      if (!user || !verifyPassword(body.password || '', user.password_hash)) {
        fails.count++;
        if (fails.count >= 8) fails.until = Date.now() + 15 * 60 * 1000;
        loginFailures.set(failKey, fails);
        return json(res, 401, { error: 'Email ou mot de passe incorrect' });
      }
      loginFailures.delete(failKey);
      user.last_login_at = new Date().toISOString();
      saveDb(DB);
      const ctx = getUserOrg(user.id);
      const token = signJWT({ sub: user.id, email: user.email, role: ctx?.role || user.role, org: ctx?.org?.id });
      audit(ctx?.org?.id, user.id, 'user.login', 'user', user.id);
      return json(res, 200, {
        user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, role: ctx?.role || user.role },
        organization: ctx ? { id: ctx.org.id, name: ctx.org.name, plan: ctx.org.plan } : null,
        token,
      });
    }


    if (method === 'POST' && p === '/api/auth/forgot-password') {
      const ip = clientIp(req);
      if (!rateLimit('forgot:' + ip, 5, 15 * 60 * 1000)) {
        return json(res, 429, { error: 'Trop de tentatives' });
      }
      const body = await readBody(req);
      const email = (body.email || '').toLowerCase().trim();
      // Always same response (no user enumeration)
      const generic = { ok: true, message: 'Si un compte existe, un email de réinitialisation sera envoyé lorsque le service email est configuré.' };
      const user = DB.users.find(u => u.email === email);
      if (user) {
        const raw = uid() + uid();
        DB.password_resets = DB.password_resets || [];
        DB.password_resets.push({
          id: uid(),
          user_id: user.id,
          token_hash: crypto.createHash('sha256').update(raw).digest('hex'),
          expires_at: new Date(Date.now() + 3600 * 1000).toISOString(),
          used_at: null,
        });
        saveDb(DB);
        if (!(process.env.EMAIL_PROVIDER && process.env.EMAIL_API_KEY)) {
          // Configuration requise — ne pas renvoyer le token au client
        }
      }
      return json(res, 200, generic);
    }

    if (method === 'POST' && p === '/api/auth/reset-password') {
      const body = await readBody(req);
      const token = body.token || '';
      const password = body.password || '';
      if (password.length < 8) return json(res, 400, { error: 'Mot de passe min 8 caractères' });
      const hash = crypto.createHash('sha256').update(token).digest('hex');
      const row = (DB.password_resets || []).find(r => r.token_hash === hash && !r.used_at);
      if (!row || new Date(row.expires_at) < new Date()) {
        return json(res, 400, { error: 'Lien invalide ou expiré' });
      }
      const user = DB.users.find(u => u.id === row.user_id);
      if (!user) return json(res, 400, { error: 'Lien invalide ou expiré' });
      user.password_hash = hashPassword(password);
      user.updated_at = new Date().toISOString();
      row.used_at = new Date().toISOString();
      saveDb(DB);
      audit(null, user.id, 'user.password_reset', 'user', user.id);
      return json(res, 200, { ok: true });
    }


    if (method === 'GET' && p === '/api/auth/me') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = getUserOrg(user.id);
      return json(res, 200, {
        user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, role: ctx?.role || user.role },
        organization: ctx ? { id: ctx.org.id, name: ctx.org.name, plan: ctx.org.plan, subscription_status: ctx.org.subscription_status } : null,
      });
    }

    // ── PROPERTIES ──
    if (method === 'GET' && p === '/api/properties') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const list = DB.properties.filter(x => x.organization_id === ctx.org.id);
      return json(res, 200, { properties: list });
    }

    if (method === 'POST' && p === '/api/properties') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const lim = assertPlanLimit(ctx.org.id, 'properties');
      if (!lim.ok) return json(res, 403, { error: lim.error, code: lim.code });
      const body = await readBody(req);
      if (!body.name || !body.address) return json(res, 400, { error: 'Nom et adresse requis' });
      const prop = {
        id: uid(),
        organization_id: ctx.org.id,
        name: body.name,
        description: body.description || null,
        address: body.address,
        city: body.city || null,
        postal_code: body.postal_code || null,
        country: body.country || 'FR',
        checkin_time: body.checkin_time || '15h00',
        checkout_time: body.checkout_time || '11h00',
        wifi_name: body.wifi_name || null,
        wifi_password: body.wifi_password || null,
        entry_code: body.entry_code || null,
        parking_information: body.parking_information || null,
        house_rules: body.house_rules || null,
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.properties.push(prop);
      saveDb(DB);
      audit(ctx.org.id, user.id, 'property.created', 'property', prop.id);
      return json(res, 201, { property: prop });
    }

    if (method === 'DELETE' && p.startsWith('/api/properties/')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const id = p.split('/').pop();
      const idx = DB.properties.findIndex(x => x.id === id && x.organization_id === ctx.org.id);
      if (idx < 0) return json(res, 404, { error: 'Logement introuvable' });
      DB.properties.splice(idx, 1);
      saveDb(DB);
      audit(ctx.org.id, user.id, 'property.deleted', 'property', id);
      return json(res, 200, { ok: true });
    }

    // ── RESERVATIONS ──
    if (method === 'GET' && p === '/api/reservations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const list = DB.reservations
        .filter(r => r.organization_id === ctx.org.id)
        .map(r => {
          const prop = DB.properties.find(p => p.id === r.property_id);
          const guest = DB.guests.find(g => g.id === r.guest_id);
          return {
            ...r,
            property_name: prop?.name,
            guest_name: guest ? `${guest.first_name} ${guest.last_name || ''}`.trim() : null,
          };
        });
      return json(res, 200, { reservations: list });
    }

    if (method === 'POST' && p === '/api/reservations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const body = await readBody(req);
      const prop = DB.properties.find(x => x.id === body.property_id && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      if (!body.guest_name || !body.check_in || !body.check_out) {
        return json(res, 400, { error: 'guest_name, check_in, check_out requis' });
      }
      const guestId = uid();
      const parts = body.guest_name.trim().split(/\s+/);
      DB.guests.push({
        id: guestId,
        organization_id: ctx.org.id,
        first_name: parts[0],
        last_name: parts.slice(1).join(' ') || '',
        email: body.guest_email || null,
        phone: body.guest_phone || null,
        country: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      const resId = uid();
      const token = uid() + uid();
      const reservation = {
        id: resId,
        organization_id: ctx.org.id,
        property_id: prop.id,
        guest_id: guestId,
        external_id: body.external_id || null,
        platform: body.platform || 'direct',
        check_in: body.check_in,
        check_out: body.check_out,
        number_of_guests: body.number_of_guests || 1,
        status: 'confirmed',
        total_amount: body.total_amount || 0,
        currency: 'EUR',
        checkin_token_hash: null,
        checkin_status: 'pending',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.reservations.push(reservation);
      // Conversation
      const convId = uid();
      DB.conversations.push({
        id: convId,
        organization_id: ctx.org.id,
        property_id: prop.id,
        reservation_id: resId,
        guest_id: guestId,
        status: 'open',
        ai_enabled: 1,
        human_controlled: 0,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      });
      DB.notifications.push({
        id: uid(),
        organization_id: ctx.org.id,
        user_id: user.id,
        type: 'reservation',
        title: 'Nouvelle réservation',
        message: `${body.guest_name} — ${prop.name}`,
        read_at: null,
        created_at: new Date().toISOString(),
      });
      saveDb(DB);
      runAutomations('RESERVATION_CREATED', ctx.org.id, {
        property_id: prop.id,
        reservation_id: resId,
        guest_id: guestId,
        user_id: user.id,
        check_in: body.check_in,
        check_out: body.check_out,
        platform: body.platform || 'direct',
        status: 'confirmed',
      });
      audit(ctx.org.id, user.id, 'reservation.created', 'reservation', resId);
      return json(res, 201, { reservation, checkin_url: `/checkin/${token}` });
    }


    // ── CHECK-IN / CHECK-OUT / CLEANING WORKFLOW ──
    // Generate / regenerate check-in link (auth)
    if (method === 'POST' && p.match(/^\/api\/reservations\/[^/]+\/checkin-link$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const rid = p.split('/')[3];
      const r = DB.reservations.find(x => x.id === rid && x.organization_id === ctx.org.id);
      if (!r) return json(res, 404, { error: 'Réservation introuvable' });
      const { token, expires_at } = createCheckinToken(rid, ctx.org.id);
      saveDb(DB);
      audit(ctx.org.id, user.id, 'checkin.link_generated', 'reservation', rid);
      const base = (process.env.APP_URL || (IS_PROD ? '' : `http://localhost:${PORT}`));
      return json(res, 200, {
        checkin_url: `${base}/checkin.html?token=${token}`,
        token,
        expires_at,
      });
    }

    // Public check-in data (token validated server-side)
    if (method === 'GET' && p === '/api/checkin') {
      const token = url.searchParams.get('token') || '';
      const out = buildCheckinPayload(token);
      if (out.error) return json(res, out.error, out.body);
      return json(res, 200, out.body);
    }

    // Confirm check-in instructions received
    if (method === 'POST' && p === '/api/checkin/confirm') {
      const body = await readBody(req);
      const token = body.token || '';
      const rec = findTokenRecord(token);
      if (!rec) return json(res, 404, { error: 'Ce lien de check-in n\'est plus valide.' });
      const reservationId = rec.reservation_id || rec.id;
      const r = DB.reservations.find(x => x.id === reservationId);
      if (!r) return json(res, 404, { error: 'Ce lien de check-in n\'est plus valide.' });
      const now = new Date().toISOString();
      if (rec.confirmed_at !== undefined) rec.confirmed_at = now;
      if (rec.used_at !== undefined && !rec.used_at) rec.used_at = now;
      r.checkin_confirmed_at = now;
      r.checkin_status = 'instructions_received';
      saveDb(DB);
      audit(r.organization_id, null, 'checkin.confirmed', 'reservation', r.id);
      runAutomations('CHECK_IN_TODAY', r.organization_id, {
        property_id: r.property_id,
        reservation_id: r.id,
      });
      return json(res, 200, { ok: true, confirmed_at: now, message: 'Instructions confirmées et enregistrées' });
    }

    // Check-out confirm
    if (method === 'POST' && p.match(/^\/api\/reservations\/[^/]+\/checkout$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const rid = p.split('/')[3];
      const r = DB.reservations.find(x => x.id === rid && x.organization_id === ctx.org.id);
      if (!r) return json(res, 404, { error: 'Réservation introuvable' });
      const now = new Date().toISOString();
      // Idempotence: if already checked out with a cleaning task, return existing
      const existingTask = (DB.cleaning_tasks || []).find(
        t => t.reservation_id === r.id && t.organization_id === ctx.org.id
      );
      if (r.checkout_confirmed_at && existingTask) {
        return json(res, 200, {
          reservation: r,
          cleaning_task_id: existingTask.id,
          idempotent: true,
          message: 'Checkout déjà confirmé — aucune tâche de ménage supplémentaire créée',
        });
      }
      r.checkout_confirmed_at = now;
      r.status = 'completed';
      r.updated_at = now;
      let taskId = existingTask ? existingTask.id : uid();
      if (!existingTask) {
        DB.cleaning_tasks.push({
          id: taskId,
          organization_id: ctx.org.id,
          property_id: r.property_id,
          reservation_id: r.id,
          assigned_to: null,
          scheduled_at: now,
          started_at: null,
          completed_at: null,
          status: 'pending',
          notes: null,
          created_at: now,
          updated_at: now,
        });
        const defaults = ['Cuisine', 'Salle de bain', 'Sols', 'Lits', 'Serviettes', 'Poubelles', 'Équipements', 'Contrôle final'];
        for (const title of defaults) {
          DB.cleaning_checklists.push({
            id: uid(),
            cleaning_task_id: taskId,
            title,
            completed: 0,
            completed_at: null,
          });
        }
        for (const m of DB.organization_members.filter(x => x.organization_id === ctx.org.id)) {
          DB.notifications.push({
            id: uid(), organization_id: ctx.org.id, user_id: m.user_id,
            type: 'cleaning', title: 'Nouvelle tâche de ménage',
            message: 'Check-out terminé — ménage à planifier',
            read_at: null, created_at: now,
          });
        }
      }
      saveDb(DB);
      if (!existingTask) {
        runAutomations('CHECK_OUT_COMPLETED', ctx.org.id, {
          property_id: r.property_id,
          reservation_id: r.id,
          check_out: r.check_out,
          user_id: user.id,
        });
        audit(ctx.org.id, user.id, 'checkout.confirmed', 'reservation', rid);
      }
      return json(res, 200, { reservation: r, cleaning_task_id: taskId, idempotent: !!existingTask });
    }

    // Toggle checklist item
    if (method === 'PATCH' && p.match(/^\/api\/cleaning\/[^/]+\/checklist\/[^/]+$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const parts = p.split('/');
      const taskId = parts[3];
      const itemId = parts[5];
      const task = DB.cleaning_tasks.find(t => t.id === taskId && t.organization_id === ctx.org.id);
      if (!task) return json(res, 404, { error: 'Tâche introuvable' });
      if (ctx.role === 'cleaner' && task.assigned_to && task.assigned_to !== user.id) {
        return json(res, 403, { error: 'Tâche non assignée à vous' });
      }
      const item = DB.cleaning_checklists.find(c => c.id === itemId && c.cleaning_task_id === taskId);
      if (!item) return json(res, 404, { error: 'Item introuvable' });
      const body = await readBody(req);
      item.completed = body.completed ? 1 : 0;
      item.completed_at = body.completed ? new Date().toISOString() : null;
      saveDb(DB);
      return json(res, 200, { item });
    }

    // Report cleaning problem → incident
    if (method === 'POST' && p.match(/^\/api\/cleaning\/[^/]+\/problem$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const taskId = p.split('/')[3];
      const task = DB.cleaning_tasks.find(t => t.id === taskId && t.organization_id === ctx.org.id);
      if (!task) return json(res, 404, { error: 'Tâche introuvable' });
      const body = await readBody(req);
      if (!body.description) return json(res, 400, { error: 'description requise' });
      task.status = 'problem_reported';
      task.updated_at = new Date().toISOString();
      const inc = {
        id: uid(),
        organization_id: ctx.org.id,
        property_id: task.property_id,
        reservation_id: task.reservation_id,
        reported_by: user.id,
        title: body.title || 'Problème de ménage',
        description: body.description,
        category: body.category || 'cleaning',
        severity: body.severity || 'medium',
        status: 'open',
        cleaning_task_id: taskId,
        resolved_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.incidents.push(inc);
      for (const m of DB.organization_members.filter(x => x.organization_id === ctx.org.id)) {
        if (['owner', 'admin', 'manager'].includes(m.role)) {
          DB.notifications.push({
            id: uid(), organization_id: ctx.org.id, user_id: m.user_id,
            type: 'incident', title: 'Problème ménage', message: body.description.slice(0, 120),
            read_at: null, created_at: new Date().toISOString(),
          });
        }
      }
      saveDb(DB);
      runAutomations('CLEANING_PROBLEM_REPORTED', ctx.org.id, {
        property_id: task.property_id,
        reservation_id: task.reservation_id,
      });
      audit(ctx.org.id, user.id, 'cleaning.problem', 'cleaning_task', taskId);
      return json(res, 201, { incident: inc, task });
    }


    // Legacy path /api/checkin/:token — same security rules as ?token=
    if (method === 'GET' && p.startsWith('/api/checkin/') && p !== '/api/checkin/confirm') {
      const token = p.split('/').pop();
      if (token === 'confirm') { /* fallthrough handled below */ }
      else {
        const out = buildCheckinPayload(token);
        if (out.error) return json(res, out.error, out.body);
        return json(res, 200, out.body);
      }
    }

    if (method === 'POST' && p.match(/^\/api\/checkin\/[^/]+\/confirm$/)) {
      const token = p.split('/')[3];
      const out = buildCheckinPayload(token);
      if (out.error) return json(res, out.error, out.body);
      const now = new Date().toISOString();
      if (out.rec && out.rec.confirmed_at !== undefined) out.rec.confirmed_at = now;
      if (out.rec && out.rec.used_at !== undefined && !out.rec.used_at) out.rec.used_at = now;
      out.r.checkin_confirmed_at = now;
      out.r.checkin_status = 'instructions_received';
      saveDb(DB);
      audit(out.r.organization_id, null, 'checkin.confirmed', 'reservation', out.r.id);
      return json(res, 200, { ok: true, confirmed_at: now, message: 'Instructions confirmées et enregistrées' });
    }

    // legacy simple dashboard removed — use /api/dashboard

    // ── CLEANING ──
    if (method === 'GET' && p === '/api/cleaning') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      let tasks = DB.cleaning_tasks.filter(t => t.organization_id === ctx.org.id);
      if (ctx.role === 'cleaner') {
        tasks = tasks.filter(t => t.assigned_to === user.id);
      }
      const enriched = tasks.map(t => ({
        ...t,
        property_name: DB.properties.find(p => p.id === t.property_id)?.name,
        checks: DB.cleaning_checklists.filter(c => c.cleaning_task_id === t.id),
      }));
      return json(res, 200, { tasks: enriched });
    }

    if (method === 'PATCH' && p.startsWith('/api/cleaning/')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const task = DB.cleaning_tasks.find(t => t.id === id && t.organization_id === ctx.org.id);
      if (!task) return json(res, 404, { error: 'Tâche introuvable' });
      const body = await readBody(req);
      if (body.status) {
        task.status = body.status;
        if (body.status === 'completed') {
          task.completed_at = new Date().toISOString();
          runAutomations('cleaning.completed', ctx.org.id, { property_id: task.property_id, user_id: user.id });
        }
        if (body.status === 'in_progress') task.started_at = new Date().toISOString();
      }
      if (body.assigned_to !== undefined) {
        task.assigned_to = body.assigned_to;
        if (body.assigned_to && (!task.status || task.status === 'pending')) task.status = 'assigned';
      }
      if (body.notes !== undefined) task.notes = body.notes;
      task.updated_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { task });
    }


    if (method === 'POST' && p.match(/^\/api\/cleaning\/[^/]+\/photos$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const taskId = p.split('/')[3];
      const task = DB.cleaning_tasks.find(t => t.id === taskId && t.organization_id === ctx.org.id);
      if (!task) return json(res, 404, { error: 'Tâche introuvable' });
      const body = await readBody(req);
      if (!body.data_base64) return json(res, 400, { error: 'data_base64 requis' });
      const raw = String(body.data_base64).replace(/^data:image\/\w+;base64,/, '');
      if (raw.length > 2_500_000) return json(res, 400, { error: 'Fichier trop volumineux (max ~1.5MB)' });
      const uploadDir = path.join(__dirname, '../data/uploads', ctx.org.id);
      if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });
      const fname = `${taskId}_${uid()}.jpg`;
      const fpath = path.join(uploadDir, fname);
      fs.writeFileSync(fpath, Buffer.from(raw, 'base64'));
      const photo = {
        id: uid(),
        cleaning_task_id: taskId,
        uploaded_by: user.id,
        storage_path: fpath,
        storage_url: `/api/uploads/${ctx.org.id}/${fname}`,
        created_at: new Date().toISOString(),
      };
      DB.cleaning_photos = DB.cleaning_photos || [];
      DB.cleaning_photos.push(photo);
      saveDb(DB);
      return json(res, 201, { photo: { id: photo.id, storage_url: photo.storage_url, created_at: photo.created_at } });
    }


    // ── INCIDENTS ──
    if (method === 'GET' && p === '/api/incidents') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const list = DB.incidents
        .filter(i => i.organization_id === ctx.org.id)
        .map(i => ({ ...i, property_name: DB.properties.find(p => p.id === i.property_id)?.name }));
      return json(res, 200, { incidents: list });
    }

    if (method === 'POST' && p === '/api/incidents') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const body = await readBody(req);
      const prop = DB.properties.find(x => x.id === body.property_id && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const inc = {
        id: uid(),
        organization_id: ctx.org.id,
        property_id: prop.id,
        reservation_id: body.reservation_id || null,
        reported_by: user.id,
        title: body.title || 'Incident',
        description: body.description || null,
        category: body.category || 'other',
        severity: body.severity || 'low',
        status: 'open',
        resolved_at: null,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.incidents.push(inc);
      if (inc.severity === 'critical' || inc.severity === 'high') {
        DB.notifications.push({
          id: uid(),
          organization_id: ctx.org.id,
          user_id: user.id,
          type: 'incident',
          title: 'Incident urgent',
          message: inc.title,
          read_at: null,
          created_at: new Date().toISOString(),
        });
      }
      saveDb(DB);
      audit(ctx.org.id, user.id, 'incident.created', 'incident', inc.id);
      return json(res, 201, { incident: inc });
    }

    if (method === 'PATCH' && p.startsWith('/api/incidents/')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/').pop();
      const inc = DB.incidents.find(i => i.id === id && i.organization_id === ctx.org.id);
      if (!inc) return json(res, 404, { error: 'Incident introuvable' });
      const body = await readBody(req);
      if (body.status) {
        inc.status = body.status;
        if (body.status === 'resolved') inc.resolved_at = new Date().toISOString();
      }
      inc.updated_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { incident: inc });
    }


    // ── MESSAGES / CONVERSATIONS ──
    if (method === 'GET' && p === '/api/conversations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const list = DB.conversations
        .filter(c => c.organization_id === ctx.org.id)
        .map(c => {
          const msgs = DB.messages.filter(m => m.conversation_id === c.id);
          const last = msgs.sort((a,b) => (a.created_at < b.created_at ? 1 : -1))[0];
          const prop = DB.properties.find(x => x.id === c.property_id);
          const guest = DB.guests.find(g => g.id === c.guest_id);
          return {
            ...c,
            property_name: prop?.name,
            guest_name: guest ? `${guest.first_name} ${guest.last_name||''}`.trim() : null,
            last_message: last?.content || null,
            last_message_at: last?.created_at || c.updated_at,
            message_count: msgs.length,
          };
        })
        .sort((a,b) => (a.last_message_at < b.last_message_at ? 1 : -1));
      return json(res, 200, { conversations: list });
    }

    if (method === 'GET' && p.match(/^\/api\/conversations\/[^/]+\/messages$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const conv = DB.conversations.find(c => c.id === id && c.organization_id === ctx.org.id);
      if (!conv) return json(res, 404, { error: 'Conversation introuvable' });
      const messages = DB.messages.filter(m => m.conversation_id === id)
        .sort((a,b) => (a.created_at > b.created_at ? 1 : -1));
      return json(res, 200, { conversation: conv, messages });
    }

    if (method === 'POST' && p.match(/^\/api\/conversations\/[^/]+\/messages$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const conv = DB.conversations.find(c => c.id === id && c.organization_id === ctx.org.id);
      if (!conv) return json(res, 404, { error: 'Conversation introuvable' });
      const body = await readBody(req);
      if (!body.content || !String(body.content).trim()) return json(res, 400, { error: 'content requis' });

      // Message humain sortant
      if (body.sender_type === 'human' || body.as_host) {
        const m = {
          id: uid(),
          conversation_id: id,
          sender_type: 'human',
          sender_id: user.id,
          content: body.content.trim(),
          channel: body.channel || 'internal',
          delivery_status: (body.channel && body.channel !== 'internal') ? 'pending' : 'sent',
          delivery_note: (body.channel && body.channel !== 'internal')
            ? 'Configuration requise pour envoi sur la plateforme'
            : null,
          created_at: new Date().toISOString(),
        };
        DB.messages.push(m);
        conv.updated_at = new Date().toISOString();
        saveDb(DB);
        audit(ctx.org.id, user.id, 'message.human_sent', 'conversation', id);
        return json(res, 201, { message: m });
      }

      // Message voyageur (simulation canal interne pour tests) → pipeline IA
      const result = await handleInboundGuestMessage(id, body.content.trim(), body.channel || 'internal');
      return json(res, 201, result);
    }

    if (method === 'PATCH' && p.match(/^\/api\/conversations\/[^/]+$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const conv = DB.conversations.find(c => c.id === id && c.organization_id === ctx.org.id);
      if (!conv) return json(res, 404, { error: 'Conversation introuvable' });
      const body = await readBody(req);
      if (body.human_controlled !== undefined) {
        conv.human_controlled = body.human_controlled ? 1 : 0;
        if (body.human_controlled) {
          conv.ai_enabled = 0;
          conv.status = 'human_control';
          audit(ctx.org.id, user.id, 'conversation.take_control', 'conversation', id);
        } else {
          conv.ai_enabled = 1;
          conv.status = 'open';
          audit(ctx.org.id, user.id, 'conversation.reactivate_ai', 'conversation', id);
        }
      }
      if (body.ai_enabled !== undefined) conv.ai_enabled = body.ai_enabled ? 1 : 0;
      if (body.status) conv.status = body.status;
      conv.updated_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { conversation: conv });
    }

    // Knowledge base CRUD
    if (method === 'GET' && p.match(/^\/api\/properties\/[^/]+\/knowledge$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      return json(res, 200, { knowledge: getPropertyKnowledge(propId), property: { id: prop.id, name: prop.name, address: prop.address, checkin_time: prop.checkin_time, checkout_time: prop.checkout_time, wifi_name: prop.wifi_name, entry_code: prop.entry_code ? '***' : null, parking_information: prop.parking_information, house_rules: prop.house_rules } });
    }

    if (method === 'POST' && p.match(/^\/api\/properties\/[^/]+\/knowledge$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const body = await readBody(req);
      if (!body.content) return json(res, 400, { error: 'content requis' });
      const k = {
        id: uid(), property_id: propId, category: body.category || 'general',
        title: body.title || '', content: body.content, is_active: 1,
        created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
      };
      DB.property_knowledge = DB.property_knowledge || [];
      DB.property_knowledge.push(k);
      saveDb(DB);
      return json(res, 201, { knowledge: k });
    }


    // ── AUTOMATIONS ──
    if (method === 'GET' && p === '/api/automations/events') {
      const user = requireAuth(req, res);
      if (!user) return;
      return json(res, 200, { events: [
        'RESERVATION_CREATED','RESERVATION_UPDATED','RESERVATION_CANCELLED',
        'CHECK_IN_APPROACHING','CHECK_IN_TODAY','CHECK_OUT_APPROACHING','CHECK_OUT_TODAY','CHECK_OUT_COMPLETED',
        'CLEANING_COMPLETED','INCIDENT_CREATED','INCIDENT_RESOLVED','GUEST_MESSAGE_RECEIVED'
      ], actions: [
        'send_message','create_cleaning_task','notify','generate_checkin_link','create_incident','send_email'
      ]});
    }

    if (method === 'GET' && p === '/api/automations/runs') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const runs = DB.automation_runs
        .filter(r => r.organization_id === ctx.org.id)
        .slice(-50)
        .reverse();
      return json(res, 200, { runs });
    }

    if (method === 'GET' && p === '/api/automations/jobs') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const jobs = (DB.jobs || []).filter(j => j.organization_id === ctx.org.id).slice(-50).reverse();
      return json(res, 200, { jobs });
    }

    if (method === 'POST' && p === '/api/automations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const body = await readBody(req);
      if (!body.name || !body.event_type) return json(res, 400, { error: 'name et event_type requis' });
      const auto = {
        id: uid(),
        organization_id: ctx.org.id,
        name: body.name,
        description: body.description || '',
        enabled: body.enabled !== false ? 1 : 0,
        event_type: body.event_type,
        conditions_json: JSON.stringify(body.conditions || []),
        actions_json: JSON.stringify(body.actions || []),
        created_by: user.id,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.automations.push(auto);
      saveDb(DB);
      audit(ctx.org.id, user.id, 'automation.created', 'automation', auto.id);
      return json(res, 201, { automation: auto });
    }


    if (method === 'GET' && p === '/api/automations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      return json(res, 200, { automations: DB.automations.filter(a => a.organization_id === ctx.org.id) });
    }

    if (method === 'PATCH' && p.startsWith('/api/automations/')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const id = p.split('/').pop();
      const auto = DB.automations.find(a => a.id === id && a.organization_id === ctx.org.id);
      if (!auto) return json(res, 404, { error: 'Introuvable' });
      const body = await readBody(req);
      if (body.enabled !== undefined) auto.enabled = body.enabled ? 1 : 0;
      auto.updated_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { automation: auto });
    }

    // ── INTEGRATIONS (OAuth officiel uniquement — jamais de faux connecté) ──
    function platformConfig(platform) {
      const env = process.env;
      const map = {
        airbnb: {
          name: 'Airbnb',
          clientId: env.AIRBNB_CLIENT_ID,
          clientSecret: env.AIRBNB_CLIENT_SECRET,
          authUrl: env.AIRBNB_AUTH_URL || 'https://www.airbnb.com/oauth2/auth',
          tokenUrl: env.AIRBNB_TOKEN_URL || 'https://api.airbnb.com/v2/oauth2/authorizations',
          docs: 'https://www.airbnb.com/partner',
          note: 'API Partenaire Airbnb : partenariat / approbation développeur requis. OAuth officiel uniquement.',
        },
        booking: {
          name: 'Booking.com',
          clientId: env.BOOKING_CLIENT_ID,
          clientSecret: env.BOOKING_CLIENT_SECRET,
          authUrl: env.BOOKING_AUTH_URL || '',
          tokenUrl: env.BOOKING_TOKEN_URL || '',
          docs: 'https://developers.booking.com',
          note: 'Connectivity API Booking.com : compte partenaire et credentials officiels requis.',
        },
        vrbo: {
          name: 'Vrbo (Expedia Group)',
          clientId: env.VRBO_CLIENT_ID || env.EXPEDIA_CLIENT_ID,
          clientSecret: env.VRBO_CLIENT_SECRET || env.EXPEDIA_CLIENT_SECRET,
          authUrl: env.VRBO_AUTH_URL || '',
          tokenUrl: env.VRBO_TOKEN_URL || '',
          docs: 'https://developer.expediagroup.com',
          note: 'API Expedia Group / Vrbo : partenariat développeur et credentials officiels requis.',
        },
      };
      return map[platform] || null;
    }

    if (method === 'GET' && p === '/api/integrations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const platforms = ['airbnb', 'booking', 'vrbo'];
      const list = platforms.map(platform => {
        const cfg = platformConfig(platform);
        const row = DB.integrations.find(i => i.organization_id === ctx.org.id && i.platform === platform);
        const apiConfigured = !!(cfg && cfg.clientId && cfg.clientSecret);
        let status = 'configuration_required';
        let message = cfg ? cfg.note : 'Plateforme inconnue';
        if (row) {
          status = row.status || 'disconnected';
          if (row.last_error) message = row.last_error;
          else if (status === 'connected') message = 'Connecté via OAuth officiel';
          else if (status === 'error') message = row.last_error || 'Erreur — reconnexion requise';
        }
        if (!apiConfigured && status !== 'connected') {
          status = 'configuration_required';
          message = (cfg && cfg.note) || 'Configuration requise';
        }
        return {
          platform,
          name: cfg?.name || platform,
          status,
          apiConfigured,
          message,
          docs: cfg?.docs || null,
          last_sync_at: row?.last_sync_at || null,
          last_sync_status: row?.last_sync_status || null,
          canConnect: apiConfigured,
          canSync: apiConfigured && status === 'connected',
        };
      });
      return json(res, 200, { integrations: list });
    }

    // Démarrer OAuth — uniquement si credentials serveur présents
    if (method === 'POST' && p.startsWith('/api/integrations/') && p.endsWith('/connect')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const platform = p.split('/')[3];
      const cfg = platformConfig(platform);
      if (!cfg) return json(res, 404, { error: 'Plateforme inconnue' });
      if (!cfg.clientId || !cfg.clientSecret) {
        return json(res, 503, {
          error: 'Configuration requise',
          message: cfg.note,
          docs: cfg.docs,
          env_vars: platform === 'airbnb'
            ? ['AIRBNB_CLIENT_ID', 'AIRBNB_CLIENT_SECRET']
            : platform === 'booking'
            ? ['BOOKING_CLIENT_ID', 'BOOKING_CLIENT_SECRET']
            : ['VRBO_CLIENT_ID', 'VRBO_CLIENT_SECRET'],
        });
      }
      if (!cfg.authUrl) {
        return json(res, 503, {
          error: 'Configuration requise',
          message: 'URL OAuth non configurée pour cette plateforme. Renseignez les variables d\'environnement officielles.',
          docs: cfg.docs,
        });
      }
      const state = uid();
      if (IS_PROD && !oauthCryptoReady()) {
        return json(res, 503, {
          error: 'Configuration requise',
          message: 'OAUTH_ENCRYPTION_KEY obligatoire en production pour stocker les tokens OAuth',
        });
      }

      // store pending oauth state (no secrets in response)
      let row = DB.integrations.find(i => i.organization_id === ctx.org.id && i.platform === platform);
      if (!row) {
        row = {
          id: uid(),
          organization_id: ctx.org.id,
          platform,
          status: 'pending_oauth',
          external_account_id: null,
          last_sync_at: null,
          last_sync_status: null,
          error_message: null,
          oauth_state: state,
          created_at: new Date().toISOString(),
        };
        DB.integrations.push(row);
      } else {
        row.status = 'pending_oauth';
        row.oauth_state = state;
      }
      saveDb(DB);
      const redirectUri = ((process.env.APP_URL || (IS_PROD ? '' : `http://localhost:${PORT}`))) + `/api/integrations/${platform}/callback`;
      const authUrl = `${cfg.authUrl}?client_id=${encodeURIComponent(cfg.clientId)}&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&state=${state}`;
      audit(ctx.org.id, user.id, 'integration.connect_started', 'integration', platform);
      return json(res, 200, {
        status: 'redirect',
        message: 'Redirection vers la page OAuth officielle de la plateforme',
        authUrl,
        // jamais de client_secret ici
      });
    }

    // Callback OAuth (échange code → tokens côté serveur uniquement)
    if (method === 'GET' && p.startsWith('/api/integrations/') && p.endsWith('/callback')) {
      const platform = p.split('/')[3];
      const cfg = platformConfig(platform);
      const code = url.searchParams.get('code');
      const state = url.searchParams.get('state');
      const err = url.searchParams.get('error');
      if (err || !code || !state || !cfg) {
        res.writeHead(302, { Location: '/?integration=error' });
        return res.end();
      }
      const row = DB.integrations.find(i => i.oauth_state === state && i.platform === platform);
      if (!row) {
        res.writeHead(302, { Location: '/?integration=invalid_state' });
        return res.end();
      }
      if (!cfg.clientId || !cfg.clientSecret || !cfg.tokenUrl) {
        row.status = 'configuration_required';
        row.error_message = 'Credentials OAuth manquants côté serveur';
        saveDb(DB);
        res.writeHead(302, { Location: '/?integration=config_required' });
        return res.end();
      }
      // Échange réel du code (fetch) — échoue proprement si API non accessible
      try {
        const redirectUri = ((process.env.APP_URL || (IS_PROD ? '' : `http://localhost:${PORT}`))) + `/api/integrations/${platform}/callback`;
        const tokenRes = await fetch(cfg.tokenUrl, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
          body: JSON.stringify({
            client_id: cfg.clientId,
            client_secret: cfg.clientSecret,
            code,
            grant_type: 'authorization_code',
            redirect_uri: redirectUri,
          }),
        });
        if (!tokenRes.ok) {
          row.status = 'error';
          row.error_message = 'Échec échange token OAuth — vérifiez le partenariat et les credentials';
          row.oauth_state = null;
          saveDb(DB);
          res.writeHead(302, { Location: '/?integration=token_error' });
          return res.end();
        }
        const tokens = await tokenRes.json();
        // Tokens stockés uniquement serveur — jamais renvoyés au client
        row.status = 'connected';
        row.error_message = null;
        row.oauth_state = null;
        row.external_account_id = tokens.user_id || tokens.account_id || null;
        if (!oauthCryptoReady()) {
          row.status = 'error';
          row.error_message = 'OAUTH_ENCRYPTION_KEY requis pour stocker les tokens';
          row._access_token = null;
          row._refresh_token = null;
          saveDb(DB);
          res.writeHead(302, { Location: '/?page=settings&integration=' + platform + '&error=encryption_key' });
          return res.end();
        }
        row._access_token = encryptSecret(tokens.access_token || '') || null;
        row._refresh_token = tokens.refresh_token ? encryptSecret(tokens.refresh_token) : null;
        /* refresh encrypted above */
        row.token_expiration = tokens.expires_in
          ? new Date(Date.now() + tokens.expires_in * 1000).toISOString()
          : null;
        row.updated_at = new Date().toISOString();
        saveDb(DB);
        audit(row.organization_id, null, 'integration.connected', 'integration', platform);
        res.writeHead(302, { Location: '/?integration=connected' });
        return res.end();
      } catch (e) {
        row.status = 'error';
        row.error_message = 'Impossible de joindre l\'API OAuth de la plateforme';
        row.oauth_state = null;
        saveDb(DB);
        res.writeHead(302, { Location: '/?integration=network_error' });
        return res.end();
      }
    }

    // Déconnecter
    if (method === 'POST' && p.startsWith('/api/integrations/') && p.endsWith('/disconnect')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const platform = p.split('/')[3];
      const row = DB.integrations.find(i => i.organization_id === ctx.org.id && i.platform === platform);
      if (row) {
        row.status = 'disconnected';
        row._access_token = null;
        row._refresh_token = null;
        row.token_expiration = null;
        row.external_account_id = null;
        row.oauth_state = null;
        row.error_message = null;
        row.updated_at = new Date().toISOString();
        saveDb(DB);
        audit(ctx.org.id, user.id, 'integration.disconnected', 'integration', platform);
      }
      return json(res, 200, { ok: true, status: 'disconnected' });
    }

    // Synchroniser — uniquement si vraiment connecté + credentials
    if (method === 'POST' && p.startsWith('/api/integrations/') && p.endsWith('/sync')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const platform = p.split('/')[3];
      const cfg = platformConfig(platform);
      const row = DB.integrations.find(i => i.organization_id === ctx.org.id && i.platform === platform);
      if (!cfg?.clientId) {
        return json(res, 503, { error: 'Configuration requise', message: cfg?.note || 'Credentials manquants' });
      }
      if (!row || row.status !== 'connected' || !row._access_token) {
        return json(res, 400, {
          error: 'Non connecté',
          message: 'Connectez d\'abord la plateforme via OAuth officiel, ou reconnection requise.',
        });
      }
      // Sans endpoints partenaires réels approuvés, on n'invente aucune réservation
      row.last_sync_at = new Date().toISOString();
      row.last_sync_status = 'PARTNER_API_REQUIRED';
      row.error_message = 'PARTNER_API_REQUIRED — partenariat officiel requis. Aucune donnée synchronisée.';
      saveDb(DB);
      audit(ctx.org.id, user.id, 'integration.sync_blocked', 'integration', platform);
      return json(res, 503, {
        ok: false,
        error: 'PARTNER_API_REQUIRED',
        code: 'PARTNER_API_REQUIRED',
        synced: 0,
        message: row.error_message,
        last_sync_at: row.last_sync_at,
        docs: cfg.docs || null,
      });
    }



    // ── NOTIFICATIONS ──
    if (method === 'GET' && p === '/api/notifications') {
      const user = requireAuth(req, res);
      if (!user) return;
      const list = (DB.notifications || [])
        .filter(n => n.user_id === user.id)
        .sort((a, b) => (a.created_at < b.created_at ? 1 : -1))
        .slice(0, 100);
      return json(res, 200, { notifications: list });
    }

    if (method === 'GET' && p === '/api/notifications/unread-count') {
      const user = requireAuth(req, res);
      if (!user) return;
      const count = (DB.notifications || []).filter(n => n.user_id === user.id && !n.read).length;
      return json(res, 200, { count });
    }

    if (method === 'PUT' && p.match(/^\/api\/notifications\/[^/]+\/read$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const id = p.split('/')[3];
      const n = (DB.notifications || []).find(x => x.id === id && x.user_id === user.id);
      if (!n) return json(res, 404, { error: 'Notification introuvable' });
      n.read = 1;
      n.read_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { notification: n });
    }

    if (method === 'PUT' && p.match(/^\/api\/notifications\/[^/]+\/unread$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const id = p.split('/')[3];
      const n = (DB.notifications || []).find(x => x.id === id && x.user_id === user.id);
      if (!n) return json(res, 404, { error: 'Notification introuvable' });
      n.read = 0;
      n.read_at = null;
      saveDb(DB);
      return json(res, 200, { notification: n });
    }

    if (method === 'POST' && p === '/api/notifications/read-all') {
      const user = requireAuth(req, res);
      if (!user) return;
      const now = new Date().toISOString();
      for (const n of (DB.notifications || []).filter(x => x.user_id === user.id && !x.read)) {
        n.read = 1;
        n.read_at = now;
      }
      saveDb(DB);
      return json(res, 200, { ok: true });
    }

    if (method === 'GET' && p === '/api/notification-preferences') {
      const user = requireAuth(req, res);
      if (!user) return;
      let prefs = (DB.notification_preferences || []).find(x => x.user_id === user.id);
      if (!prefs) {
        prefs = {
          user_id: user.id,
          categories: { reservation: true, message: true, cleaning: true, incident: true, checkin: true, checkout: true, automation: true, integration: true, system: true },
          email_categories: { reservation: false, message: false, cleaning: false, incident: true, automation: false, integration: true },
          push_categories: {},
        };
      }
      const emailConfigured = !!(process.env.EMAIL_PROVIDER && process.env.EMAIL_API_KEY && process.env.EMAIL_FROM);
      const pushConfigured = false;
      return json(res, 200, {
        preferences: prefs,
        channels: {
          in_app: true,
          email: emailConfigured ? 'ready' : 'Configuration requise',
          push: pushConfigured ? 'ready' : 'Configuration requise',
        },
      });
    }

    if (method === 'PUT' && p === '/api/notification-preferences') {
      const user = requireAuth(req, res);
      if (!user) return;
      const body = await readBody(req);
      DB.notification_preferences = DB.notification_preferences || [];
      let prefs = DB.notification_preferences.find(x => x.user_id === user.id);
      if (!prefs) {
        prefs = { user_id: user.id, categories: {}, email_categories: {}, push_categories: {} };
        DB.notification_preferences.push(prefs);
      }
      if (body.categories) prefs.categories = { ...prefs.categories, ...body.categories };
      if (body.email_categories) prefs.email_categories = { ...prefs.email_categories, ...body.email_categories };
      if (body.push_categories) prefs.push_categories = { ...prefs.push_categories, ...body.push_categories };
      prefs.updated_at = new Date().toISOString();
      saveDb(DB);
      audit(null, user.id, 'notification.preferences_updated', 'user', user.id);
      return json(res, 200, { preferences: prefs });
    }

    if (method === 'POST' && p === '/api/devices') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const body = await readBody(req);
      if (!body.token) return json(res, 400, { error: 'token requis' });
      // Push non configuré — on enregistre le device pour plus tard, sans prétendre envoyer
      DB.devices = DB.devices || [];
      const dev = {
        id: uid(),
        user_id: user.id,
        organization_id: ctx.org.id,
        token: body.token,
        platform: body.platform || 'web',
        active: 1,
        created_at: new Date().toISOString(),
        last_used_at: new Date().toISOString(),
      };
      DB.devices.push(dev);
      saveDb(DB);
      return json(res, 201, {
        device: { id: dev.id, platform: dev.platform, active: 1 },
        push: 'Configuration requise — aucun service push configuré',
      });
    }

    if (method === 'DELETE' && p.startsWith('/api/devices/')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const id = p.split('/').pop();
      DB.devices = (DB.devices || []).filter(d => !(d.id === id && d.user_id === user.id));
      saveDb(DB);
      return json(res, 200, { ok: true });
    }





    if (method === 'GET' && p === '/api/gdpr/export') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = getUserOrg(user.id);
      const orgId = ctx?.org?.id;
      const data = {
        user: { id: user.id, email: user.email, first_name: user.first_name, last_name: user.last_name, created_at: user.created_at },
        organization: ctx?.org ? { id: ctx.org.id, name: ctx.org.name } : null,
        properties: orgId ? DB.properties.filter(x => x.organization_id === orgId).map(x => ({ id: x.id, name: x.name, address: x.address })) : [],
        exported_at: new Date().toISOString(),
      };
      audit(orgId, user.id, 'gdpr.export', 'user', user.id);
      return json(res, 200, data);
    }



    // ── DASHBOARD / STATS / CALENDAR (calculs serveur uniquement) ──
    function parseRange(url) {
      const from = url.searchParams.get('from');
      const to = url.searchParams.get('to');
      const period = url.searchParams.get('period') || 'month';
      const now = new Date();
      let start, end = new Date(now);
      end.setHours(23, 59, 59, 999);
      if (from && to) {
        start = new Date(from);
        end = new Date(to);
        end.setHours(23, 59, 59, 999);
      } else if (period === 'today') {
        start = new Date(now); start.setHours(0, 0, 0, 0);
      } else if (period === 'week') {
        start = new Date(now); start.setDate(now.getDate() - 7); start.setHours(0, 0, 0, 0);
      } else if (period === 'quarter') {
        start = new Date(now); start.setMonth(now.getMonth() - 3); start.setHours(0, 0, 0, 0);
      } else if (period === 'year') {
        start = new Date(now.getFullYear(), 0, 1);
      } else {
        // month default
        start = new Date(now.getFullYear(), now.getMonth(), 1);
      }
      return { start, end, period };
    }

    function nightsBetween(a, b) {
      const d1 = new Date(a), d2 = new Date(b);
      const ms = d2 - d1;
      if (isNaN(ms) || ms <= 0) return 0;
      return Math.round(ms / (24 * 3600 * 1000));
    }

    function dayStr(d) {
      return new Date(d).toISOString().slice(0, 10);
    }

    if (method === 'GET' && (p === '/api/dashboard' || p === '/api/stats/dashboard')) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const orgId = ctx.org.id;
      const { start, end, period } = parseRange(url);
      const propertyId = url.searchParams.get('property_id');
      const platform = url.searchParams.get('platform');
      const statusFilter = url.searchParams.get('status');

      let resas = DB.reservations.filter(r => r.organization_id === orgId);
      if (propertyId) resas = resas.filter(r => r.property_id === propertyId);
      if (platform) resas = resas.filter(r => r.platform === platform);

      const activeResas = resas.filter(r => r.status !== 'cancelled');
      const inPeriod = activeResas.filter(r => {
        const ci = new Date(r.check_in);
        return ci >= start && ci <= end;
      });
      const cancelledInPeriod = resas.filter(r => r.status === 'cancelled' && new Date(r.check_in) >= start && new Date(r.check_in) <= end);

      const revenue = inPeriod.reduce((s, r) => s + (Number(r.total_amount) || 0), 0);
      const revenueAllActive = activeResas.reduce((s, r) => s + (Number(r.total_amount) || 0), 0);

      const props = DB.properties.filter(x => x.organization_id === orgId && x.status !== 'inactive');
      const propCount = propertyId ? 1 : props.length;
      const periodDays = Math.max(1, Math.round((end - start) / (24 * 3600 * 1000)) + 1);
      let occupiedNights = 0;
      for (const r of activeResas) {
        const ci = new Date(r.check_in), co = new Date(r.check_out);
        const from = ci > start ? ci : start;
        const to = co < end ? co : end;
        if (to > from) occupiedNights += nightsBetween(from, to);
      }
      const availableNights = propCount * periodDays;
      const occupancy = availableNights > 0 ? Math.min(100, Math.round((occupiedNights / availableNights) * 1000) / 10) : 0;

      const today = dayStr(new Date());
      const arrivalsToday = activeResas.filter(r => dayStr(r.check_in) === today).length;
      const departuresToday = activeResas.filter(r => dayStr(r.check_out) === today).length;

      const upcomingCheckins = activeResas
        .filter(r => dayStr(r.check_in) >= today)
        .sort((a, b) => (a.check_in > b.check_in ? 1 : -1))
        .slice(0, 5)
        .map(r => ({
          id: r.id,
          check_in: r.check_in,
          property_name: DB.properties.find(p => p.id === r.property_id)?.name,
          guest_name: (() => { const g = DB.guests.find(x => x.id === r.guest_id); return g ? `${g.first_name} ${g.last_name || ''}`.trim() : null; })(),
        }));

      const upcomingCheckouts = activeResas
        .filter(r => dayStr(r.check_out) >= today)
        .sort((a, b) => (a.check_out > b.check_out ? 1 : -1))
        .slice(0, 5)
        .map(r => ({
          id: r.id,
          check_out: r.check_out,
          property_name: DB.properties.find(p => p.id === r.property_id)?.name,
        }));

      const cleaning = DB.cleaning_tasks.filter(t => t.organization_id === orgId);
      const cleaningTodo = cleaning.filter(t => ['pending', 'assigned', 'in_progress'].includes(t.status)).length;
      const cleaningLate = cleaning.filter(t => {
        if (!['pending', 'assigned', 'in_progress'].includes(t.status)) return false;
        if (!t.scheduled_at) return false;
        return new Date(t.scheduled_at) < new Date(Date.now() - 2 * 3600 * 1000);
      }).length;

      const incidentsOpen = DB.incidents.filter(i => i.organization_id === orgId && i.status !== 'resolved').length;
      const incidentsUrgent = DB.incidents.filter(i => i.organization_id === orgId && i.status !== 'resolved' && ['high', 'critical'].includes(i.severity)).length;

      const convNeed = DB.conversations.filter(c => c.organization_id === orgId && (c.status === 'intervention_required' || c.human_controlled)).length;

      const autoFailed = (DB.automation_runs || []).filter(r => r.organization_id === orgId && r.status === 'failed').length;

      const integNeed = (DB.integrations || []).filter(i => i.organization_id === orgId && ['error', 'disconnected', 'configuration_required'].includes(i.status)).length;

      const byProperty = props.map(pr => {
        const prResas = activeResas.filter(r => r.property_id === pr.id);
        const prPeriod = prResas.filter(r => new Date(r.check_in) >= start && new Date(r.check_in) <= end);
        const rev = prPeriod.reduce((s, r) => s + (Number(r.total_amount) || 0), 0);
        const nights = prPeriod.reduce((s, r) => s + nightsBetween(r.check_in, r.check_out), 0);
        const inc = DB.incidents.filter(i => i.property_id === pr.id && i.organization_id === orgId).length;
        const clean = DB.cleaning_tasks.filter(t => t.property_id === pr.id && t.organization_id === orgId).length;
        return {
          id: pr.id,
          name: pr.name,
          revenue: rev,
          bookings: prPeriod.length,
          nights,
          avg_per_booking: prPeriod.length ? Math.round(rev / prPeriod.length) : 0,
          avg_per_night: nights ? Math.round(rev / nights) : 0,
          incidents: inc,
          cleaning_tasks: clean,
        };
      });

      const byPlatform = {};
      for (const r of inPeriod) {
        const pl = r.platform || 'direct';
        if (!byPlatform[pl]) byPlatform[pl] = { platform: pl, count: 0, revenue: 0 };
        byPlatform[pl].count++;
        byPlatform[pl].revenue += Number(r.total_amount) || 0;
      }

      // revenue by day for chart
      const revenueSeries = [];
      const cursor = new Date(start);
      while (cursor <= end && revenueSeries.length < 93) {
        const d = dayStr(cursor);
        const dayRev = inPeriod.filter(r => dayStr(r.check_in) === d).reduce((s, r) => s + (Number(r.total_amount) || 0), 0);
        revenueSeries.push({ date: d, revenue: dayRev });
        cursor.setDate(cursor.getDate() + 1);
      }

      const actions = [];
      if (convNeed) actions.push({ type: 'messages', label: `${convNeed} conversation(s) nécessitent votre attention`, page: 'messages' });
      if (incidentsUrgent) actions.push({ type: 'incident', label: `${incidentsUrgent} incident(s) urgent(s)`, page: 'incidents' });
      else if (incidentsOpen) actions.push({ type: 'incident', label: `${incidentsOpen} incident(s) ouvert(s)`, page: 'incidents' });
      if (cleaningLate) actions.push({ type: 'cleaning', label: `${cleaningLate} ménage(s) en retard`, page: 'cleaning' });
      if (integNeed) actions.push({ type: 'integration', label: `${integNeed} intégration(s) à reconnecter`, page: 'settings' });
      if (autoFailed) actions.push({ type: 'automation', label: `${autoFailed} automatisation(s) en échec`, page: 'automations' });

      // Conflicts: overlapping reservations same property
      const conflicts = [];
      for (const pr of props) {
        const list = activeResas.filter(r => r.property_id === pr.id).sort((a, b) => (a.check_in > b.check_in ? 1 : -1));
        for (let i = 0; i < list.length - 1; i++) {
          if (new Date(list[i].check_out) > new Date(list[i + 1].check_in)) {
            conflicts.push({
              type: 'overlap',
              property_name: pr.name,
              reservation_ids: [list[i].id, list[i + 1].id],
            });
          }
        }
      }

      return json(res, 200, {
        period: { from: start.toISOString(), to: end.toISOString(), label: period },
        empty: inPeriod.length === 0 && activeResas.length === 0,
        kpis: {
          revenue,
          revenue_total_active: revenueAllActive,
          reservations: inPeriod.length,
          reservations_cancelled: cancelledInPeriod.length,
          occupancy_percent: occupancy,
          occupied_nights: occupiedNights,
          available_nights: availableNights,
          arrivals_today: arrivalsToday,
          departures_today: departuresToday,
          cleaning_todo: cleaningTodo,
          cleaning_late: cleaningLate,
          incidents_open: incidentsOpen,
          messages_intervention: convNeed,
          automations_failed: autoFailed,
          integrations_attention: integNeed,
          properties: propCount,
        },
        byProperty,
        byPlatform: Object.values(byPlatform),
        revenueSeries,
        upcomingCheckins,
        upcomingCheckouts,
        actions,
        conflicts,
      });
    }

    if (method === 'GET' && p === '/api/calendar') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const orgId = ctx.org.id;
      const from = url.searchParams.get('from') || dayStr(new Date(new Date().getFullYear(), new Date().getMonth(), 1));
      const to = url.searchParams.get('to') || dayStr(new Date(Date.now() + 120 * 86400000));
      const events = [];
      for (const r of DB.reservations.filter(x => x.organization_id === orgId && x.status !== 'cancelled')) {
        if (r.check_out < from || r.check_in > to) continue;
        const prop = DB.properties.find(p => p.id === r.property_id);
        const guest = DB.guests.find(g => g.id === r.guest_id);
        events.push({
          type: 'reservation',
          id: r.id,
          title: (guest ? `${guest.first_name} ` : '') + (prop?.name || ''),
          start: r.check_in,
          end: r.check_out,
          property_id: r.property_id,
          property_name: prop?.name,
          platform: r.platform,
          status: r.status,
          amount: r.total_amount,
        });
      }
      for (const t of DB.cleaning_tasks.filter(x => x.organization_id === orgId)) {
        const d = (t.scheduled_at || '').slice(0, 10);
        if (!d || d < from || d > to) continue;
        events.push({
          type: 'cleaning',
          id: t.id,
          title: 'Ménage — ' + (DB.properties.find(p => p.id === t.property_id)?.name || ''),
          start: t.scheduled_at,
          end: t.scheduled_at,
          status: t.status,
          property_id: t.property_id,
        });
      }
      for (const i of DB.incidents.filter(x => x.organization_id === orgId && x.status !== 'resolved' && ['high', 'critical'].includes(x.severity))) {
        events.push({
          type: 'incident',
          id: i.id,
          title: i.title,
          start: i.created_at,
          end: i.created_at,
          severity: i.severity,
          property_id: i.property_id,
        });
      }
      return json(res, 200, { from, to, events });
    }

    if (method === 'GET' && p === '/api/system/status') {
      const user = requireAuth(req, res);
      if (!user) return;
      let dbOk = true;
      try { JSON.stringify(DB.users?.length); } catch { dbOk = false; }
      return json(res, 200, {
        database: dbOk ? 'ok' : 'error',
        automations: 'ok',
        messaging_ai: process.env.AI_API_KEY ? 'ok' : 'configuration_required',
        notifications_email: (process.env.EMAIL_PROVIDER && process.env.EMAIL_API_KEY) ? 'ok' : 'configuration_required',
        stripe: stripeConfigured() ? 'ok' : 'configuration_required',
        integrations: 'configuration_required',
      });
    }

    if (method === 'GET' && p === '/api/export/reservations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const rows = DB.reservations.filter(r => r.organization_id === ctx.org.id);
      const header = 'id,property,guest,platform,check_in,check_out,status,amount,currency\n';
      const lines = rows.map(r => {
        const prop = DB.properties.find(p => p.id === r.property_id)?.name || '';
        const g = DB.guests.find(x => x.id === r.guest_id);
        const guest = g ? `${g.first_name} ${g.last_name || ''}`.trim() : '';
        return [r.id, prop, guest, r.platform, r.check_in, r.check_out, r.status, r.total_amount, r.currency || 'EUR']
          .map(c => `"${String(c ?? '').replace(/"/g, '""')}"`).join(',');
      });
      const csv = header + lines.join('\n');
      res.writeHead(200, {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="reservations.csv"',
        'X-Content-Type-Options': 'nosniff',
      });
      return res.end(csv);
    }





    // ── ONBOARDING ──
    if (method === 'GET' && p === '/api/onboarding/status') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = getUserOrg(user.id);
      if (!ctx) {
        return json(res, 200, {
          needs_onboarding: true,
          step: 2,
          completed: false,
          checklist: null,
          percent: 10,
          message: 'Organisation à créer',
        });
      }
      const state = getOnboardingState(user.id, ctx.org.id);
      const checklist = computeOnboardingChecklist(ctx.org.id, user.id);
      const completed = !!state.completed || checklist.percent >= 90;
      if (completed && !state.completed) {
        state.completed = 1;
        state.completed_at = new Date().toISOString();
        saveDb(DB);
      }
      return json(res, 200, {
        needs_onboarding: !completed,
        step: state.step || 1,
        completed,
        percent: checklist.percent,
        checklist: checklist.items,
        knowledge_percent: checklist.knowledgePct,
        property_id: checklist.property_id,
        organization: { id: ctx.org.id, name: ctx.org.name, country: ctx.org.country || null, currency: ctx.org.currency || 'EUR', timezone: ctx.org.timezone || null },
      });
    }

    if (method === 'POST' && p === '/api/onboarding/organization') {
      const user = requireAuth(req, res);
      if (!user) return;
      const body = await readBody(req);
      if (!body.name || !String(body.name).trim()) return json(res, 400, { error: 'Nom requis' });
      let ctx = getUserOrg(user.id);
      if (ctx) {
        ctx.org.name = body.name.trim();
        if (body.country) ctx.org.country = body.country;
        if (body.currency) ctx.org.currency = body.currency;
        if (body.timezone) ctx.org.timezone = body.timezone;
        ctx.org.updated_at = new Date().toISOString();
        const state = getOnboardingState(user.id, ctx.org.id);
        state.step = Math.max(state.step, 3);
        state.updated_at = new Date().toISOString();
        saveDb(DB);
        return json(res, 200, { organization: ctx.org, step: state.step });
      }
      // Should rarely happen — register already creates org; allow create if missing
      const orgId = uid();
      const org = {
        id: orgId,
        name: body.name.trim(),
        owner_id: user.id,
        plan: 'starter',
        subscription_status: 'trialing',
        country: body.country || null,
        currency: body.currency || 'EUR',
        timezone: body.timezone || 'Europe/Paris',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.organizations.push(org);
      DB.organization_members.push({
        id: uid(), organization_id: orgId, user_id: user.id, role: 'owner', created_at: new Date().toISOString(),
      });
      const state = getOnboardingState(user.id, orgId);
      state.step = 3;
      saveDb(DB);
      audit(orgId, user.id, 'onboarding.organization', 'organization', orgId);
      return json(res, 201, { organization: org, step: 3 });
    }

    if (method === 'POST' && p === '/api/onboarding/property') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const lim = assertPlanLimit(ctx.org.id, 'properties');
      if (!lim.ok) return json(res, 403, { error: lim.error });
      const body = await readBody(req);
      if (!body.name || !body.address) return json(res, 400, { error: 'Nom et adresse requis' });
      const prop = {
        id: uid(),
        organization_id: ctx.org.id,
        name: body.name,
        description: body.description || null,
        address: body.address,
        city: body.city || null,
        postal_code: body.postal_code || null,
        country: body.country || 'FR',
        checkin_time: body.checkin_time || '15h00',
        checkout_time: body.checkout_time || '11h00',
        wifi_name: body.wifi_name || null,
        wifi_password: body.wifi_password || null,
        entry_code: body.entry_code || null,
        parking_information: body.parking_information || null,
        house_rules: body.house_rules || null,
        status: 'active',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.properties.push(prop);
      // knowledge seeds from filled fields
      DB.property_knowledge = DB.property_knowledge || [];
      const seeds = [
        body.wifi_name && { category: 'wifi', title: 'Wi-Fi', content: `Réseau: ${body.wifi_name}${body.wifi_password ? ' / ' + body.wifi_password : ''}` },
        body.entry_code && { category: 'acces', title: 'Code d\'accès', content: String(body.entry_code) },
        body.parking_information && { category: 'parking', title: 'Parking', content: body.parking_information },
        body.house_rules && { category: 'regles', title: 'Règles', content: body.house_rules },
        body.checkin_time && { category: 'arrivee', title: 'Check-in', content: 'À partir de ' + body.checkin_time },
        body.checkout_time && { category: 'depart', title: 'Check-out', content: 'Jusqu\'à ' + body.checkout_time },
      ].filter(Boolean);
      for (const s of seeds) {
        DB.property_knowledge.push({
          id: uid(), property_id: prop.id, category: s.category, title: s.title, content: s.content,
          is_active: 1, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        });
      }
      // default pricing rules
      getPricingRules(ctx.org.id, prop.id);
      if (body.base_price) {
        const rules = getPricingRules(ctx.org.id, prop.id);
        rules.base_price = Number(body.base_price) || rules.base_price;
        if (body.min_price) rules.min_price = Number(body.min_price);
        if (body.max_price) rules.max_price = Number(body.max_price);
      }
      const state = getOnboardingState(user.id, ctx.org.id);
      state.step = Math.max(state.step, 4);
      state.updated_at = new Date().toISOString();
      saveDb(DB);
      audit(ctx.org.id, user.id, 'onboarding.property', 'property', prop.id);
      const checklist = computeOnboardingChecklist(ctx.org.id, user.id);
      return json(res, 201, { property: prop, knowledge_percent: checklist.knowledgePct, step: state.step });
    }

    if (method === 'POST' && p === '/api/onboarding/automations') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const body = await readBody(req);
      const selected = body.automations || [];
      const map = {
        reservation_confirm: { name: 'Confirmation de réservation', event_type: 'RESERVATION_CREATED', actions: [{ type: 'notify', title: 'Nouvelle réservation', message: '{{guest_first_name}} — {{property_name}}' }] },
        checkin_link: { name: 'Lien check-in', event_type: 'RESERVATION_CREATED', actions: [{ type: 'generate_checkin_link' }] },
        cleaning_on_checkout: { name: 'Ménage au départ', event_type: 'CHECK_OUT_COMPLETED', actions: [{ type: 'create_cleaning_task' }] },
        incident_notify: { name: 'Notification incident', event_type: 'INCIDENT_CREATED', actions: [{ type: 'notify', title: 'Incident', message: 'Nouvel incident' }] },
      };
      let created = 0;
      for (const key of selected) {
        const def = map[key];
        if (!def) continue;
        const exists = DB.automations.find(a => a.organization_id === ctx.org.id && a.name === def.name);
        if (exists) { exists.enabled = 1; continue; }
        DB.automations.push({
          id: uid(), organization_id: ctx.org.id, name: def.name, description: '',
          enabled: 1, event_type: def.event_type,
          conditions_json: '[]', actions_json: JSON.stringify(def.actions),
          created_by: user.id, created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
        });
        created++;
      }
      const state = getOnboardingState(user.id, ctx.org.id);
      state.step = Math.max(state.step, 7);
      state.flags = { ...state.flags, automations: true };
      saveDb(DB);
      return json(res, 200, { created, step: state.step });
    }

    if (method === 'POST' && p === '/api/onboarding/notifications') {
      const user = requireAuth(req, res);
      if (!user) return;
      const body = await readBody(req);
      DB.notification_preferences = DB.notification_preferences || [];
      let prefs = DB.notification_preferences.find(x => x.user_id === user.id);
      if (!prefs) {
        prefs = { user_id: user.id, categories: {}, email_categories: {}, push_categories: {} };
        DB.notification_preferences.push(prefs);
      }
      prefs.categories = { ...(prefs.categories || {}), ...(body.categories || {}) };
      prefs.updated_at = new Date().toISOString();
      const ctx = getUserOrg(user.id);
      if (ctx) {
        const state = getOnboardingState(user.id, ctx.org.id);
        state.step = Math.max(state.step, 8);
        state.flags = { ...state.flags, notifications: true };
      }
      saveDb(DB);
      return json(res, 200, { preferences: prefs });
    }

    if (method === 'POST' && p === '/api/onboarding/step') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const body = await readBody(req);
      const state = getOnboardingState(user.id, ctx.org.id);
      if (body.step) state.step = Number(body.step);
      state.updated_at = new Date().toISOString();
      saveDb(DB);
      return json(res, 200, { step: state.step });
    }

    if (method === 'POST' && p === '/api/onboarding/complete') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const state = getOnboardingState(user.id, ctx.org.id);
      state.completed = 1;
      state.completed_at = new Date().toISOString();
      state.step = 99;
      saveDb(DB);
      audit(ctx.org.id, user.id, 'onboarding.completed', 'user', user.id);
      return json(res, 200, { completed: true });
    }


    // ── REVIEWS ──
    if (method === 'GET' && p === '/api/reviews/stats') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const list = (DB.reviews || []).filter(r => r.organization_id === ctx.org.id);
      const withRating = list.filter(r => r.rating != null);
      const avg = withRating.length
        ? Math.round((withRating.reduce((s, r) => s + Number(r.rating), 0) / withRating.length) * 10) / 10
        : null;
      const needReply = list.filter(r => r.status === 'pending_response' || (r.rating != null && r.rating <= 3 && !r.response_sent)).length;
      const responded = list.filter(r => r.response_sent).length;
      const distribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
      for (const r of withRating) {
        const k = Math.min(5, Math.max(1, Math.round(Number(r.rating))));
        distribution[k]++;
      }
      const topicCount = {};
      for (const r of list) {
        const topics = (r.analysis && r.analysis.topics) || [];
        for (const t of topics) topicCount[t] = (topicCount[t] || 0) + 1;
      }
      const topTopics = Object.entries(topicCount).sort((a, b) => b[1] - a[1]).slice(0, 8)
        .map(([topic, count]) => ({ topic, count }));
      // recurrent: same topic >= 2
      const recurrent = topTopics.filter(t => t.count >= 2);
      return json(res, 200, {
        total: list.length,
        average_rating: avg,
        need_response: needReply,
        response_rate: list.length ? Math.round((responded / list.length) * 100) : 0,
        distribution,
        top_topics: topTopics,
        recurrent_issues: recurrent,
        platform_sync: 'Configuration requise — récupération automatique des avis via APIs officielles non configurée',
        empty: list.length === 0,
      });
    }

    if (method === 'GET' && p === '/api/reviews') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      let list = (DB.reviews || []).filter(r => r.organization_id === ctx.org.id);
      const propertyId = url.searchParams.get('property_id');
      const platform = url.searchParams.get('platform');
      const status = url.searchParams.get('status');
      if (propertyId) list = list.filter(r => r.property_id === propertyId);
      if (platform) list = list.filter(r => r.platform === platform);
      if (status) list = list.filter(r => r.status === status);
      list = list.sort((a, b) => (a.created_at < b.created_at ? 1 : -1)).map(r => ({
        ...r,
        property_name: DB.properties.find(p => p.id === r.property_id)?.name,
      }));
      return json(res, 200, {
        reviews: list,
        platform_sync: 'Configuration requise',
      });
    }

    if (method === 'POST' && p === '/api/reviews') {
      // Manual / internal import only — not fake platform scrape
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const body = await readBody(req);
      if (!body.property_id || body.rating == null) return json(res, 400, { error: 'property_id et rating requis' });
      const prop = DB.properties.find(x => x.id === body.property_id && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      if (body.external_id) {
        const dup = (DB.reviews || []).find(r => r.organization_id === ctx.org.id && r.platform === (body.platform || 'direct') && r.external_id === body.external_id);
        if (dup) return json(res, 200, { review: dup, duplicate: true });
      }
      const analysis = analyzeReviewText(body.comment || '', Number(body.rating));
      const review = {
        id: uid(),
        organization_id: ctx.org.id,
        property_id: prop.id,
        reservation_id: body.reservation_id || null,
        platform: body.platform || 'direct',
        external_id: body.external_id || null,
        guest_name: body.guest_name || null,
        rating: Number(body.rating),
        comment: body.comment || '',
        analysis,
        status: analysis.sensitive ? 'human_required' : 'pending_response',
        response_sent: false,
        proposed_response: null,
        created_at: new Date().toISOString(),
        source: 'manual_or_api',
      };
      DB.reviews = DB.reviews || [];
      DB.reviews.push(review);
      const prio = analysis.sentiment === 'negatif' || analysis.sensitive ? 'high' : 'normal';
      try {
        notifyOrgRoles(ctx.org.id, ['owner', 'admin', 'manager'], {
          type: 'message',
          title: analysis.sensitive ? 'Avis sensible — intervention' : 'Nouvel avis',
          message: (prop.name || '') + ' · note ' + review.rating + '/5',
          priority: prio,
          related: { property_id: prop.id },
          idempotency_key: 'review:' + review.id,
        });
      } catch (ne) { console.error('[review-notify]', ne.message); }
      try { saveDb(DB); } catch (se) { console.error('[review-save]', se.message); }
      audit(ctx.org.id, user.id, 'review.created', 'review', review.id);
      return json(res, 201, { review });
    }

    if (method === 'POST' && p.match(/^\/api\/reviews\/[^/]+\/analyze$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const review = (DB.reviews || []).find(r => r.id === id && r.organization_id === ctx.org.id);
      if (!review) return json(res, 404, { error: 'Avis introuvable' });
      review.analysis = analyzeReviewText(review.comment, review.rating);
      if (review.analysis.sensitive) review.status = 'human_required';
      saveDb(DB);
      return json(res, 200, { review });
    }

    if (method === 'POST' && p.match(/^\/api\/reviews\/[^/]+\/generate-response$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const review = (DB.reviews || []).find(r => r.id === id && r.organization_id === ctx.org.id);
      if (!review) return json(res, 404, { error: 'Avis introuvable' });
      const prop = DB.properties.find(x => x.id === review.property_id);
      const gen = generateReviewReply(review, prop);
      if (gen.blocked) {
        review.status = 'human_required';
        saveDb(DB);
        return json(res, 200, { blocked: true, reason: gen.reason, review });
      }
      review.proposed_response = gen.draft;
      review.status = 'response_proposed';
      saveDb(DB);
      audit(ctx.org.id, user.id, 'review.response_generated', 'review', id);
      return json(res, 200, { proposed_response: gen.draft, review });
    }

    if (method === 'POST' && p.match(/^\/api\/reviews\/[^/]+\/approve-response$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const id = p.split('/')[3];
      const review = (DB.reviews || []).find(r => r.id === id && r.organization_id === ctx.org.id);
      if (!review) return json(res, 404, { error: 'Avis introuvable' });
      const body = await readBody(req);
      const text = body.response || review.proposed_response;
      if (!text) return json(res, 400, { error: 'Aucune réponse à envoyer' });
      // Platform send = configuration required — store as approved locally only
      review.approved_response = text;
      review.response_sent = false;
      review.status = 'approved_pending_send';
      review.resolved_at = new Date().toISOString();
      DB.review_responses = DB.review_responses || [];
      DB.review_responses.push({
        id: uid(),
        review_id: id,
        organization_id: ctx.org.id,
        content: text,
        delivery_status: 'configuration_required',
        delivery_note: 'Envoi public via Airbnb/Booking/Vrbo : Configuration requise (API officielle)',
        created_by: user.id,
        created_at: new Date().toISOString(),
      });
      saveDb(DB);
      audit(ctx.org.id, user.id, 'review.response_approved', 'review', id);
      return json(res, 200, {
        review,
        delivery: 'Configuration requise',
        message: 'Réponse approuvée et enregistrée. Publication sur la plateforme : Configuration requise.',
      });
    }

    if (method === 'POST' && p.match(/^\/api\/reviews\/[^/]+\/reject-response$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const review = (DB.reviews || []).find(r => r.id === id && r.organization_id === ctx.org.id);
      if (!review) return json(res, 404, { error: 'Avis introuvable' });
      review.proposed_response = null;
      review.status = 'pending_response';
      saveDb(DB);
      return json(res, 200, { review });
    }

    if (method === 'POST' && p.match(/^\/api\/reviews\/[^/]+\/create-incident$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const id = p.split('/')[3];
      const review = (DB.reviews || []).find(r => r.id === id && r.organization_id === ctx.org.id);
      if (!review) return json(res, 404, { error: 'Avis introuvable' });
      const inc = {
        id: uid(),
        organization_id: ctx.org.id,
        property_id: review.property_id,
        reservation_id: review.reservation_id,
        reported_by: user.id,
        title: 'Problème signalé via avis',
        description: review.comment || '',
        category: 'review',
        severity: review.rating <= 2 ? 'high' : 'medium',
        status: 'open',
        review_id: id,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
      };
      DB.incidents.push(inc);
      saveDb(DB);
      return json(res, 201, { incident: inc });
    }

    // Sync endpoint — honest
    if (method === 'POST' && p === '/api/reviews/sync') {
      const user = requireAuth(req, res);
      if (!user) return;
      return json(res, 503, {
        error: 'Configuration requise',
        message: 'La synchronisation automatique des avis nécessite les APIs officielles des plateformes (partenariat / OAuth). Aucun avis inventé.',
      });
    }


    // ── PRICING ──
    if (method === 'GET' && p === '/api/pricing/overview') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const props = DB.properties.filter(x => x.organization_id === ctx.org.id);
      const items = props.map(pr => {
        const rec = generateRecommendation(ctx.org.id, pr.id);
        const pending = (DB.pricing_recommendations || []).filter(
          r => r.property_id === pr.id && r.status === 'pending'
        ).length;
        return {
          property_id: pr.id,
          property_name: pr.name,
          ...rec,
          pending_recommendations: pending,
        };
      });
      const pendingTotal = items.reduce((s, i) => s + i.pending_recommendations, 0);
      const avgDelta = items.length
        ? Math.round(items.reduce((s, i) => s + (i.recommended_price - i.current_price), 0) / items.length)
        : 0;
      return json(res, 200, {
        properties: items,
        summary: {
          pending_recommendations: pendingTotal,
          avg_recommended_delta: avgDelta,
          properties_count: props.length,
        },
        platform_sync: 'Configuration requise — APIs officielles Airbnb/Booking/Vrbo non connectées',
      });
    }

    if (method === 'GET' && p.match(/^\/api\/properties\/[^/]+\/pricing$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const rules = getPricingRules(ctx.org.id, propId);
      const rec = generateRecommendation(ctx.org.id, propId);
      return json(res, 200, {
        property: { id: prop.id, name: prop.name },
        rules: {
          base_price: rules.base_price,
          min_price: rules.min_price,
          max_price: rules.max_price,
          max_increase_pct: rules.max_increase_pct,
          max_decrease_pct: rules.max_decrease_pct,
          weekend_pct: rules.weekend_pct,
          auto_apply: !!rules.auto_apply,
          long_stay_nights: rules.long_stay_nights,
          long_stay_discount_pct: rules.long_stay_discount_pct,
        },
        metrics: rec,
        explanation: explainRecommendation(rec),
        platform_push: 'Configuration requise',
      });
    }

    if (method === 'PUT' && p.match(/^\/api\/properties\/[^/]+\/pricing\/rules$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const body = await readBody(req);
      const rules = getPricingRules(ctx.org.id, propId);
      for (const key of ['base_price', 'min_price', 'max_price', 'max_increase_pct', 'max_decrease_pct', 'weekend_pct', 'long_stay_nights', 'long_stay_discount_pct']) {
        if (body[key] !== undefined) {
          const n = Number(body[key]);
          if (isNaN(n) || n < 0) return json(res, 400, { error: `Valeur invalide: ${key}` });
          rules[key] = n;
        }
      }
      if (body.auto_apply !== undefined) rules.auto_apply = body.auto_apply ? 1 : 0;
      if (rules.min_price > rules.max_price) return json(res, 400, { error: 'min_price > max_price' });
      if (rules.base_price < rules.min_price || rules.base_price > rules.max_price) {
        return json(res, 400, { error: 'base_price hors limites min/max' });
      }
      rules.updated_at = new Date().toISOString();
      saveDb(DB);
      audit(ctx.org.id, user.id, 'pricing.rules_updated', 'property', propId);
      return json(res, 200, { rules });
    }

    if (method === 'POST' && p.match(/^\/api\/properties\/[^/]+\/pricing\/recommendations$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const rec = generateRecommendation(ctx.org.id, propId);
      const row = {
        id: uid(),
        organization_id: ctx.org.id,
        property_id: propId,
        current_price: rec.current_price,
        recommended_price: rec.recommended_price,
        reason: rec.reason,
        explanation: explainRecommendation(rec),
        occupancy_14d: rec.occupancy_14d,
        status: 'pending',
        created_at: new Date().toISOString(),
        resolved_at: null,
        resolved_by: null,
      };
      DB.pricing_recommendations = DB.pricing_recommendations || [];
      DB.pricing_recommendations.push(row);
      saveDb(DB);
      // auto_apply only if explicitly enabled
      const rules = getPricingRules(ctx.org.id, propId);
      if (rules.auto_apply) {
        // apply without platform push
        const old = rules.base_price;
        rules.base_price = row.recommended_price;
        rules.updated_at = new Date().toISOString();
        row.status = 'applied';
        row.resolved_at = new Date().toISOString();
        row.resolved_by = 'automation';
        DB.pricing_history = DB.pricing_history || [];
        DB.pricing_history.push({
          id: uid(),
          organization_id: ctx.org.id,
          property_id: propId,
          old_price: old,
          new_price: row.recommended_price,
          reason: row.reason,
          source: 'automation',
          user_id: user.id,
          platform_sync: 'skipped_configuration_required',
          created_at: new Date().toISOString(),
        });
        saveDb(DB);
      }
      return json(res, 201, { recommendation: row });
    }

    if (method === 'GET' && p.match(/^\/api\/properties\/[^/]+\/pricing\/recommendations$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const list = (DB.pricing_recommendations || [])
        .filter(r => r.property_id === propId && r.organization_id === ctx.org.id)
        .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
      return json(res, 200, { recommendations: list });
    }

    if (method === 'POST' && p.match(/^\/api\/properties\/[^/]+\/pricing\/recommendations\/[^/]+\/(approve|apply|reject)$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      const parts = p.split('/');
      const propId = parts[3];
      const recId = parts[6];
      const action = parts[7];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const row = (DB.pricing_recommendations || []).find(r => r.id === recId && r.organization_id === ctx.org.id && r.property_id === propId);
      if (!row) return json(res, 404, { error: 'Recommandation introuvable' });
      if (row.status !== 'pending') return json(res, 409, { error: 'Déjà traitée' });

      if (action === 'reject') {
        row.status = 'rejected';
        row.resolved_at = new Date().toISOString();
        row.resolved_by = user.id;
        saveDb(DB);
        audit(ctx.org.id, user.id, 'pricing.recommendation_rejected', 'pricing_recommendation', recId);
        return json(res, 200, { recommendation: row });
      }

      // approve or apply → update base price locally; platform sync = config required
      const rules = getPricingRules(ctx.org.id, propId);
      const old = rules.base_price;
      let newPrice = row.recommended_price;
      const body = await readBody(req).catch(() => ({}));
      if (body.price !== undefined) {
        newPrice = clampPrice(Number(body.price), rules);
      }
      rules.base_price = newPrice;
      rules.updated_at = new Date().toISOString();
      row.status = 'applied';
      row.resolved_at = new Date().toISOString();
      row.resolved_by = user.id;
      row.applied_price = newPrice;
      DB.pricing_history = DB.pricing_history || [];
      DB.pricing_history.push({
        id: uid(),
        organization_id: ctx.org.id,
        property_id: propId,
        old_price: old,
        new_price: newPrice,
        reason: row.reason,
        source: 'human',
        user_id: user.id,
        platform_sync: 'configuration_required',
        platform_sync_note: 'Modification enregistrée dans HostPilot. Push Airbnb/Booking/Vrbo : Configuration requise.',
        created_at: new Date().toISOString(),
      });
      saveDb(DB);
      audit(ctx.org.id, user.id, 'pricing.price_applied', 'property', propId);
      return json(res, 200, {
        recommendation: row,
        rules,
        platform_sync: 'Configuration requise',
        message: 'Prix mis à jour dans HostPilot. Synchronisation plateformes : Configuration requise.',
      });
    }

    if (method === 'GET' && p.match(/^\/api\/properties\/[^/]+\/pricing\/history$/)) {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const propId = p.split('/')[3];
      const prop = DB.properties.find(x => x.id === propId && x.organization_id === ctx.org.id);
      if (!prop) return json(res, 404, { error: 'Logement introuvable' });
      const hist = (DB.pricing_history || [])
        .filter(h => h.property_id === propId && h.organization_id === ctx.org.id)
        .sort((a, b) => (a.created_at < b.created_at ? 1 : -1));
      return json(res, 200, { history: hist });
    }



    // Test email (owner/admin) — n'affiche jamais "envoyé" sans confirmation provider
    if (method === 'POST' && p === '/api/email/test') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (!['owner', 'admin'].includes(ctx.role)) return json(res, 403, { error: 'Permission refusée' });
      if (!emailConfigured()) {
        return json(res, 503, {
          error: 'EMAIL_NOT_CONFIGURED',
          message: 'Définissez EMAIL_PROVIDER (resend|sendgrid), EMAIL_API_KEY et EMAIL_FROM',
        });
      }
      const body = await readBody(req);
      const to = (body.to || user.email || '').trim();
      if (!to) return json(res, 400, { error: 'Destinataire requis' });
      const result = await sendEmailViaProvider({
        to,
        subject: body.subject || 'HostPilot — test email',
        text: body.text || 'Ceci est un email de test HostPilot.',
      });
      if (!result.ok) {
        return json(res, 502, {
          error: result.code || 'EMAIL_ERROR',
          message: result.error,
        });
      }
      return json(res, 200, { ok: true, provider: result.provider, id: result.id });
    }

    // ── BILLING / STRIPE ──
    if (method === 'GET' && p === '/api/billing/plans') {
      const prices = {
        free: null,
        pro: process.env.STRIPE_PRICE_PRO || null,
        business: process.env.STRIPE_PRICE_BUSINESS || null,
      };
      return json(res, 200, {
        configured: stripeConfigured(),
        publishable_key: process.env.STRIPE_PUBLISHABLE_KEY || null,
        plans: Object.entries(PLAN_LIMITS).filter(([k]) => k !== 'starter').map(([id, lim]) => ({
          id,
          ...lim,
          stripe_price_id: prices[id] || null,
          checkout_available: stripeConfigured() && !!prices[id],
        })),
        message: stripeConfigured() ? null : 'Configuration requise — définissez STRIPE_SECRET_KEY et les Price IDs (mode TEST)',
      });
    }

    if (method === 'GET' && p === '/api/billing/subscription') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      const info = getOrgPlan(ctx.org.id);
      const propsUsed = DB.properties.filter(x => x.organization_id === ctx.org.id).length;
      const autosUsed = DB.automations.filter(x => x.organization_id === ctx.org.id).length;
      // Never trust frontend — return server truth only
      const safeSub = info.sub ? {
        plan: info.sub.plan,
        status: info.sub.status,
        current_period_start: info.sub.current_period_start || null,
        current_period_end: info.sub.current_period_end || null,
        cancel_at_period_end: info.sub.cancel_at_period_end || false,
        stripe_subscription_id: info.sub.stripe_subscription_id ? 'set' : null,
        // no secret ids exposed beyond existence
      } : { plan: 'starter', status: 'trialing' };
      return json(res, 200, {
        subscription: safeSub,
        limits: info.limits,
        usage: { properties: propsUsed, automations: autosUsed },
        stripe_configured: stripeConfigured(),
      });
    }

    if (method === 'POST' && p === '/api/billing/create-checkout-session') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (ctx.role === 'cleaner') return json(res, 403, { error: 'Permission refusée' });
      if (!stripeConfigured()) {
        return json(res, 503, {
          error: 'Configuration requise',
          message: 'Ajoutez STRIPE_SECRET_KEY (sk_test_…) et STRIPE_PRICE_PRO / STRIPE_PRICE_BUSINESS dans le .env serveur',
        });
      }
      const body = await readBody(req);
      const plan = (body.plan || 'pro').toLowerCase();
      const priceMap = {
        pro: process.env.STRIPE_PRICE_PRO,
        business: process.env.STRIPE_PRICE_BUSINESS,
      };
      const priceId = priceMap[plan];
      if (!priceId) {
        return json(res, 400, {
          error: 'Price ID manquant',
          message: `Définissez STRIPE_PRICE_${plan.toUpperCase()} avec un Price ID Stripe (mode TEST)`,
        });
      }
      try {
        let sub = (DB.subscriptions || []).find(s => s.organization_id === ctx.org.id);
        if (!sub) {
          sub = {
            id: uid(), organization_id: ctx.org.id, plan: 'starter', status: 'trialing',
            created_at: new Date().toISOString(), updated_at: new Date().toISOString(),
          };
          DB.subscriptions.push(sub);
        }
        let customerId = sub.stripe_customer_id;
        if (!customerId) {
          const customer = await stripeRequest('/customers', 'POST', {
            email: user.email,
            name: ctx.org.name,
            'metadata[organization_id]': ctx.org.id,
          });
          customerId = customer.id;
          sub.stripe_customer_id = customerId;
          saveDb(DB);
        }
        const appUrl = (process.env.APP_URL || (IS_PROD ? '' : `http://localhost:${PORT}`));
        const session = await stripeRequest('/checkout/sessions', 'POST', {
          mode: 'subscription',
          customer: customerId,
          client_reference_id: ctx.org.id,
          'line_items[0][price]': priceId,
          'line_items[0][quantity]': '1',
          success_url: appUrl + '/?billing=success',
          cancel_url: appUrl + '/?billing=cancel',
          'metadata[organization_id]': ctx.org.id,
          'metadata[plan]': plan,
        });
        audit(ctx.org.id, user.id, 'billing.checkout_created', 'subscription', sub.id);
        return json(res, 200, { url: session.url, session_id: session.id });
      } catch (e) {
        return json(res, 502, { error: 'Erreur Stripe', message: e.message });
      }
    }

    if (method === 'POST' && p === '/api/billing/create-portal-session') {
      const user = requireAuth(req, res);
      if (!user) return;
      const ctx = requireOrg(user, res);
      if (!ctx) return;
      if (!stripeConfigured()) {
        return json(res, 503, { error: 'Configuration requise', message: 'STRIPE_SECRET_KEY requis' });
      }
      const sub = (DB.subscriptions || []).find(s => s.organization_id === ctx.org.id);
      if (!sub?.stripe_customer_id) {
        return json(res, 400, { error: 'Aucun client Stripe — souscrivez d\'abord via Checkout' });
      }
      try {
        const appUrl = (process.env.APP_URL || (IS_PROD ? '' : `http://localhost:${PORT}`));
        const portal = await stripeRequest('/billing_portal/sessions', 'POST', {
          customer: sub.stripe_customer_id,
          return_url: appUrl + '/?page=settings',
        });
        audit(ctx.org.id, user.id, 'billing.portal_opened', 'subscription', sub.id);
        return json(res, 200, { url: portal.url });
      } catch (e) {
        return json(res, 502, { error: 'Erreur Stripe', message: e.message });
      }
    }

    // Stripe webhook — signature HMAC obligatoire si STRIPE_WEBHOOK_SECRET défini
    if (method === 'POST' && p === '/api/webhooks/stripe') {
      const secret = process.env.STRIPE_WEBHOOK_SECRET;
      let raw;
      try {
        raw = await readRawBody(req);
      } catch {
        return json(res, 400, { error: 'Payload invalide' });
      }
      if (secret) {
        const sig = req.headers['stripe-signature'];
        if (!sig) return json(res, 400, { error: 'Signature manquante' });
        if (!verifyStripeSignature(raw, sig, secret)) {
          return json(res, 400, { error: 'Signature Stripe invalide' });
        }
      } else if (process.env.NODE_ENV === 'production') {
        return json(res, 503, {
          error: 'Configuration requise',
          message: 'STRIPE_WEBHOOK_SECRET obligatoire en production',
        });
      } else if (!stripeConfigured()) {
        return json(res, 503, { error: 'Configuration requise' });
      }
      // Dev sans secret : parse uniquement (ne jamais déployer ainsi)
      let event;
      try {
        event = raw.length ? JSON.parse(raw.toString('utf8')) : {};
      } catch {
        return json(res, 400, { error: 'JSON invalide' });
      }
      if (!event || !event.type) return json(res, 400, { error: 'Événement invalide' });

      // Idempotency
      DB.stripe_events = DB.stripe_events || [];
      if (event.id && DB.stripe_events.find(e => e.id === event.id)) {
        return json(res, 200, { received: true, duplicate: true });
      }
      if (event.id) {
        DB.stripe_events.push({ id: event.id, type: event.type, at: new Date().toISOString() });
      }

      const obj = event.data?.object || {};
      const orgId = obj.metadata?.organization_id || obj.client_reference_id;

      if (event.type === 'checkout.session.completed' && orgId) {
        let sub = (DB.subscriptions || []).find(s => s.organization_id === orgId);
        if (!sub) {
          sub = { id: uid(), organization_id: orgId, created_at: new Date().toISOString() };
          DB.subscriptions.push(sub);
        }
        sub.stripe_customer_id = obj.customer || sub.stripe_customer_id;
        sub.stripe_subscription_id = obj.subscription || sub.stripe_subscription_id;
        sub.plan = obj.metadata?.plan || sub.plan || 'pro';
        sub.status = 'active';
        sub.updated_at = new Date().toISOString();
        audit(orgId, null, 'billing.checkout_completed', 'subscription', sub.id);
      }

      if (['customer.subscription.updated', 'customer.subscription.created'].includes(event.type)) {
        const sub = (DB.subscriptions || []).find(s => s.stripe_subscription_id === obj.id || s.stripe_customer_id === obj.customer);
        if (sub) {
          sub.status = obj.status || sub.status;
          sub.cancel_at_period_end = !!obj.cancel_at_period_end;
          if (obj.current_period_start) sub.current_period_start = new Date(obj.current_period_start * 1000).toISOString();
          if (obj.current_period_end) sub.current_period_end = new Date(obj.current_period_end * 1000).toISOString();
          sub.updated_at = new Date().toISOString();
          if (obj.status === 'past_due' || obj.status === 'unpaid') {
            notifyOrgRoles(sub.organization_id, ['owner', 'admin'], {
              type: 'system', title: 'Paiement en échec', message: 'Mettez à jour votre moyen de paiement via le portail Stripe.',
              priority: 'high', idempotency_key: 'payfail:' + (event.id || obj.id),
            });
          }
        }
      }

      if (event.type === 'customer.subscription.deleted') {
        const sub = (DB.subscriptions || []).find(s => s.stripe_subscription_id === obj.id);
        if (sub) {
          sub.status = 'canceled';
          sub.canceled_at = new Date().toISOString();
          sub.plan = 'free';
          sub.updated_at = new Date().toISOString();
          audit(sub.organization_id, null, 'billing.subscription_canceled', 'subscription', sub.id);
        }
      }

      if (event.type === 'invoice.payment_failed') {
        const sub = (DB.subscriptions || []).find(s => s.stripe_customer_id === obj.customer);
        if (sub) {
          sub.status = 'past_due';
          notifyOrgRoles(sub.organization_id, ['owner', 'admin'], {
            type: 'system', title: 'Échec de paiement', message: 'Votre paiement Stripe a échoué.',
            priority: 'urgent', idempotency_key: 'invfail:' + (event.id || obj.id),
          });
        }
      }

      saveDb(DB);
      return json(res, 200, { received: true });
    }


    // ── WEBHOOKS (préparation, pas de fausse sync) ──
    if (method === 'POST' && (p === '/api/webhooks/airbnb' || p === '/api/webhooks/booking' || p === '/api/webhooks/vrbo')) {
      // Prêt à recevoir de vrais événements — pour l'instant log + 501 si non configuré
      return json(res, 501, {
        error: 'Connexion requise',
        message: 'Endpoint webhook préparé. Configurez la vérification de signature et les credentials OAuth officiels.',
      });
    }

    // Static frontend
    if (method === 'GET') {
      let filePath = p === '/' ? '/index.html' : p;
      const full = path.join(PUBLIC_DIR, path.normalize(filePath).replace(/^(\.\.[/\\])+/, ''));
      if (full.startsWith(PUBLIC_DIR) && fs.existsSync(full) && fs.statSync(full).isFile()) {
        const ext = path.extname(full);
        const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json' };
        res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
        return fs.createReadStream(full).pipe(res);
      }
      // SPA fallback
      const index = path.join(PUBLIC_DIR, 'index.html');
      if (fs.existsSync(index)) {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        return fs.createReadStream(index).pipe(res);
      }
    }

    return json(res, 404, { error: 'Route introuvable' });
  } catch (e) {
    console.error('[error]', e.message);
    return json(res, 500, { error: 'Erreur serveur' });
  }
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    console.error(e);
    json(res, 500, { error: 'Erreur serveur' });
  });
});

server.listen(PORT, () => {
  console.log(`\n🚀 HostPilot API → http://localhost:${PORT}`);
  console.log(`   Health: http://localhost:${PORT}/api/health`);
  console.log(`   DB: ${DATA_FILE}`);
  if (!IS_PROD && (WEAK_JWT.has(JWT_SECRET) || JWT_SECRET.length < 32)) {
    console.warn('   ⚠️  JWT_SECRET faible — dev only');
  }
  if (IS_PROD) {
    if (!process.env.CORS_ORIGIN || process.env.CORS_ORIGIN === '*') {
      console.warn('   ⚠️  CORS_ORIGIN non restreint en production');
    }
    if (!process.env.APP_URL || process.env.APP_URL.includes('localhost')) {
      console.warn('   ⚠️  APP_URL doit être HTTPS public en production');
    }
  }
  if (!stripeConfigured()) console.log('   Stripe: Configuration requise');
  else console.log('   Stripe: clés présentes');
  console.log('');
  try { rotateBackup(); } catch (_) {}
  setInterval(() => { try { rotateBackup(); } catch (_) {} }, 30 * 60 * 1000);
});
