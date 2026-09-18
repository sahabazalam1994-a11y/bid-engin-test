'use strict';

/**
 * bid-engine.js — Bikas Bidding v4.0 "Rank-1 Hardening"
 *
 * The whole game at window-open:  fetch captcha → 0ms local hash lookup → submit
 * on a hot connection with a fresh CSRF, fired on SAP's clock.
 *
 * Removed vs v3.35: captcha pre-fetch poller, EARLY_DROP, bidding.js HTTP solver,
 * TrueCaptcha, tesseract, parallel captcha probes, global submit mutex.
 * Kept: rule/blacklist/priority CSVs, batching, ghost/tie/silent-201 detection,
 * WAF back-off, L1-undercut, cookie-dead detection, bid CSV log.
 *
 * Files next to this script:
 *   ./data.json (or CAPTCHA_MAP_FILE)  [{hash: sha256(base64), result}] — 162 known captchas
 *   ./cookie.txt, cookie2.txt …        one SAP session cookie per file
 *   ./files/input2.csv, delete.csv, priority.csv
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const csv    = require('csv-parser');
const { Pool, buildConnector } = require('undici');
const { build } = require('./logger');

const log = build('engine');
const ROOT = __dirname;

// ---- Config ----------------------------------------------------------------

const envInt  = (k, d) => parseInt(process.env[k] ?? d, 10);
const envBool = (k, d) => String(process.env[k] ?? d).toLowerCase() === 'true';

const SAP_BASE_URL = process.env.SAP_BASE_URL || 'https://rise.eye2serve.com:8443/sap/opu/odata/sap/ZVC_TRANSPORTER_SRV';
const SAP_ORIGIN   = new URL(SAP_BASE_URL).origin;
const SAP_PFX      = new URL(SAP_BASE_URL).pathname.replace(/\/$/, '');
const VENDOR_ID    = process.env.VENDOR_ID || '2210181';
const PLANT_CODE   = process.env.PLANT_CODE || '6924';
const BATCH_SIZE   = envInt('BATCH_SIZE', 3);
const POLL_MS      = envInt('POLL_MS', 200);

const FETCH_ORDERS_TIMEOUT_MS  = envInt('FETCH_ORDERS_TIMEOUT_MS', 10000);
const FETCH_CAPTCHA_TIMEOUT_MS = envInt('FETCH_CAPTCHA_TIMEOUT_MS', 4000);
const SUBMIT_TIMEOUT_MS        = envInt('SUBMIT_TIMEOUT_MS', 5000);
const TIME_ENDED_COOLDOWN_MS   = envInt('TIME_ENDED_COOLDOWN_MS', 30000);

// Window schedule (IST). Default :15 and :45 of every hour.
const WINDOW_MINUTES = (process.env.WINDOW_MINUTES || '15,45').split(',').map((s) => parseInt(s, 10)).filter((n) => n >= 0 && n < 60).sort((a, b) => a - b);
const HOT_PRE_MS  = envInt('HOT_PRE_MS', 60000);     // pre-warm phase before boundary
const HOT_POST_MS = envInt('HOT_POST_MS', 300000);   // active window after boundary

// Fire loop
const FIRE_LEAD_MS            = envInt('FIRE_LEAD_MS', -1);        // -1 = auto (one-way latency)
const FIRE_MAX_WAIT_MS        = envInt('FIRE_MAX_WAIT_MS', 90000);  // give up waiting for captcha unlock
const FIRE_MAX_ATTEMPTS       = envInt('FIRE_MAX_ATTEMPTS', 12);    // submits per item per window
const CAPTCHA_EMPTY_RETRY_MS  = envInt('CAPTCHA_EMPTY_RETRY_MS', 25);
const CAPTCHA_EMPTY_SLOW_MS   = envInt('CAPTCHA_EMPTY_SLOW_MS', 100); // after 3s of empties
const SESSION_STAGGER_MS      = envInt('SESSION_STAGGER_MS', 0);           // extra race stagger (probe phasing already spreads sessions)
const FIRE_RACE_FIRST         = envBool('FIRE_RACE_FIRST', 'true'); // all sessions race the first item
const MAX_INFLIGHT_SUBMITS    = envInt('MAX_INFLIGHT_SUBMITS', 3);
const SUBMIT_MIN_GAP_MS       = envInt('SUBMIT_MIN_GAP_MS', 0);           // global spacing between submit sends (WAF dial)
const CSRF_REMINT_LEAD_MS     = envInt('CSRF_REMINT_LEAD_MS', 300);
const ORDERS_POLL_HOT_MS      = envInt('ORDERS_POLL_HOT_MS', 100);
const ORDERS_POLL_LEAD_MS     = envInt('ORDERS_POLL_LEAD_MS', 5000);
const ORDERS_TIGHT_MS         = envInt('ORDERS_TIGHT_MS', 10);          // back-to-back order fetch gap at boundary
const ARM_CAPTCHA_AT_BOUNDARY = envBool('ARM_CAPTCHA_AT_BOUNDARY', 'true'); // fetch ONE captcha in parallel with orders
const ARMED_CAPTCHA_MAX_AGE_MS = envInt('ARMED_CAPTCHA_MAX_AGE_MS', 5000);

// Clock sync
const CLOCK_SOURCE            = (process.env.CLOCK_SOURCE || 'backend').toLowerCase(); // backend | date
const CLOCK_BACKEND_PROBES    = envInt('CLOCK_BACKEND_PROBES', 9);
const CLOCK_SYNC_LEAD_MS      = envInt('CLOCK_SYNC_LEAD_MS', 20000);
const CLOCK_SYNC_DURATION_MS  = envInt('CLOCK_SYNC_DURATION_MS', 6000);
const CLOCK_SYNC_INTERVAL_MS  = envInt('CLOCK_SYNC_INTERVAL_MS', 100);
const SAP_CLOCK_OFFSET_MS     = process.env.SAP_CLOCK_OFFSET_MS !== undefined ? parseInt(process.env.SAP_CLOCK_OFFSET_MS, 10) : null;
const UNLOCK_LAG_MS           = envInt('UNLOCK_LAG_MS', -1);            // -1 = learn from live windows
const UNLOCK_MARGIN_MS        = envInt('UNLOCK_MARGIN_MS', 15);          // aim first probe this far after unlock
const ORDERS_FREEZE_MS        = envInt('ORDERS_FREEZE_MS', 1500);        // stop order fetches this close to boundary when plan is ready
const CAPTCHA_FALLBACK_URL    = process.env.CAPTCHA_FALLBACK_URL || '';   // optional legacy solver for unknown/bad hashes

// Undercut / adjust
const L1_UNDERCUT              = envBool('L1_UNDERCUT', 'true');
const L1_UNDERCUT_STEP         = parseFloat(process.env.L1_UNDERCUT_STEP || '1');
const L1_UNDERCUT_MAX_ATTEMPTS = envInt('L1_UNDERCUT_MAX_ATTEMPTS', 2);
const AUTO_ADJUST              = envBool('AUTO_ADJUST', 'false');
const MAX_ADJUST_RETRIES       = envInt('MAX_ADJUST_RETRIES', 3);

// WAF
const WAF_MIN_MS   = envInt('WAF_BACKOFF_MIN_MS', 30000);
const WAF_MAX_MS   = envInt('WAF_BACKOFF_MAX_MS', 120000);
const WAF_RESET_MS = envInt('WAF_RESET_AFTER_MS', 300000);
const AUTH_DEAD_THRESHOLD   = envInt('AUTH_DEAD_THRESHOLD', 3);
const AUTH_DEAD_COOLDOWN_MS = envInt('AUTH_DEAD_COOLDOWN_MS', 30000);

const METRICS_MS = envInt('METRICS_INTERVAL_MS', 30000);
const SAP_HTTP2  = envBool('SAP_HTTP2', 'false');

const COOKIE_FILE  = path.join(ROOT, 'cookie.txt');
const TOKEN_FILE   = path.join(ROOT, 'token.txt');
const FILES_DIR    = path.join(ROOT, 'files');
const INPUT_CSV    = path.join(FILES_DIR, 'input2.csv');
const DELETE_CSV   = path.join(FILES_DIR, 'delete.csv');
const PRIORITY_CSV = path.join(FILES_DIR, 'priority.csv');
const CAPTCHA_MAP_FILE = process.env.CAPTCHA_MAP_FILE ? path.resolve(ROOT, process.env.CAPTCHA_MAP_FILE) : path.join(ROOT, 'data.json');
const LOGS_DIR = path.join(ROOT, 'logs');
if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const jitter = (max) => Math.floor(Math.random() * max);

// ---- Undici pool: warm, TCP_NODELAY, keep-alive ------------------------------

const baseConnect = buildConnector({ timeout: 5_000, allowH2: SAP_HTTP2, keepAlive: true, keepAliveInitialDelay: 5_000 });
const connect = (opts, cb) => baseConnect(opts, (err, socket) => {
  if (socket) {
    try { socket.setNoDelay(true); socket.setKeepAlive(true, 5_000); } catch (_) { /* ignore */ }
  }
  cb(err, socket);
});

const sapPool = new Pool(SAP_ORIGIN, {
  connections: envInt('SAP_CONNECTIONS', 16),
  pipelining: 1,
  keepAliveTimeout: 20_000,
  headersTimeout: 15_000,
  bodyTimeout: 15_000,
  allowH2: SAP_HTTP2,
  connect,
});

// ---- Window scheduler (IST) --------------------------------------------------

const IST_OFFSET_MS = 5.5 * 3_600_000;

// Epoch ms of the next configured boundary strictly after `nowMs`.
function nextBoundaryMs(nowMs = Date.now()) {
  const ist = nowMs + IST_OFFSET_MS;
  const hourStart = ist - (ist % 3_600_000);
  for (let h = 0; h < 2; h++) {
    for (const m of WINDOW_MINUTES) {
      const b = hourStart + h * 3_600_000 + m * 60_000;
      if (b > ist) return b - IST_OFFSET_MS;
    }
  }
  return hourStart + 3_600_000 - IST_OFFSET_MS;
}
function prevBoundaryMs(nowMs = Date.now()) {
  const ist = nowMs + IST_OFFSET_MS;
  const hourStart = ist - (ist % 3_600_000);
  for (let h = 0; h >= -1; h--) {
    for (let i = WINDOW_MINUTES.length - 1; i >= 0; i--) {
      const b = hourStart + h * 3_600_000 + WINDOW_MINUTES[i] * 60_000;
      if (b <= ist) return b - IST_OFFSET_MS;
    }
  }
  return hourStart - IST_OFFSET_MS;
}
function msUntilNextWindow() { const s = sapNow(); return nextBoundaryMs(s) - s; }
function msSinceLastWindow() { const s = sapNow(); return s - prevBoundaryMs(s); }
function isHotWindow() { return msUntilNextWindow() <= HOT_PRE_MS || msSinceLastWindow() <= HOT_POST_MS; }
function isActiveWindow() { return msSinceLastWindow() <= HOT_POST_MS; }
// Window key (wall-clock ms of the boundary) this moment belongs to, on SAP's clock.
function currentWindowMs() { const s = sapNow(); return msUntilNextWindow() < 2000 ? nextBoundaryMs(s) : prevBoundaryMs(s); }
function istHHMM(ms) {
  return new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(ms));
}
function boundaryStatusText() {
  const until = msUntilNextWindow();
  if (until < HOT_PRE_MS) return `${(until / 1000).toFixed(1)}s BEFORE ${istHHMM(nextBoundaryMs(sapNow()))} boundary (SAP clock)`;
  return `+${(msSinceLastWindow() / 1000).toFixed(1)}s past ${istHHMM(prevBoundaryMs(sapNow()))} boundary (SAP clock)`;
}

// ---- SAP clock sync ---------------------------------------------------------
//
// SAP's `Date` header has 1s resolution. We refine it by edge detection:
// poll SessionSet every ~100ms and note the local instant where the header
// second increments — that pins SAP's second boundary to ±(interval/2 + RTT/2).
// offset = sapNow - localNow. Fire time (local) = boundary - offset - oneWay.

const clock = {
  offsetMs: SAP_CLOCK_OFFSET_MS ?? 0,
  coarseOffsetMs: 0,
  dateOffsetMs: null,
  backendOffsetMs: null,
  source: SAP_CLOCK_OFFSET_MS != null ? 'env' : 'none',
  rttMs: 150,
  rttSamples: [],
  edges: [],
  backendSamples: [],
  unlockLagSamples: [],
  unlockLagMs: Math.max(0, UNLOCK_LAG_MS),
  unlockNotedWin: 0,
  synced: SAP_CLOCK_OFFSET_MS != null,
  lastSyncAt: 0,
};

function noteRtt(ms) {
  clock.rttSamples.push(ms);
  if (clock.rttSamples.length > 30) clock.rttSamples.shift();
  const s = [...clock.rttSamples].sort((a, b) => a - b);
  clock.rttMs = s[Math.floor(s.length / 2)];
}
function oneWayMs() { return Math.round(clock.rttMs / 2); }
function fireLeadMs() { return FIRE_LEAD_MS >= 0 ? FIRE_LEAD_MS : oneWayMs(); }
function sapNow() { return Date.now() + clock.offsetMs; }

// One probe: GET SessionSet, read Date header. Returns {t0,t1,sapSec} or null.
async function clockProbe(auth) {
  const t0 = Date.now();
  try {
    const r = await sapPool.request({
      path: `${SAP_PFX}/SessionSet('')`, method: 'GET',
      headers: auth.headers({ 'x-csrf-token': 'Fetch' }), headersTimeout: 3_000, bodyTimeout: 3_000,
    });
    const t1 = Date.now();
    await r.body.dump();
    noteRtt(t1 - t0);
    const tok = r.headers['x-csrf-token'];
    if (tok && String(tok).toLowerCase() !== 'required') auth.setToken(String(tok));
    const d = r.headers['date'];
    if (!d) return null;
    const sapMs = Date.parse(d);
    if (!Number.isFinite(sapMs)) return null;
    // coarse: assume header second is uniformly mid-way
    clock.coarseOffsetMs = Math.round(sapMs + 500 - (t0 + t1) / 2);
    return { t0, t1, mid: (t0 + t1) / 2, sapSec: Math.floor(sapMs / 1000) };
  } catch (_) { return null; }
}

async function syncSapClock(auth) {
  if (SAP_CLOCK_OFFSET_MS != null) return;
  const dateSync = syncViaDateHeader(auth);           // WAF/ICM clock (1s header, edge-refined)
  const backendSync = CLOCK_SOURCE === 'backend' ? syncViaBackendTimestamp(auth) : Promise.resolve(null);
  const [dateOff, backendOff] = await Promise.all([dateSync, backendSync]);
  clock.dateOffsetMs = dateOff;
  clock.backendOffsetMs = backendOff;
  if (backendOff != null) {
    clock.offsetMs = backendOff; clock.source = 'backend';
  } else if (dateOff != null) {
    clock.offsetMs = dateOff; clock.source = 'date-header';
  } else if (clock.coarseOffsetMs) {
    clock.offsetMs = clock.coarseOffsetMs; clock.source = 'date-coarse';
  }
  clock.synced = true;
  clock.lastSyncAt = Date.now();
  const delta = (backendOff != null && dateOff != null) ? ` | WAF-vs-backend delta ${dateOff - backendOff}ms` : '';
  log.info(`🕰  SAP clock sync [${clock.source}]: offset=${clock.offsetMs > 0 ? '+' : ''}${clock.offsetMs}ms (SAP ${clock.offsetMs >= 0 ? 'ahead' : 'behind'}) backend=${backendOff ?? 'n/a'}ms date-hdr=${dateOff ?? 'n/a'}ms${delta} | rtt=${clock.rttMs}ms | unlock-lag=${clock.unlockLagMs}ms (${clock.unlockLagSamples.length} windows) → first probe arrives boundary+${clock.unlockLagMs + UNLOCK_MARGIN_MS}ms`);
  saveClockState();
}

async function syncViaDateHeader(auth) {
  const end = Date.now() + CLOCK_SYNC_DURATION_MS;
  let prev = null;
  const edges = [];
  while (Date.now() < end) {
    const p = await clockProbe(auth);
    if (p) {
      if (prev && p.sapSec === prev.sapSec + 1) edges.push(Math.round(p.sapSec * 1000 - (prev.mid + p.mid) / 2));
      prev = p;
    }
    await sleep(CLOCK_SYNC_INTERVAL_MS);
  }
  clock.edges = edges;
  if (!edges.length) return null;
  const s = [...edges].sort((a, b) => a - b);
  return s[Math.floor(s.length / 2)];
}

// Backend (ABAP) clock: any bad OData URI returns a Gateway error XML with
// <timestamp>YYYYMMDDhhmmss.fffffff</timestamp> taken at processing time (µs).
// offset = backendTs - (t0 + t1)/2. Median of N probes.
async function backendClockProbe(auth) {
  const t0 = Date.now();
  try {
    const r = await sapPool.request({
      path: `${SAP_PFX}/ClockProbe${t0 % 1000}Set`, method: 'GET',
      headers: auth.headers({ accept: 'application/xml' }), headersTimeout: 3_000, bodyTimeout: 3_000,
    });
    const text = await r.body.text();
    const t1 = Date.now();
    const m = /<timestamp>(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})\.?(\d{0,7})<\/timestamp>/i.exec(text);
    if (!m) { clock.backendProbeErr = `HTTP ${r.statusCode} no <timestamp> (${text.slice(0, 80).replace(/\s+/g, ' ')})`; return null; }
    const frac = m[7] ? parseInt((m[7] + '0000000').slice(0, 3), 10) : 0;
    const utcMs = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6], frac);
    const mid = (t0 + t1) / 2;
    // Timestamp may be UTC or system-local (IST): pick the interpretation with the smaller |offset|.
    const cands = [utcMs - mid, utcMs - IST_OFFSET_MS - mid];
    const off = cands.reduce((a, b) => (Math.abs(b) < Math.abs(a) ? b : a));
    noteRtt(t1 - t0);
    return { offset: Math.round(off), rtt: t1 - t0 };
  } catch (e) { clock.backendProbeErr = e.message; return null; }
}

async function syncViaBackendTimestamp(auth) {
  const samples = [];
  for (let i = 0; i < CLOCK_BACKEND_PROBES; i++) {
    const p = await backendClockProbe(auth);
    if (p) samples.push(p);
    await sleep(CLOCK_SYNC_INTERVAL_MS + 50);
  }
  if (!samples.length) { log.warn(`backend clock probe unusable (${clock.backendProbeErr || 'no samples'}) — falling back to Date header`); return null; }
  // Prefer low-RTT samples (less asymmetric), then median.
  samples.sort((a, b) => a.rtt - b.rtt);
  const best = samples.slice(0, Math.max(3, Math.ceil(samples.length / 2))).map((s) => s.offset).sort((a, b) => a - b);
  clock.backendSamples = samples.map((s) => s.offset);
  return best[Math.floor(best.length / 2)];
}

// ---- Unlock-lag learning ------------------------------------------------------
// SAP unlocks the captcha some fixed lag after the boundary (observed ≈1s on its
// clock). We learn it per window from the first non-empty captcha and aim the
// first probe to ARRIVE at boundary + lag + margin. Persisted across restarts.
const CLOCK_STATE_FILE = path.join(LOGS_DIR, 'clock-state.json');
function loadClockState() {
  try {
    const s = JSON.parse(fs.readFileSync(CLOCK_STATE_FILE, 'utf8'));
    if (Array.isArray(s.unlockLagSamples)) clock.unlockLagSamples = s.unlockLagSamples.slice(-20);
    recomputeUnlockLag();
  } catch (_) { /* first run */ }
}
function saveClockState() {
  try { fs.writeFileSync(CLOCK_STATE_FILE, JSON.stringify({ unlockLagSamples: clock.unlockLagSamples, unlockLagMs: clock.unlockLagMs, lastOffsetMs: clock.offsetMs, savedAt: new Date().toISOString() })); } catch (_) { /* ignore */ }
}
function recomputeUnlockLag() {
  if (UNLOCK_LAG_MS >= 0) { clock.unlockLagMs = UNLOCK_LAG_MS; return; }
  const s = clock.unlockLagSamples.filter((v) => Number.isFinite(v) && v > -2000 && v < 30000).sort((a, b) => a - b);
  if (!s.length) { clock.unlockLagMs = 0; return; }
  // measured lag = true lag + detection delay (0..RTT) → the low quantile is closest to truth
  clock.unlockLagMs = Math.max(0, s[Math.floor(s.length * 0.2)]);
}
// Called with the local send time of the first probe that returned a captcha, plus
// (if any) the send time of the last EMPTY probe before it → unlock ∈ (empty, hit].
function noteUnlock(winKey, tReqLocal, tRespLocal, sid, lastEmptyReqLocal = 0) {
  if (clock.unlockNotedWin === winKey) return;
  clock.unlockNotedWin = winKey;
  const hitProc = tReqLocal + oneWayMs() + clock.offsetMs;   // SAP time when the hit probe was processed
  const hitLag = Math.round(hitProc - winKey);
  let lag;
  if (lastEmptyReqLocal && tReqLocal - lastEmptyReqLocal < 2 * clock.rttMs + 200) {
    const emptyLag = Math.round(lastEmptyReqLocal + oneWayMs() + clock.offsetMs - winKey);
    lag = Math.round((emptyLag + hitLag) / 2);                // bracketed → midpoint
  } else {
    lag = hitLag - UNLOCK_MARGIN_MS - 10;                     // first probe already unlocked → nudge earlier
  }
  clock.unlockLagSamples.push(lag);
  if (clock.unlockLagSamples.length > 20) clock.unlockLagSamples.shift();
  const before = clock.unlockLagMs;
  recomputeUnlockLag();
  unlockLog.write([new Date().toISOString(), istHHMM(winKey), sid, winKey, tReqLocal, tRespLocal, clock.offsetMs, clock.rttMs, hitLag, clock.unlockLagMs]);
  log.info(`🔓 captcha UNLOCK observed at boundary+${hitLag}ms (SAP ${clock.source} clock${lastEmptyReqLocal ? ', bracketed' : ', first probe already open'}) — learned lag ${before}→${clock.unlockLagMs}ms (${clock.unlockLagSamples.length} samples)`);
  saveClockState();
}
// Local instant at which session #idx should SEND its first captcha probe so it
// arrives at SAP at boundary + lag + margin (+ per-session phase spread).
function firstProbeLocalMs(boundaryMs, idx = 0, n = 1) {
  const phase = n > 1 ? Math.round((idx * clock.rttMs) / n) : 0;
  return boundaryMs + clock.unlockLagMs + UNLOCK_MARGIN_MS + phase - clock.offsetMs - oneWayMs();
}

// ---- WAF back-off (per-session, escalates to global) --------------------------

const waf = { globalUntil: 0, hits: 0 };

function markWaf(auth, reason) {
  const now = Date.now();
  waf.hits++;
  metrics.wafHits++;
  const target = auth || waf;
  const key = auth ? 'wafStep' : 'globalStep';
  const lastKey = auth ? 'wafLastAt' : 'globalLastAt';
  if (now - (target[lastKey] || 0) > WAF_RESET_MS) target[key] = WAF_MIN_MS;
  else target[key] = Math.min((target[key] || WAF_MIN_MS) * 2, WAF_MAX_MS);
  target[lastKey] = now;
  if (auth) {
    auth.wafUntil = now + target[key];
    log.error(`⚠  WAF hit on [${auth.id}] (${reason}) — session paused ${Math.round(target[key] / 1000)}s, other sessions continue. Total hits: ${waf.hits}`);
    if (sessionsRef.every((s) => s.wafUntil > now)) {
      waf.globalUntil = now + WAF_MIN_MS;
      log.error(`⚠  ALL sessions WAF-blocked — global pause ${WAF_MIN_MS / 1000}s`);
    }
  } else {
    waf.globalUntil = now + target[key];
    log.error(`⚠  WAF hit (${reason}) — global pause ${Math.round(target[key] / 1000)}s`);
  }
}
function wafActive(auth) {
  const now = Date.now();
  if (now < waf.globalUntil) return true;
  return !!(auth && auth.wafUntil > now);
}
function isWafResponse(statusCode, data) {
  if (statusCode === 406) return true;
  const s = typeof data === 'string' ? data.slice(0, 300) : '';
  return /Not Acceptable|<!DOCTYPE html>|indusguard|apptrana/i.test(s);
}

// ---- Auth (cookie + CSRF) ----------------------------------------------------

class AuthConfig {
  constructor(id, cookieFile, tokenFile) {
    this.id = id;
    this.cookieFile = cookieFile;
    this.tokenFile = tokenFile;
    this.cookie = this._read(cookieFile);
    this.token  = this._read(tokenFile);
    this.tokenMintedAt = this.token ? 0 : 0;
    this._refreshInFlight = null;
    this._lastPlantConf = null;
    this._lastCaptchaFlag = undefined;
    this.wafUntil = 0;
    this.inFlight = 0;
    let chain = Promise.resolve();
    this.mutex = {
      _busy: false,
      run: (fn) => {
        const wrapped = async () => { this.mutex._busy = true; try { return await fn(); } finally { this.mutex._busy = false; } };
        const p = chain.then(wrapped, wrapped);
        chain = p.catch(() => {});
        return p;
      },
    };
    if (!this.cookie) throw new Error(`Session ${id}: ${cookieFile} is empty. Paste browser Cookie header there.`);
  }
  _read(p) { try { return fs.readFileSync(p, 'utf8').trim(); } catch { return ''; } }
  setToken(tok) {
    this.token = tok;
    this.tokenMintedAt = Date.now();
    try { fs.writeFileSync(this.tokenFile, tok, 'utf8'); } catch (_) { /* ignore */ }
  }
  headers(extra = {}) {
    return {
      'content-type': 'application/json',
      'accept': 'application/json',
      'dataserviceversion': '2.0',
      'maxdataserviceversion': '2.0',
      'x-csrf-token': this.token || 'Fetch',
      'cookie': this.cookie,
      'x-requested-with': 'XMLHttpRequest',
      'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120 Safari/537.36',
      ...extra,
    };
  }
  async refreshToken() {
    if (this._refreshInFlight) return this._refreshInFlight;
    this._refreshInFlight = (async () => {
      const t0 = Date.now();
      try {
        const r = await sapPool.request({
          path: `${SAP_PFX}/SessionSet('')`, method: 'GET',
          headers: this.headers({ 'x-csrf-token': 'Fetch' }), headersTimeout: 5_000, bodyTimeout: 5_000,
        });
        await r.body.dump();
        noteRtt(Date.now() - t0);
        const tok = r.headers['x-csrf-token'];
        if (!tok || String(tok).toLowerCase() === 'required') throw new Error(`HTTP ${r.statusCode} — no CSRF token. Cookie may have expired.`);
        this.setToken(String(tok));
        log.debug(`[${this.id}] CSRF minted in ${Date.now() - t0}ms`);
        return this.token;
      } finally { this._refreshInFlight = null; }
    })();
    return this._refreshInFlight;
  }
}

let sessionsRef = [];

function discoverSessions() {
  const out = [];
  const add = (id, cf, tf) => { if (fs.existsSync(cf) && fs.readFileSync(cf, 'utf8').trim()) out.push({ id, cookieFile: cf, tokenFile: tf }); };
  add('s1', COOKIE_FILE, TOKEN_FILE);
  for (let n = 2; n <= 10; n++) add(`s${n}`, path.join(ROOT, `cookie${n}.txt`), path.join(ROOT, `token${n}.txt`));
  if (!out.length) { log.error(`No cookie file found. Paste your logged-in browser Cookie header into ${COOKIE_FILE}`); process.exit(1); }
  return out;
}

// ---- CSV logs ----------------------------------------------------------------

function csvLogger(prefix, header) {
  let day = ''; let stream = null;
  const esc = (v) => { const s = String(v == null ? '' : v); return /[",\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
  return {
    write(cols) {
      try {
        const today = new Date().toISOString().slice(0, 10);
        if (today !== day || !stream) {
          if (stream) stream.end();
          day = today;
          const f = path.join(LOGS_DIR, `${prefix}-${today}.csv`);
          const exists = fs.existsSync(f);
          stream = fs.createWriteStream(f, { flags: 'a' });
          if (!exists) stream.write(header + '\n');
        }
        stream.write(cols.map(esc).join(',') + '\n');
      } catch (_) { /* never break bidding */ }
    },
  };
}
const bidLog  = csvLogger('bids', 'timestamp,session,sap_order_id,city,spi,csv_rate,submit_ms,status,message');
const fireLog = csvLogger('fire-timing', 'ts,window,session,attempt,t_boundary_sap_ms,t_captcha_req_ms,t_captcha_resp_ms,captcha_ms,lookup_hit,t_submit_req_ms,t_submit_resp_ms,submit_ms,total_from_boundary_ms,status');
const unlockLog = csvLogger('unlock-lag', 'ts,window,session,boundary_ms,probe_sent_local_ms,probe_resp_local_ms,sap_offset_ms,rtt_ms,unlock_lag_ms,learned_lag_ms');

function writeBid(session, b, submitMs, status, message) {
  bidLog.write([new Date().toISOString(), session, b.order.SapOrderId, b.city, b.spi, b.amount, submitMs ?? '', status, message]);
}

// ---- SAP request helper ------------------------------------------------------

const NETWORK_ERR_RE = /HeadersTimeoutError|Headers Timeout|UND_ERR_CONNECT_TIMEOUT|UND_ERR_SOCKET|ETIMEDOUT|ECONNRESET|socket hang up|other side closed/i;

async function sapRequest(auth, { path: p, method = 'POST', body, timeoutMs = 5000, retryOnNetworkError = false }) {
  const doOnce = () => sapPool.request({
    path: p, method, headers: auth.headers(), body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
    headersTimeout: timeoutMs, bodyTimeout: timeoutMs,
  });
  const doWithRetry = async () => {
    try { return await doOnce(); } catch (e) {
      if (!retryOnNetworkError || !NETWORK_ERR_RE.test((e && e.message) || String(e))) throw e;
      await sleep(100);
      auth._netRetries = (auth._netRetries || 0) + 1;
      return doOnce();
    }
  };
  if (auth._deadUntil && Date.now() < auth._deadUntil) {
    return { statusCode: 401, headers: {}, data: { _cookieDead: true } };
  }
  if (!auth.token) await auth.refreshToken();
  let r = await doWithRetry();
  if (r.statusCode === 403 && String(r.headers['x-csrf-token'] || '').toLowerCase() === 'required') {
    await r.body.dump();
    log.warn(`[${auth.id}] CSRF rejected — re-minting and retrying once.`);
    await auth.refreshToken();
    r = await doWithRetry();
    if (r.statusCode === 403) {
      auth._deadCount = (auth._deadCount || 0) + 1;
      if (auth._deadCount >= AUTH_DEAD_THRESHOLD) {
        auth._deadUntil = Date.now() + AUTH_DEAD_COOLDOWN_MS;
        if (!auth._lastDeadWarnAt || Date.now() - auth._lastDeadWarnAt > 5 * 60_000) {
          auth._lastDeadWarnAt = Date.now();
          log.error(`🔒 COOKIE EXPIRED for [${auth.id}] — re-login in browser, paste Cookie header into ${path.basename(auth.cookieFile)}, delete ${path.basename(auth.tokenFile)}, restart. Pausing this session ${AUTH_DEAD_COOLDOWN_MS / 1000}s.`);
        }
      }
    } else auth._deadCount = 0;
  } else if (r.statusCode < 400) auth._deadCount = 0;
  const text = await r.body.text();
  let data;
  try { data = text ? JSON.parse(text) : {}; } catch { data = text; }
  return { statusCode: r.statusCode, headers: r.headers, data };
}

// ---- Metrics -----------------------------------------------------------------

const metrics = {
  startedAt: Date.now(), captchaFetches: 0, captchaEmpty: 0, captchaHit: 0, captchaUnknown: 0,
  submits: 0, submitsOk: 0, submitsWrongCaptcha: 0, submitsTimeEnded: 0, submitsRejected: 0, submitsGhost: 0,
  submitMs: [], captchaMs: [], wafHits: 0,
};
const pushCap = (arr, v) => { arr.push(v); if (arr.length > 200) arr.shift(); };
const avg = (a) => (a.length ? Math.round(a.reduce((x, y) => x + y, 0) / a.length) : 0);
function metricsDump() {
  log.info(`[metrics] up=${Math.round((Date.now() - metrics.startedAt) / 1000)}s | captcha fetch=${metrics.captchaFetches} empty=${metrics.captchaEmpty} hit=${metrics.captchaHit} unknown=${metrics.captchaUnknown} avg=${avg(metrics.captchaMs)}ms | submits=${metrics.submits} ok=${metrics.submitsOk} wrong-captcha=${metrics.submitsWrongCaptcha} ghost=${metrics.submitsGhost} time-ended=${metrics.submitsTimeEnded} rejected=${metrics.submitsRejected} avg=${avg(metrics.submitMs)}ms | rtt=${clock.rttMs}ms sap-offset=${clock.offsetMs}ms waf=${waf.hits}`);
}

// ---- Captcha map: in-memory 0ms lookup -----------------------------------------

const captchaMap = new Map();
const unknownSeen = new Set();
const BAD_MAP_FILE = path.join(ROOT, 'captcha-bad.json');
let badAnswers = {};                       // hash → { wrong, ts, count }

function loadCaptchaMap() {
  try { badAnswers = JSON.parse(fs.readFileSync(BAD_MAP_FILE, 'utf8')) || {}; } catch (_) { badAnswers = {}; }
  try {
    const raw = JSON.parse(fs.readFileSync(CAPTCHA_MAP_FILE, 'utf8'));
    const list = Array.isArray(raw) ? raw : Object.entries(raw).map(([hash, result]) => ({ hash, result }));
    captchaMap.clear();
    let skipped = 0;
    for (const e of list) {
      if (!e || !e.hash || !e.result) continue;
      const h = String(e.hash).toLowerCase();
      if (badAnswers[h] && badAnswers[h].wrong === String(e.result)) { skipped++; continue; }
      captchaMap.set(h, String(e.result));
    }
    log.info(`🧩 Captcha map loaded: ${captchaMap.size} known images from ${path.basename(CAPTCHA_MAP_FILE)} (in-process sha256 lookup)${skipped ? ` — ${skipped} answers excluded: SAP rejected them earlier (see captcha-bad.json + logs/wrong-captcha/)` : ''}${CAPTCHA_FALLBACK_URL ? ` | fallback solver ${CAPTCHA_FALLBACK_URL}` : ''}`);
  } catch (e) {
    log.error(`Captcha map load failed (${CAPTCHA_MAP_FILE}): ${e.message}`);
  }
}
const stripDataUri = (b64) => (typeof b64 === 'string' && b64.includes(',') ? b64.split(',')[1] : b64);
const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// Returns { solved, hash, raw, source } — solved '' when unknown. Microseconds.
function lookupCaptcha(img) {
  const raw = stripDataUri(img);
  const hash = sha256(raw);
  const solved = captchaMap.get(hash) || '';
  if (!solved) logUnknownCaptcha(hash, raw);
  return { solved, hash, raw, source: 'map' };
}

// Opt-in: legacy HTTP solver (bidding.js / TrueCaptcha) for unknown or rejected hashes only.
async function fallbackSolve(raw) {
  if (!CAPTCHA_FALLBACK_URL) return '';
  const t0 = Date.now();
  try {
    const u = new URL(CAPTCHA_FALLBACK_URL);
    const r = await fallbackPool.request({ path: u.pathname || '/', method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ base64Image: raw }), headersTimeout: 8_000, bodyTimeout: 8_000 });
    const j = JSON.parse(await r.body.text());
    const s = (j.solved || '').toString().trim();
    if (s && s !== 'Redo') { log.info(`🧩 fallback solver → "${s}" in ${Date.now() - t0}ms`); return s; }
  } catch (e) { log.warn(`fallback solver failed: ${e.message}`); }
  return '';
}
const fallbackPool = CAPTCHA_FALLBACK_URL ? new Pool(new URL(CAPTCHA_FALLBACK_URL).origin, { connections: 2, keepAliveTimeout: 30_000 }) : null;

// SAP accepted an answer that did not come from the map → learn it into the map file.
function learnCaptcha(hash, answer) {
  if (!hash || !answer || captchaMap.get(hash) === answer) return;
  captchaMap.set(hash, answer);
  try {
    const raw = JSON.parse(fs.readFileSync(CAPTCHA_MAP_FILE, 'utf8'));
    const list = Array.isArray(raw) ? raw.filter((e) => e && e.hash !== hash) : Object.entries(raw).map(([h, result]) => ({ hash: h, result })).filter((e) => e.hash !== hash);
    list.push({ hash, file: `learned-${Date.now()}.png`, result: answer, savedAt: Date.now() });
    fs.writeFileSync(CAPTCHA_MAP_FILE, JSON.stringify(list, null, 2));
    delete badAnswers[hash];
    fs.writeFileSync(BAD_MAP_FILE, JSON.stringify(badAnswers, null, 2));
    log.info(`🧩 LEARNED captcha ${hash.slice(0, 12)}… = "${answer}" (SAP accepted) → saved to ${path.basename(CAPTCHA_MAP_FILE)}`);
  } catch (e) { log.warn(`learnCaptcha write failed: ${e.message}`); }
}
function logUnknownCaptcha(hash, raw) {
  metrics.captchaUnknown++;
  if (unknownSeen.has(hash)) return;
  unknownSeen.add(hash);
  try {
    const dir = path.join(LOGS_DIR, 'unknown-captcha');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${hash}.png`), Buffer.from(raw, 'base64'));
    fs.appendFileSync(path.join(LOGS_DIR, 'unknown-captcha.jsonl'), JSON.stringify({ ts: new Date().toISOString(), hash, len: raw.length, base64: raw }) + '\n');
    log.warn(`🧩 UNKNOWN captcha hash ${hash.slice(0, 12)}… — saved logs/unknown-captcha/${hash.slice(0, 12)}….png. Add {"hash","result"} to ${path.basename(CAPTCHA_MAP_FILE)} (hot-reloaded).`);
  } catch (_) { /* ignore */ }
}
function dropCaptchaAnswer(hash, wrong, raw) {
  if (!hash) return;
  captchaMap.delete(hash);
  const prev = badAnswers[hash] || { count: 0 };
  badAnswers[hash] = { wrong, ts: new Date().toISOString(), count: prev.count + 1 };
  try {
    fs.writeFileSync(BAD_MAP_FILE, JSON.stringify(badAnswers, null, 2));
    if (raw) {
      const dir = path.join(LOGS_DIR, 'wrong-captcha');
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(path.join(dir, `${hash.slice(0, 16)}__was-${String(wrong).replace(/[^A-Za-z0-9]/g, '_')}.png`), Buffer.from(raw, 'base64'));
    }
  } catch (_) { /* ignore */ }
  log.warn(`🧩 SAP rejected answer "${wrong}" for hash ${hash.slice(0, 12)}… — PERSISTED to captcha-bad.json (excluded on every restart). Image: logs/wrong-captcha/${hash.slice(0, 16)}__was-*.png → read it and fix ${path.basename(CAPTCHA_MAP_FILE)}.`);
}

// ---- CSV rules ---------------------------------------------------------------

function parseCSV(filePath) {
  return new Promise((resolve, reject) => {
    if (!fs.existsSync(filePath)) return resolve([]);
    const rows = [];
    fs.createReadStream(filePath).pipe(csv()).on('data', (d) => rows.push(d)).on('end', () => resolve(rows)).on('error', reject);
  });
}

function buildRuleMaps(inputRows, deleteRows) {
  const rules = new Map();
  for (const r of inputRows) {
    const city = (r['City Code Descriptio'] || r['City Code Description'] || '').trim().toUpperCase();
    const spi  = (r['Special Process Indi'] || r['Special Process Indicator'] || '').trim();
    const amt  = parseFloat(r['BIDING AMMOUNT'] || r['Bidding Amount'] || '0');
    if (!city || !amt) continue;
    if (!rules.has(city)) rules.set(city, []);
    rules.get(city).push({ spi, amount: amt });
  }
  const blacklist = deleteRows.map((r) => (r.Customer || r.City || Object.values(r)[0] || '').toString().trim().toUpperCase()).filter(Boolean);
  return { rules, blacklist };
}

function pickBySpi(list, orderSpi, ruleCity, matchKind) {
  if (!Array.isArray(list) || !list.length) return null;
  for (const rule of list) if (rule.spi && orderSpi.includes(rule.spi)) return { amount: rule.amount, matchedCity: ruleCity, matchedSpi: rule.spi, matchKind };
  for (const rule of list) if (!rule.spi) return { amount: rule.amount, matchedCity: ruleCity, matchedSpi: '(any)', matchKind };
  return null;
}

function matchOrder(order, rules, ruleCitiesByLen) {
  const dest = (order.Destination || order.DestCityDesc || order.CityCodeDescription || '').toString().trim().toUpperCase();
  if (!dest) return null;
  const orderSpi = (order.SPI || order.Spi || order.SpecialProcessInd || order.Zspi || '').toString().trim();
  for (const rc of ruleCitiesByLen) { if (dest !== rc) continue; const hit = pickBySpi(rules.get(rc), orderSpi, rc, 'exact'); if (hit) return hit; }
  for (const rc of ruleCitiesByLen) {
    if (dest === rc || !(dest.includes(rc) || rc.includes(dest))) continue;
    const hit = pickBySpi(rules.get(rc), orderSpi, rc, 'substr'); if (hit) return hit;
  }
  return null;
}

function isCustomerBlacklisted(order, blacklist) {
  const names = [order.KunagName1, order.KunweName1, order.CustomerOrg, order.Customer, order.CustomerName, order.Kunag, order.Kunnr, order.Kunwe]
    .filter(Boolean).map((v) => v.toString().trim().toUpperCase());
  if (!names.length) return false;
  return blacklist.some((b) => names.some((n) => n === b || n.includes(b) || b.includes(n)));
}

function loadPriorityVbelns() {
  const set = new Set();
  try {
    if (fs.existsSync(PRIORITY_CSV)) {
      const lines = fs.readFileSync(PRIORITY_CSV, 'utf8').split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
      const hasHeader = lines.length && /[A-Za-z]/.test(lines[0]) && !lines[0].startsWith('#');
      let col = 0;
      if (hasHeader) {
        const cols = lines[0].split(',').map((c) => c.trim().toLowerCase());
        const i = cols.findIndex((c) => ['vbeln', 'cof order id', 'coforderid', 'orderid', 'order id'].includes(c));
        col = i >= 0 ? i : 0;
      }
      lines.forEach((line, i) => {
        if (line.startsWith('#') || (hasHeader && i === 0)) return;
        const v = (line.split(',')[col] || '').trim();
        if (v) set.add(v);
      });
    }
  } catch (e) { log.warn(`priority.csv read failed: ${e.message}`); }
  for (const v of (process.env.PRIORITY_VBELNS || '').split(',')) if (v.trim()) set.add(v.trim());
  return set;
}

// ---- Batcher -----------------------------------------------------------------

function buildBatches(orders, ctx) {
  const { rules, blacklist, submitted: seen, inFlight, cooldown, priorityVbelns: priSet } = ctx;
  const now = Date.now();
  const stats = { total: orders.length, matched: 0, blacklisted: 0, noRule: 0, clubDropped: 0, coolskip: 0, priority: 0 };
  const ruleCitiesByLen = Array.from(rules.keys()).sort((a, b) => b.length - a.length);
  const reverse = (process.env.MATCH_ORDER_REVERSE ?? 'true').toLowerCase() !== 'false';
  const iter = reverse ? [...orders].reverse() : orders;

  const fresh = iter.filter((o) => {
    const key = String(o.SapOrderId || '');
    if (!key || seen.has(key) || inFlight.has(key)) return false;
    const retryAt = cooldown.get(key);
    if (retryAt && retryAt > now) { stats.coolskip++; return false; }
    if (retryAt) cooldown.delete(key);
    return true;
  });
  const isPriority = (o) => {
    if (!priSet.size) return false;
    const v = (o.Vbeln || o.CofOrderId || o.CofOrder || '').toString().trim();
    return (v && priSet.has(v)) || priSet.has((o.SapOrderId || '').toString().trim());
  };
  const byClub = new Map();
  for (const o of fresh) { const c = (o.ClubId || '').toString().trim(); if (!byClub.has(c)) byClub.set(c, []); byClub.get(c).push(o); }

  const singles = []; const clubs = [];
  for (const [club, members] of byClub) {
    if (!club) {
      for (const o of members) {
        if (isCustomerBlacklisted(o, blacklist)) { stats.blacklisted++; continue; }
        const m = matchOrder(o, rules, ruleCitiesByLen);
        if (!m) { stats.noRule++; continue; }
        stats.matched++;
        const priority = isPriority(o); if (priority) stats.priority++;
        singles.push({ order: o, amount: m.amount, city: m.matchedCity, spi: m.matchedSpi, priority });
      }
    } else {
      const items = []; let drop = false; let pri = false;
      for (const o of members) {
        if (isCustomerBlacklisted(o, blacklist)) { drop = true; break; }
        const m = matchOrder(o, rules, ruleCitiesByLen);
        if (!m) { drop = true; break; }
        if (isPriority(o)) pri = true;
        items.push({ order: o, amount: m.amount, city: m.matchedCity, spi: m.matchedSpi });
      }
      if (drop) { stats.clubDropped++; continue; }
      stats.matched += items.length; if (pri) stats.priority += items.length;
      for (let i = 0; i < items.length; i += BATCH_SIZE) clubs.push({ clubId: club, bids: items.slice(i, i + BATCH_SIZE), priority: pri });
    }
  }
  const pack = (arr) => { const out = []; for (let i = 0; i < arr.length; i += BATCH_SIZE) out.push(arr.slice(i, i + BATCH_SIZE)); return out; };
  const plan = [];
  for (const b of pack(singles.filter((s) => s.priority)))  plan.push({ kind: 'single', bids: b, priority: true });
  for (const c of clubs.filter((c) => c.priority))          plan.push({ kind: 'club', bids: c.bids, clubId: c.clubId, priority: true });
  for (const b of pack(singles.filter((s) => !s.priority))) plan.push({ kind: 'single', bids: b, priority: false });
  for (const c of clubs.filter((c) => !c.priority))         plan.push({ kind: 'club', bids: c.bids, clubId: c.clubId, priority: false });
  return { plan, stats };
}

// ---- SAP calls ---------------------------------------------------------------

// Shared across sessions: same vendor+plant → same plant conf / captcha flag.
const sapState = { plantConf: null, captchaFlag: undefined };

async function fetchLiveOrders(auth) {
  if (wafActive(auth)) return { orders: [], plantConf: null };
  const today = new Date().toISOString().slice(0, 10) + 'T00:00:00';
  const payload = {
    EvFrieghtPercent: '', EvTolerenceAmount: '', IvBidBiddingPlantFlag: '', IvBiddingStatus: '2', IvStatus: '',
    NavBidApplAreaRange: [], NavBidBgpRange: [], NavBidBiddingPlant: [], NavBidBrandRange: [], NavBidClubId: [],
    NavBidCurrDtDm: { CurrDate: '/Date(1467981296000)/', CurrTime: null },
    NavBidErdatRange: [{ Sign: 'I', Option: 'BT', Low: today, High: today }],
    NavBidGradeRange: [], NavBidKunagRange: [], NavBidKunweRange: [], NavBidMessage: [], NavBidOrderIdRange: [],
    NavBidPackRange: [], NavBidPlntConf: [], NavBidSapOrderIdRange: [], NavBidSapStoIdRange: [], NavBidSchVendors: [],
    NavBidShipFromWerksRange: [{ Sign: 'I', Option: 'EQ', Low: PLANT_CODE, High: '' }],
    NavBidShipToVkburRange: [], NavBidStateRange: [], NavBidStoIdRange: [], NavBidToler: [], NavBidTolerence: [],
    NavBidVendorRange: [{ Sign: 'I', Option: 'EQ', Low: VENDOR_ID, High: '' }],
    NavBidVendorStatus: [{ Sign: 'I', Option: 'EQ', Low: '1', High: '' }],
  };
  const res = await sapRequest(auth, { path: `${SAP_PFX}/BidOrderListSet`, method: 'POST', body: payload, timeoutMs: FETCH_ORDERS_TIMEOUT_MS, retryOnNetworkError: true });
  if (res.statusCode !== 200 && res.statusCode !== 201) {
    if (isWafResponse(res.statusCode, res.data)) { markWaf(auth, `BidOrderListSet HTTP ${res.statusCode}`); return { orders: [], plantConf: null }; }
    if (res.data && res.data._cookieDead) return { orders: [], plantConf: null };
    log.warn(`[${auth.id}] BidOrderListSet → HTTP ${res.statusCode} | ${(typeof res.data === 'string' ? res.data : JSON.stringify(res.data)).slice(0, 200)}`);
    return { orders: [], plantConf: null };
  }
  const d = res.data?.d || {};
  const orders = d.NavBidSchVendors?.results || d.results || (Array.isArray(d) ? d : []);
  auth._lastPlantConf = d.NavBidPlntConf?.results?.[0] || null;
  if (auth._lastPlantConf) sapState.plantConf = auth._lastPlantConf;
  const captchaFlag = (d.EvCaptchaFlag || '').toString();
  if (sapState.captchaFlag !== captchaFlag) {
    log.info(captchaFlag === '' ? `[${auth.id}] ⚡ EvCaptchaFlag='' — captcha-free fast-path` : `[${auth.id}] 🔒 EvCaptchaFlag='${captchaFlag}' — captcha required`);
  }
  sapState.captchaFlag = captchaFlag;
  auth._lastCaptchaFlag = captchaFlag;
  return { orders, plantConf: auth._lastPlantConf, captchaFlag };
}

// Fetch exactly ONE captcha. Never poll this while a valid captcha is outstanding.
async function fetchCaptchaImage(auth) {
  if (wafActive(auth)) return { img: null, reason: 'waf' };
  metrics.captchaFetches++;
  const t0 = Date.now();
  const res = await sapRequest(auth, { path: `${SAP_PFX}/EbiddingCaptchaSet(Vendor='${VENDOR_ID}',Plant='${PLANT_CODE}')`, method: 'GET', timeoutMs: FETCH_CAPTCHA_TIMEOUT_MS });
  pushCap(metrics.captchaMs, Date.now() - t0);
  if (isWafResponse(res.statusCode, res.data)) { markWaf(auth, 'EbiddingCaptchaSet'); return { img: null, reason: 'waf-406' }; }
  if (res.statusCode !== 200 && res.statusCode !== 201) return { img: null, reason: `http-${res.statusCode}` };
  const d = res.data?.d || {};
  const img = d.ImageString || d.Captcha || d.CaptchaImage || d.EvCaptcha || null;
  if (!img) metrics.captchaEmpty++;
  return { img, reason: img ? 'ok' : 'sap-empty', ms: Date.now() - t0 };
}

const fmtAmtInt = (v) => `${Math.round(Number(v || 0))}`;
const fmtAmtSap = (v) => `${Math.round(Number(v || 0))}.000`;

// Pre-built payload (everything except the captcha value).
function buildSavePayload(auth, bids) {
  const pc = auth._lastPlantConf || sapState.plantConf || {};
  const biddingDate = pc.BiddingDate || `/Date(${Date.now()})/`;
  const slotNumber = (pc.SlotNumber ?? '').toString();
  return {
    Flag: '1', Ev_Text: '', NavEBiddingMessage: {},
    NavEBiddingTrackHis: bids.map((b) => {
      const o = b.order || {};
      return {
        Mandt: '', SapOrderId: String(b.order.SapOrderId), Vendor: VENDOR_ID, ChangeNo: '',
        ShipFromWerks: (o.ShipFromWerks || PLANT_CODE).toString(), BiddingDate: biddingDate, SlotNumber: slotNumber,
        Freight: fmtAmtSap(o.Freight ?? 0), ClubId: (o.ClubId || '').toString(), ClubFreight: fmtAmtSap(o.ClubFreight ?? 0),
        BiddingAmount: fmtAmtSap(b.amount), BiddingRank: fmtAmtInt(o.BiddingRank ?? 0), AvgWtBidAmount: fmtAmtSap(b.amount),
        CreatedOn: null, CreatedAt: null,
      };
    }),
  };
}

let submitDumps = 0;
async function submitBid(auth, payloadBase, solvedCaptcha) {
  const t0 = Date.now();
  const payload = solvedCaptcha === '__NO_CAPTCHA_REQUIRED__' ? payloadBase : { ...payloadBase, IvCaptchaValue: solvedCaptcha };
  auth.inFlight++;
  let res;
  try { res = await sapRequest(auth, { path: `${SAP_PFX}/EBiddingSaveSet`, method: 'POST', body: payload, timeoutMs: SUBMIT_TIMEOUT_MS }); }
  finally { auth.inFlight--; }
  const submitMs = Date.now() - t0;
  pushCap(metrics.submitMs, submitMs);
  const d = res.data?.d || {};
  const messages = extractSapMessages(d);
  const sev = { E: 3, I: 2, S: 1, '': 0 };
  let primary = { info: '', text: '' };
  for (const m of messages) if ((sev[m.info] || 0) > (sev[primary.info] || 0)) primary = m;
  if (!primary.text && d.Ev_Text) primary = { info: primary.info || '', text: d.Ev_Text };
  if (submitDumps < 50) {
    submitDumps++;
    try { fs.appendFileSync(path.join(LOGS_DIR, 'submit-responses.jsonl'), JSON.stringify({ ts: new Date().toISOString(), session: auth.id, submitMs, statusCode: res.statusCode, primary, messages, raw: JSON.stringify(res.data).slice(0, 4000) }) + '\n'); } catch (_) { /* ignore */ }
  }
  const rankHints = (d?.NavEBiddingTrackHis?.results || []).map((t) => {
    const changeNo = (t.ChangeNo || '').toString();
    const createdAt = (t.CreatedAt || '').toString();
    const ghost = (!changeNo || /^A+={0,2}$/.test(changeNo)) && (t.CreatedOn == null) && /^PT(0+H)?(0+M)?0+S$/i.test(createdAt);
    return { sapOrderId: String(t.SapOrderId || ''), rank: String(t.BiddingRank || ''), savedAmt: String(t.BiddingAmount || ''), l1Amt: String(t.L1BidAmount || ''), isGhostRecord: ghost };
  });
  return { statusCode: res.statusCode, info: primary.info, text: primary.text, evText: (d.Ev_Text || '').toString(), messages, submitMs, rankHints, isWaf: isWafResponse(res.statusCode, res.data) };
}

function extractSapMessages(d) {
  const msgs = [];
  const nav = d?.NavEBiddingMessage;
  if (Array.isArray(nav?.results)) for (const m of nav.results) msgs.push({ info: (m.Type || m.Info || m.MessageType || '').toString().trim(), text: (m.Message || m.MessageText || m.Text || '').toString().trim() });
  else if (nav && (nav.Type || nav.Info || nav.Message || nav.MessageText)) msgs.push({ info: (nav.Type || nav.Info || '').toString().trim(), text: (nav.Message || nav.MessageText || '').toString().trim() });
  if (d?.Ev_Text) msgs.push({ info: '', text: d.Ev_Text.toString().trim() });
  return msgs;
}
function parseReduceAmount(text) {
  if (!text || !/reduce|less than|minimum/i.test(text)) return null;
  const m = /(?:by|minimum|less than)\s*(?:rs\.?|₹|inr)?\s*([\d]+(?:\.\d+)?)/i.exec(text);
  return m ? parseFloat(m[1]) : null;
}
function parseMinFloor(text) {
  if (!text) return null;
  const re = /greater\s*than\s*or\s*equal\s*to\s*([\d]+(?:\.\d+)?)/gi;
  let max = null; let m;
  while ((m = re.exec(text)) !== null) { const v = parseFloat(m[1]); if (isFinite(v) && (max === null || v > max)) max = v; }
  return max;
}

// Classify a submit result. Pure function → one of:
// ok | tied | wrong-captcha | ghost | time-ended | floor | reduce | info | rejected | waf | unknown
function classify(r) {
  if (r.isWaf) return { kind: 'waf' };
  if (r.statusCode === 401 || r.statusCode === 403) return { kind: 'auth' };
  if (r.statusCode >= 500) return { kind: 'http-error' };
  const text = (r.text || '').toLowerCase();
  const ev = (r.evText || '').toLowerCase();
  const tied = /same\s+(avg\s+)?amount\s+has\s+been\s+bid\s+by\s+other\s+vendor/i.test(ev);
  const savedOk = /saved successfully|bid.*accepted|success/i.test(text);
  const explicitSuccess = r.info === 'S' && /saved\s*successfully/i.test(r.text || '') && !r.evText.trim() && !tied;
  const ghostHints = r.rankHints.filter((h) => h.isGhostRecord);
  const ghost = ghostHints.length > 0 && ghostHints.length === r.rankHints.length && !explicitSuccess;
  const wrongCaptcha = /captcha.*(fail|wrong|invalid)|worng\s*captcha/i.test(text);
  const timeEnded = /ended|closed|expired/i.test(text) && !savedOk;
  const floor = parseMinFloor(r.evText || r.text);
  const reduce = parseReduceAmount(r.evText || r.text);
  if (wrongCaptcha) return { kind: 'wrong-captcha' };
  if (tied) return { kind: 'tied' };
  if (!ghost && r.info !== 'E' && ((r.info === 'S' && !/ended|closed|expired|invalid|error/i.test(text)) || savedOk)) return { kind: 'ok' };
  if (timeEnded) return { kind: 'time-ended' };
  if (floor !== null && floor > 0) return { kind: 'floor', floor };
  if (reduce !== null && reduce > 0) return { kind: 'reduce', reduce };
  if ((r.statusCode === 200 || r.statusCode === 201) && !r.info && !r.text && !ghost) return { kind: 'ok', silent: true };
  if (ghost) return { kind: 'ghost', ids: ghostHints.map((h) => h.sapOrderId) };
  if (r.info === 'I') return { kind: 'info' };
  if (r.info === 'E') return { kind: 'rejected' };
  return { kind: 'unknown' };
}

// ---- FIRE LOOP: fetch captcha → lookup → submit, per session, serialized -------

/**
 * Runs one plan item on one session until success / definitive result /
 * deadline. Each attempt is a self-contained pair: ONE captcha fetch, then
 * an immediate submit. `race` = shared token when several sessions race
 * the same item; first success stops the others.
 */
async function fireItem(ctx, auth, item, race = null) {
  const sid = auth.id;
  const startedAt = Date.now();
  const winKey = currentWindowMs();
  const boundarySapLocal = winKey - clock.offsetMs; // local instant when SAP clock hit the boundary
  const list = item.bids.map((b) => `${b.order.SapOrderId}[${b.city}/${b.spi}]@${b.amount}`).join(', ');
  log.info(`[${sid}] 🎯 FIRE ${item.kind.toUpperCase()}${item.clubId ? ' id=' + item.clubId : ''} (${item.bids.length}): ${list}`);

  let payload = buildSavePayload(auth, item.bids);
  let attempts = 0;
  let emptyCount = 0;
  let firstEmptyAt = 0;
  let lastEmptyReq = 0;
  let lastCaptchaHash = null;
  let lastCaptchaRaw = null;
  let solvedSource = 'map';

  const done = (result) => result;
  const isRaceDone = () => race && race.done;

  while (true) {
    if (isRaceDone()) return done({ kind: 'race-lost' });
    if (Date.now() - startedAt > FIRE_MAX_WAIT_MS) { log.warn(`[${sid}] fire loop timed out after ${FIRE_MAX_WAIT_MS / 1000}s`); return done({ kind: 'timeout' }); }
    if (wafActive(auth)) { log.warn(`[${sid}] WAF back-off active — leaving fire loop`); return done({ kind: 'waf' }); }
    if (auth._deadUntil && Date.now() < auth._deadUntil) return done({ kind: 'cookie-dead' });

    // ---- captcha: exactly one fetch per attempt --------------------------------
    let solved; let tCapReq = 0; let tCapResp = 0;
    if (auth.arming) await auth.arming;
    const armed = auth.armed; auth.armed = null;
    if (auth._lastCaptchaFlag === '' || (auth._lastCaptchaFlag === undefined && sapState.captchaFlag === '')) {
      solved = '__NO_CAPTCHA_REQUIRED__';
    } else if (armed && Date.now() - armed.at < ARMED_CAPTCHA_MAX_AGE_MS) {
      solved = armed.solved; lastCaptchaHash = armed.hash; lastCaptchaRaw = armed.raw; solvedSource = armed.source || 'map'; tCapReq = armed.t0; tCapResp = armed.at;
      metrics.captchaHit++;
      log.info(`[${sid}] ⚡ using armed captcha (fetched ${Date.now() - armed.at}ms ago, in parallel with orders)`);
    } else {
      // First probe of the window: wait so it ARRIVES at SAP at boundary + learned unlock lag + margin.
      if (emptyCount === 0 && !lastCaptchaHash) {
        const idx = Math.max(0, ctx.sessions.indexOf(auth));
        const wait = firstProbeLocalMs(winKey, idx, ctx.sessions.length) - Date.now();
        if (wait > 0 && wait < 120_000) { log.info(`[${sid}] ⏲  holding first probe ${wait}ms → arrives boundary+${clock.unlockLagMs + UNLOCK_MARGIN_MS}ms (lag ${clock.unlockLagMs} + margin ${UNLOCK_MARGIN_MS}, phase ${idx}/${ctx.sessions.length})`); await sleep(wait); }
      }
      tCapReq = Date.now();
      const { img, reason } = await fetchCaptchaImage(auth);
      tCapResp = Date.now();
      if (!img) {
        if (reason === 'sap-empty') {
          emptyCount++;
          lastEmptyReq = tCapReq;
          if (!firstEmptyAt) firstEmptyAt = Date.now();
          if (emptyCount === 1 || emptyCount % 40 === 0) log.info(`[${sid}] ⏳ captcha not unlocked yet (${emptyCount} empties, ${boundaryStatusText()})`);
          const slow = Date.now() - firstEmptyAt > 3000;
          await sleep((slow ? CAPTCHA_EMPTY_SLOW_MS : CAPTCHA_EMPTY_RETRY_MS) + jitter(8));
          continue;
        }
        log.warn(`[${sid}] captcha fetch failed: ${reason}`);
        await sleep(150 + jitter(50));
        continue;
      }
      noteUnlock(winKey, tCapReq, tCapResp, sid, lastEmptyReq);
      const lk = lookupCaptcha(img);
      lastCaptchaHash = lk.hash; lastCaptchaRaw = lk.raw; solvedSource = 'map';
      if (!lk.solved) {
        const fb = await fallbackSolve(lk.raw);
        if (!fb) { await sleep(30 + jitter(20)); continue; }   // unknown image burnt; fetch a fresh one
        lk.solved = fb; solvedSource = 'fallback';
      }
      metrics.captchaHit++;
      solved = lk.solved;
    }

    if (isRaceDone()) return done({ kind: 'race-lost' });
    while (totalInFlight(ctx) >= MAX_INFLIGHT_SUBMITS) await sleep(2);
    if (SUBMIT_MIN_GAP_MS > 0) {
      const wait = ctx.lastSubmitAt + SUBMIT_MIN_GAP_MS - Date.now();
      if (wait > 0) await sleep(wait + jitter(3));
    }
    ctx.lastSubmitAt = Date.now();

    // ---- submit immediately ----------------------------------------------------
    attempts++;
    metrics.submits++;
    const tSubReq = Date.now();
    let r;
    try { r = await submitBid(auth, payload, solved); }
    catch (e) {
      log.warn(`[${sid}] submit network error: ${e.message} — retrying with fresh captcha`);
      await sleep(100 + jitter(50));
      if (attempts >= FIRE_MAX_ATTEMPTS) return done({ kind: 'max-attempts' });
      continue;
    }
    const tSubResp = Date.now();
    const c = classify(r);
    fireLog.write([new Date().toISOString(), istHHMM(winKey), sid, attempts, boundarySapLocal, tCapReq || '', tCapResp || '', tCapReq ? tCapResp - tCapReq : '', solved === '__NO_CAPTCHA_REQUIRED__' ? 'nocaptcha' : 'hit', tSubReq, tSubResp, tSubResp - tSubReq, tSubResp - boundarySapLocal, c.kind]);
    if (attempts === 1 && ctx.firstSubmitWin !== winKey) {
      ctx.firstSubmitWin = winKey;
      log.info(`⚡ FIRST SUBMIT of window landed at boundary+${tSubResp - boundarySapLocal}ms (captcha ${tCapReq ? tCapResp - tCapReq : 0}ms + submit ${tSubResp - tSubReq}ms, SAP clock offset ${clock.offsetMs}ms)`);
    }

    const rankStr = r.rankHints.length ? ' | ' + r.rankHints.map((h) => `${h.sapOrderId} rank=${h.rank || '?'} L1=${h.l1Amt || '?'}`).join('; ') : '';

    switch (c.kind) {
      case 'ok': {
        if (race) race.done = true;
        metrics.submitsOk++;
        if (solvedSource === 'fallback') learnCaptcha(lastCaptchaHash, solved);
        log.info(`[${sid}] ✓ ACCEPTED (${item.kind}, ${item.bids.length}) attempt ${attempts} in ${r.submitMs}ms: ${c.silent ? `HTTP ${r.statusCode} silent save` : r.text}${rankStr}`);
        for (const b of item.bids) {
          ctx.submitted.set(String(b.order.SapOrderId), Date.now());
          const h = r.rankHints.find((x) => x.sapOrderId === String(b.order.SapOrderId));
          writeBid(sid, b, r.submitMs, c.silent ? 'ACCEPTED_EMPTY_201' : 'ACCEPTED', h ? `rank=${h.rank || '?'} L1=${h.l1Amt || '?'} | ${r.text || 'OK'}` : (r.text || 'OK'));
        }
        schedulePostSave(ctx, auth, item);
        return done({ kind: 'ok' });
      }
      case 'tied': {
        if (race) race.done = true;
        metrics.submitsOk++;
        if (solvedSource === 'fallback') learnCaptcha(lastCaptchaHash, solved);
        log.info(`[${sid}] ✓ SAVED-TIED (${item.kind}) in ${r.submitMs}ms — other vendor landed same amount first. ${r.evText.trim()}`);
        for (const b of item.bids) { ctx.submitted.set(String(b.order.SapOrderId), Date.now()); writeBid(sid, b, r.submitMs, 'SAVED_TIED', r.evText.trim()); }
        schedulePostSave(ctx, auth, item);
        return done({ kind: 'tied' });
      }
      case 'wrong-captcha': {
        metrics.submitsWrongCaptcha++;
        if (solvedSource === 'map') dropCaptchaAnswer(lastCaptchaHash, solved, lastCaptchaRaw);
        log.warn(`[${sid}] ↻ Wrong captcha (attempt ${attempts}, answer "${solved}" from ${solvedSource}) — fresh pair`);
        break;
      }
      case 'ghost': {
        metrics.submitsGhost++;
        const n = (ctx.ghostRetries.get(String(item.bids[0].order.SapOrderId)) || 0) + 1;
        for (const b of item.bids) { ctx.ghostRetries.set(String(b.order.SapOrderId), n); writeBid(sid, b, r.submitMs, 'REJECTED_GHOST', `ghost markers, attempt ${n}/3`); }
        log.warn(`[${sid}] ✗ GHOST-SAVED (attempt ${n}/3) — SAP said saved but no commit markers [${c.ids.join(', ')}]. Re-minting CSRF and retrying.`);
        if (n >= 3) { for (const b of item.bids) ctx.submitted.set(String(b.order.SapOrderId), Date.now()); return done({ kind: 'ghost-max' }); }
        await auth.refreshToken().catch(() => {});
        await sleep(200 + jitter(100));
        break;
      }
      case 'time-ended': {
        metrics.submitsTimeEnded++;
        const retryAt = Date.now() + TIME_ENDED_COOLDOWN_MS;
        for (const b of item.bids) { ctx.cooldown.set(String(b.order.SapOrderId), retryAt); writeBid(sid, b, r.submitMs, 'TIME_ENDED', r.text); }
        log.warn(`[${sid}] ⏰ window closed — cooldown ${TIME_ENDED_COOLDOWN_MS / 1000}s`);
        return done({ kind: 'time-ended' });
      }
      case 'floor': {
        metrics.submitsRejected++;
        for (const b of item.bids) { ctx.submitted.set(String(b.order.SapOrderId), Date.now()); writeBid(sid, b, r.submitMs, 'RATE_TOO_LOW', `floor=${c.floor}`); log.error(`[${sid}] ✗ RATE TOO LOW ${b.order.SapOrderId} csv=${b.amount} SAP floor ≥ ${c.floor}`); }
        return done({ kind: 'floor' });
      }
      case 'reduce': {
        metrics.submitsRejected++;
        const key = item.bids.map((b) => b.order.SapOrderId).join('|');
        const n = (ctx.adjustAttempts.get(key) || 0) + 1;
        if (!AUTO_ADJUST || n > MAX_ADJUST_RETRIES) {
          for (const b of item.bids) { ctx.submitted.set(String(b.order.SapOrderId), Date.now()); writeBid(sid, b, r.submitMs, 'RATE_HIGH', `reduce_by=${c.reduce}`); log.error(`[${sid}] ✗ RATE HIGH ${b.order.SapOrderId} csv=${b.amount} SAP wants ≤ ${(b.amount - c.reduce).toFixed(2)}`); }
          return done({ kind: 'reduce' });
        }
        ctx.adjustAttempts.set(key, n);
        const step = c.reduce + (n - 1);
        for (const b of item.bids) b.amount = +(b.amount - step).toFixed(2);
        payload = buildSavePayload(auth, item.bids);
        log.warn(`[${sid}] ↓ Auto-adjust ${n}/${MAX_ADJUST_RETRIES} — reducing by Rs ${step}`);
        break;
      }
      case 'info': {
        log.warn(`[${sid}] ↻ Info-level: ${r.text} — retry next scan`);
        for (const b of item.bids) writeBid(sid, b, r.submitMs, 'INFO_RETRY', r.text);
        return done({ kind: 'info' });
      }
      case 'waf': { markWaf(auth, 'EBiddingSaveSet'); return done({ kind: 'waf' }); }
      case 'auth': {
        log.error(`[${sid}] ✗ HTTP ${r.statusCode} on submit — session/CSRF rejected. Not marking order; another session or next scan retries.`);
        return done({ kind: 'auth' });
      }
      case 'http-error': {
        log.warn(`[${sid}] ↻ SAP HTTP ${r.statusCode} on submit (attempt ${attempts}) — retrying with fresh captcha`);
        await sleep(150 + jitter(100));
        break;
      }
      case 'rejected': {
        metrics.submitsRejected++;
        log.error(`[${sid}] ✗ Rejected: ${r.text || '(no text)'}`);
        for (const b of item.bids) { ctx.submitted.set(String(b.order.SapOrderId), Date.now()); writeBid(sid, b, r.submitMs, 'REJECTED', r.text); }
        return done({ kind: 'rejected' });
      }
      default: {
        log.warn(`[${sid}] Unknown response info='${r.info}' status=${r.statusCode} — marking done`);
        for (const b of item.bids) { ctx.submitted.set(String(b.order.SapOrderId), Date.now()); writeBid(sid, b, r.submitMs, 'UNKNOWN', `info=${r.info} status=${r.statusCode}`); }
        return done({ kind: 'unknown' });
      }
    }
    if (attempts >= FIRE_MAX_ATTEMPTS) {
      log.error(`[${sid}] ✗ ${FIRE_MAX_ATTEMPTS} attempts exhausted for this item — will retry next scan`);
      return done({ kind: 'max-attempts' });
    }
    await sleep(10 + jitter(15));
  }
}

function totalInFlight(ctx) { return ctx.sessions.reduce((a, s) => a + s.inFlight, 0); }

// Post-boundary only: fetch ONE captcha per session while orders are still
// being fetched, so the first submit needs a single round-trip. Aborts the
// moment a fire loop starts on this session (it would rotate the captcha).
function armCaptcha(ctx, auth, winKey) {
  if (!ARM_CAPTCHA_AT_BOUNDARY || sapState.captchaFlag === '' || auth.arming) return;
  auth.arming = (async () => {
    const start = Date.now();
    let empties = 0;
    let lastEmptyReq = 0;
    const idx = Math.max(0, ctx.sessions.indexOf(auth));
    const hold = firstProbeLocalMs(winKey, idx, ctx.sessions.length) - Date.now();
    if (hold > 0 && hold < 120_000) await sleep(hold);
    while (Date.now() - start < FIRE_MAX_WAIT_MS && !wafActive(auth) && !auth.mutex._busy) {
      const t0 = Date.now();
      const { img, reason } = await fetchCaptchaImage(auth);
      if (img) {
        noteUnlock(winKey, t0, Date.now(), auth.id, lastEmptyReq);
        const lk = lookupCaptcha(img);
        let source = 'map';
        if (!lk.solved) { lk.solved = await fallbackSolve(lk.raw); source = 'fallback'; }
        if (lk.solved) { auth.armed = { solved: lk.solved, hash: lk.hash, raw: lk.raw, source, t0, at: Date.now() }; log.info(`[${auth.id}] 🔫 captcha armed (${Date.now() - t0}ms, after ${empties} empties) — waiting for orders`); return; }
        await sleep(30 + jitter(20));
        continue;
      }
      if (reason !== 'sap-empty') { await sleep(150 + jitter(50)); continue; }
      empties++;
      lastEmptyReq = t0;
      if (empties === 1 || empties % 40 === 0) log.info(`[${auth.id}] ⏳ arming: captcha not unlocked yet (${empties} empties, ${boundaryStatusText()})`);
      await sleep((Date.now() - start > 3000 ? CAPTCHA_EMPTY_SLOW_MS : CAPTCHA_EMPTY_RETRY_MS) + jitter(8));
    }
  })().catch(() => {}).finally(() => { auth.arming = null; });
}

// Boundary: back-to-back order fetches until a matched plan can be fired.
async function boundaryOrdersLoop(ctx) {
  ctx.boundaryLoopActive = true;
  const start = Date.now();
  try {
    while (Date.now() - start < FIRE_MAX_WAIT_MS) {
      const s = pickSession(ctx);
      if (wafActive(s)) { await sleep(500); continue; }
      const t0 = Date.now();
      const { orders } = await fetchLiveOrders(s);
      ctx.cachedOrders = orders; ctx.cachedOrdersAt = Date.now();
      if (orders.length) {
        if (ctx.ordersSeenWin !== currentWindowMs()) { ctx.ordersSeenWin = currentWindowMs(); log.info(`📦 orders visible: ${orders.length} (fetch ${Date.now() - t0}ms) ${boundaryStatusText()}`); }
        if (dispatchOrders(ctx, orders, 'boundary-loop')) return;
        await sleep(POLL_MS);
      } else {
        await sleep(ORDERS_TIGHT_MS + jitter(5));
      }
    }
    log.warn(`boundary orders loop: no matched orders within ${FIRE_MAX_WAIT_MS / 1000}s`);
  } finally { ctx.boundaryLoopActive = false; }
}

// Post-save: verify persistence + optional L1 undercut (fire-and-forget).
function schedulePostSave(ctx, auth, item) {
  const ids = new Set(item.bids.map((b) => String(b.order.SapOrderId)));
  const byId = Object.fromEntries(item.bids.map((b) => [String(b.order.SapOrderId), b]));
  setTimeout(async () => {
    try {
      const { orders } = await fetchLiveOrders(auth);
      const found = []; const missing = []; const undercut = [];
      for (const o of orders || []) {
        const oid = String(o.SapOrderId || '');
        if (!ids.has(oid)) continue;
        const amt = parseFloat(o.BiddingAmount || 0); const rank = parseInt(o.BiddingRank || 0, 10); const l1 = parseFloat(o.L1BidAmount || 0);
        if (amt > 0) found.push(`${oid}=${amt}(rank=${rank || '?'},L1=${l1 || '?'})`); else missing.push(oid);
        if (L1_UNDERCUT && rank > 1 && l1 > 0 && byId[oid]) {
          const n = ctx.undercutAttempts.get(oid) || 0;
          const newAmt = l1 - L1_UNDERCUT_STEP;
          if (n < L1_UNDERCUT_MAX_ATTEMPTS && newAmt > 0 && newAmt < byId[oid].amount) { ctx.undercutAttempts.set(oid, n + 1); undercut.push({ ...byId[oid], amount: newAmt }); }
        }
      }
      if (missing.length && !found.length) log.error(`🚨 POST-SAVE: none of ${ids.size} bids persisted (${missing.join(', ')})`);
      else if (found.length) log.info(`✅ POST-SAVE: persisted ${found.join(', ')}${missing.length ? ` | missing ${missing.join(', ')}` : ''}`);
      if (undercut.length && isActiveWindow()) {
        log.warn(`🎯 L1-UNDERCUT: re-bidding ${undercut.length} order(s) at L1-${L1_UNDERCUT_STEP}`);
        for (let i = 0; i < undercut.length; i += BATCH_SIZE) {
          const bids = undercut.slice(i, i + BATCH_SIZE);
          for (const b of bids) ctx.submitted.delete(String(b.order.SapOrderId));
          dispatchItem(ctx, { kind: 'single', bids });
        }
      }
    } catch (e) { log.warn(`post-save monitor failed: ${e.message}`); }
  }, 1500).unref();
}

// ---- Dispatcher: sessions in parallel, serialized per session -----------------

function pickSession(ctx) {
  const now = Date.now();
  const ok = ctx.sessions.filter((s) => !(s.wafUntil > now) && !(s._deadUntil > now));
  const pool = ok.length ? ok : ctx.sessions;
  return pool.reduce((best, s) => ((s.queued || 0) < (best.queued || 0) ? s : best), pool[0]);
}

function dispatchItem(ctx, item, { race = false, stagger = SESSION_STAGGER_MS } = {}) {
  const ids = item.bids.map((b) => String(b.order.SapOrderId));
  for (const id of ids) ctx.inFlight.add(id);
  const release = () => { for (const id of ids) ctx.inFlight.delete(id); };
  const runOn = (s, delay, token) => {
    s.queued = (s.queued || 0) + 1;
    return s.mutex.run(async () => {
      if (delay) await sleep(delay);
      try { return await fireItem(ctx, s, item, token); }
      catch (e) { log.error(`[${s.id}] fire crashed: ${e.message}`); return { kind: 'crash' }; }
      finally { s.queued--; }
    });
  };
  const live = ctx.sessions.filter((s) => !wafActive(s) && !(s._deadUntil > Date.now()));
  if (race && live.length > 1) {
    const token = { done: false };
    log.info(`🏁 RACE: ${live.length} sessions fire the same item, stagger ${stagger}ms — first save wins`);
    return Promise.all(live.map((s, i) => runOn(s, i * stagger, token))).finally(release);
  }
  return runOn(pickSession(ctx), 0, null).finally(release);
}

// Build plan from orders and fire everything not yet in flight. Idempotent.
function dispatchOrders(ctx, orders, source) {
  if (!orders || !orders.length) return 0;
  const { plan, stats } = buildBatches(orders, ctx);
  if (!plan.length) return 0;
  const win = currentWindowMs();
  log.info(`🚀 [${source}] dispatching ${plan.length} batch(es), ${stats.matched} matched (orders=${stats.total} bl=${stats.blacklisted} no-rule=${stats.noRule} pri=${stats.priority}) ${boundaryStatusText()}`);
  plan.forEach((item, i) => {
    const raceFirst = FIRE_RACE_FIRST && i === 0 && ctx.racedWin !== win;
    if (raceFirst) ctx.racedWin = win;
    dispatchItem(ctx, item, { race: raceFirst });
  });
  return plan.length;
}

// ---- Keep-warm ---------------------------------------------------------------

function startKeepWarm(sessions) {
  let last = 0;
  setInterval(() => {
    const need = isHotWindow() ? 3_000 : 20_000;
    if (Date.now() - last < need) return;
    last = Date.now();
    for (const s of sessions) {
      if (s.mutex._busy || wafActive(s)) continue;
      clockProbe(s).catch(() => {});
    }
  }, 500).unref();
}

// ---- Main --------------------------------------------------------------------

async function main() {
  log.info('🚀 Bikas Bidding v4.1 engine — backend-clock sync, learned unlock lag, embedded captcha map');
  const sessions = discoverSessions().map((sp) => new AuthConfig(sp.id, sp.cookieFile, sp.tokenFile));
  sessionsRef = sessions;
  loadCaptchaMap();
  loadClockState();
  fs.watchFile(CAPTCHA_MAP_FILE, { interval: 5000 }, () => { log.info('🧩 captcha map changed on disk — reloading'); loadCaptchaMap(); });

  log.info(`Config: sessions=${sessions.map((s) => s.id).join(',')} windows=[${WINDOW_MINUTES.join(',')}] IST batch=${BATCH_SIZE} race-first=${FIRE_RACE_FIRST} max-inflight=${MAX_INFLIGHT_SUBMITS} csrf-lead=${CSRF_REMINT_LEAD_MS}ms clock=${CLOCK_SOURCE} unlock-lag=${UNLOCK_LAG_MS < 0 ? `learned(${clock.unlockLagMs}ms)` : UNLOCK_LAG_MS + 'ms'} margin=${UNLOCK_MARGIN_MS}ms freeze=${ORDERS_FREEZE_MS}ms h2=${SAP_HTTP2} sap=${SAP_ORIGIN}`);

  await Promise.all(sessions.map((s) => s.refreshToken().catch((e) => log.warn(`[${s.id}] initial CSRF failed: ${e.message}`))));
  await Promise.all(sessions.map((s) => clockProbe(s)));
  log.info(`Pools warm (${sessions.length} session(s), TCP_NODELAY, keep-alive). rtt≈${clock.rttMs}ms coarse SAP offset≈${clock.coarseOffsetMs}ms`);
  startKeepWarm(sessions);

  const [inputRows, deleteRows] = await Promise.all([parseCSV(INPUT_CSV), parseCSV(DELETE_CSV)]);
  const { rules, blacklist } = buildRuleMaps(inputRows, deleteRows);
  log.info(`Loaded ${rules.size} cities (${inputRows.length} rows), ${blacklist.length} blacklisted, priority=${loadPriorityVbelns().size}`);

  const ctx = {
    sessions, rules, blacklist, priorityVbelns: loadPriorityVbelns(),
    scan: 0, submitted: new Map(), inFlight: new Set(), cooldown: new Map(),
    adjustAttempts: new Map(), undercutAttempts: new Map(), ghostRetries: new Map(),
    cachedOrders: null, cachedOrdersAt: 0, racedWin: 0, firstSubmitWin: 0, lastSubmitAt: 0,
  };

  process.on('SIGINT', () => { log.info('SIGINT — bye'); process.exit(0); });
  process.on('SIGTERM', () => { log.info('SIGTERM — bye'); process.exit(0); });
  if (METRICS_MS > 0) setInterval(metricsDump, METRICS_MS).unref();

  // ---- Orders poller: the cheap unlock signal (never touches captcha) ----------
  let ordersBusy = false;
  setInterval(async () => {
    if (ordersBusy || ctx.boundaryLoopActive) return;
    const until = msUntilNextWindow();
    const hot = until <= ORDERS_POLL_LEAD_MS || isActiveWindow();
    if (!hot) return;
    // Freeze: close to the boundary, if the cached orders already yield a plan, keep SAP idle
    // so nothing but captcha+submit is in flight at the open instant.
    if (until > 0 && until <= ORDERS_FREEZE_MS && ctx.cachedOrders && ctx.cachedOrders.length && buildBatches(ctx.cachedOrders, ctx).plan.length) {
      if (ctx.freezeLoggedWin !== nextBoundaryMs(sapNow())) { ctx.freezeLoggedWin = nextBoundaryMs(sapNow()); log.info(`🧊 orders frozen ${until}ms before boundary — plan ready from cache, no fetch in the critical path`); }
      return;
    }
    const primary = pickSession(ctx);
    if (wafActive(primary)) return;
    ordersBusy = true;
    try {
      const t0 = Date.now();
      const { orders } = await fetchLiveOrders(primary);
      ctx.cachedOrders = orders; ctx.cachedOrdersAt = Date.now();
      const win = currentWindowMs();
      if (orders.length && ctx.ordersSeenWin !== win && isActiveWindow()) {
        ctx.ordersSeenWin = win;
        log.info(`📦 orders visible: ${orders.length} (fetch ${Date.now() - t0}ms) ${boundaryStatusText()}`);
      }
      if (isActiveWindow()) dispatchOrders(ctx, orders, 'orders-poller');
    } catch (_) { /* silent */ } finally { ordersBusy = false; }
  }, ORDERS_POLL_HOT_MS).unref();

  // ---- Boundary scheduler: clock sync → CSRF re-mint → fire on SAP clock -------
  let scheduledWin = 0;
  setInterval(() => {
    const next = nextBoundaryMs(sapNow());
    const until = next - sapNow();
    if (scheduledWin === next || until > CLOCK_SYNC_LEAD_MS + 2000) return;
    scheduledWin = next;
    log.info(`⏱  Window ${istHHMM(next)} in ${(until / 1000).toFixed(1)}s — scheduling: clock-sync now, CSRF re-mint @T-${CSRF_REMINT_LEAD_MS}ms, fire @T-${fireLeadMs()}ms (SAP clock)`);

    (async () => {
      await syncSapClock(sessions[0]);
      const fireAtLocal = next - clock.offsetMs - fireLeadMs();          // dispatch at boundary; fireItem holds the probe itself
      const csrfAt = firstProbeLocalMs(next) - CSRF_REMINT_LEAD_MS;      // token minted just before the first probe
      const now = Date.now();
      log.info(`   ↳ plan: dispatch @${new Date(fireAtLocal).toISOString().slice(11, 23)} local, CSRF @${new Date(csrfAt).toISOString().slice(11, 23)}, first captcha probe arrives boundary+${clock.unlockLagMs + UNLOCK_MARGIN_MS}ms (sessions phased ${sessions.length > 1 ? Math.round(clock.rttMs / sessions.length) : 0}ms apart)`);
      setTimeout(() => {
        log.info(`🔑 CSRF re-mint on ${sessions.length} session(s) @ T${(Date.now() + clock.offsetMs - next) >= 0 ? '+' : ''}${Date.now() + clock.offsetMs - next}ms`);
        for (const s of sessions) s.refreshToken().catch((e) => log.warn(`[${s.id}] CSRF re-mint failed: ${e.message}`));
      }, Math.max(0, csrfAt - now));
      setTimeout(() => {
        // Reset per-window state
        const RECENT = 30_000;
        for (const [k, ts] of ctx.submitted) if (ts < Date.now() - RECENT) ctx.submitted.delete(k);
        for (const [k, ts] of ctx.cooldown) if (ts < Date.now() - RECENT) ctx.cooldown.delete(k);
        ctx.undercutAttempts.clear(); ctx.ghostRetries.clear(); ctx.adjustAttempts.clear();
        ctx.priorityVbelns = loadPriorityVbelns();
        log.info(`🕒 BOUNDARY ${istHHMM(next)} (SAP clock) — FIRE. cached orders=${ctx.cachedOrders ? ctx.cachedOrders.length : 0}`);
        // Orders already visible → fire now (captcha loop waits for unlock itself).
        // Else: arm one captcha per session AND fetch orders back-to-back in parallel.
        if (ctx.cachedOrders && ctx.cachedOrders.length && dispatchOrders(ctx, ctx.cachedOrders, 'boundary')) return;
        for (const s of sessions) armCaptcha(ctx, s, next);
        boundaryOrdersLoop(ctx).catch((e) => log.warn(`boundary loop failed: ${e.message}`));
      }, Math.max(0, fireAtLocal - now));
    })().catch((e) => log.error(`boundary scheduler failed: ${e.message}`));
  }, 500).unref();

  // ---- Main loop: slow safety net for late-appearing orders ---------------------
  let lastBeat = 0;
  while (true) {
    ctx.scan++;
    try {
      if (isActiveWindow() && !wafActive()) {
        const fresh = ctx.cachedOrders && Date.now() - ctx.cachedOrdersAt < 1000;
        const orders = fresh ? ctx.cachedOrders : (await fetchLiveOrders(pickSession(ctx))).orders;
        if (!fresh) { ctx.cachedOrders = orders; ctx.cachedOrdersAt = Date.now(); }
        dispatchOrders(ctx, orders, 'tick');
      } else if (Date.now() - lastBeat > 30_000) {
        lastBeat = Date.now();
        log.info(`💤 idle — next window ${istHHMM(nextBoundaryMs(sapNow()))} in ${Math.round(msUntilNextWindow() / 1000)}s | submitted this run=${metrics.submitsOk} | sap-offset=${clock.offsetMs}ms rtt=${clock.rttMs}ms`);
      }
    } catch (e) {
      if (!NETWORK_ERR_RE.test(e.message || '')) log.error({ err: e.message }, 'tick failed');
    }
    await sleep(isActiveWindow() ? POLL_MS : 2000);
  }
}

main().catch((e) => { log.error({ err: e.message, stack: e.stack }, 'fatal'); process.exit(1); });
