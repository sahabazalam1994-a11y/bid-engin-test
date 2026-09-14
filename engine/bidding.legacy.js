'use strict';

/**
 * bidding.js — Bikas Bidding v2 captcha solver server (clean rewrite).
 *
 * Endpoints
 *   POST /                 body: text/plain JSON  { base64Image }  → { solved }
 *   POST /solve-captcha    (alias of /, backward compatible with old bid-engine)
 *   POST /captcha          body: application/json { base64Image }  → { solved }
 *   POST /upload-base64-image (alias of /captcha)
 *   GET  /health           → { ok:true, cache:<size>, hits, misses, uptime, ... }
 *
 * Behaviour
 *   1. sha256(base64) → in-memory Map cache lookup (<5 ms hit).
 *   2. On miss → call external TrueCaptcha API (undici Pool, keep-alive).
 *   3. Persist new (hash → solved) into `data.json` (auto-saved every 60s).
 *   4. On errors → daily rotating log with base64 + response dump.
 *
 * Keep-alive HTTP server: `keepAliveTimeout=30000` for connection reuse
 * from the local bid-engine.
 */

require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express   = require('express');
const fs        = require('fs');
const path      = require('path');
const crypto    = require('crypto');
const { Pool }  = require('undici');
const { build } = require('./logger');

const log = build('solver');

// ---- Config ----------------------------------------------------------------

const PORT              = parseInt(process.env.CAPTCHA_PORT || '3000', 10);
const CREDS_FILE        = path.join(__dirname, 'creds.json');
const CREDS_FILE_ALT    = path.join(__dirname, 'credentials.json'); // backward-compat
const CACHE_FILE        = path.join(__dirname, 'data.json');
const CACHE_TTL_HOURS   = parseInt(process.env.CAPTCHA_TTL_HOURS || '24', 10);
const CACHE_SAVE_MS     = 60_000;   // flush cache to disk every 60s

const TRUECAPTCHA_ORIGIN = 'https://api.apitruecaptcha.org';
const TRUECAPTCHA_PATH   = '/one/gettext';

// ---- Credentials -----------------------------------------------------------

function loadCreds() {
  const file = fs.existsSync(CREDS_FILE) ? CREDS_FILE
             : fs.existsSync(CREDS_FILE_ALT) ? CREDS_FILE_ALT
             : null;
  if (!file) {
    log.error(`No creds.json / credentials.json found in ${__dirname}. Create one with {"userid":"...","apikey":"..."}`);
    process.exit(1);
  }
  const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!parsed.userid || !parsed.apikey) {
    log.error({ file }, 'creds file must contain "userid" and "apikey"');
    process.exit(1);
  }
  return parsed;
}

const CREDS = loadCreds();

// ---- Undici pool for TrueCaptcha -------------------------------------------

const captchaPool = new Pool(TRUECAPTCHA_ORIGIN, {
  connections: 8,
  pipelining: 1,
  keepAliveTimeout: 30_000,
  headersTimeout: 15_000,
  bodyTimeout: 20_000,
});

// ---- In-memory cache + persistence -----------------------------------------

let entries = [];            // [{hash, file, result, savedAt}, ...]  (disk shape)
const hashMap = new Map();   // hash → result
let dirty = false;           // flush on next tick if true
const stats = { hits: 0, misses: 0, apiErrors: 0, saves: 0, startedAt: Date.now() };

function loadCache() {
  try {
    if (!fs.existsSync(CACHE_FILE)) {
      entries = [];
      return;
    }
    const raw = JSON.parse(fs.readFileSync(CACHE_FILE, 'utf8'));
    if (!Array.isArray(raw)) throw new Error('data.json must be a JSON array');

    // TTL prune (savedAt in ms; missing = keep forever for backward-compat)
    const ttlMs = CACHE_TTL_HOURS * 3_600_000;
    const now = Date.now();
    entries = raw.filter((e) => {
      if (!e || !e.hash || !e.result) return false;
      if (!e.savedAt) return true; // legacy entries have no timestamp — keep
      return now - e.savedAt < ttlMs || ttlMs <= 0;
    });
    for (const e of entries) hashMap.set(e.hash, e.result);
    log.info(`Cache loaded: ${entries.length} entries (TTL=${CACHE_TTL_HOURS}h)`);
  } catch (e) {
    log.warn(`Cache load failed: ${e.message} — starting empty`);
    entries = [];
    hashMap.clear();
  }
}

function saveCache() {
  if (!dirty) return;
  try {
    fs.writeFileSync(CACHE_FILE, JSON.stringify(entries, null, 2), 'utf8');
    stats.saves++;
    dirty = false;
    log.debug(`Cache flushed to disk: ${entries.length} entries`);
  } catch (e) {
    log.error(`Cache save failed: ${e.message}`);
  }
}

function cacheHit(hash) {
  return hashMap.get(hash) || null;
}

function cachePut(hash, result) {
  if (hashMap.has(hash)) return;
  const entry = { hash, file: `image-${Date.now()}.png`, result, savedAt: Date.now() };
  entries.push(entry);
  hashMap.set(hash, result);
  dirty = true;
}

// ---- Utilities -------------------------------------------------------------

function stripDataUri(b64) {
  return typeof b64 === 'string' && b64.includes(',') ? b64.split(',')[1] : b64;
}

function sha256(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}

function parseBody(req) {
  // Body arrives as raw string (bodyParser.text) OR as parsed JSON.
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return req.body || {};
}

// ---- Local OCR (tesseract.js) — primary solver, offline & free ------------
//
// SAP captchas are 4-6 char alphanumeric single-line images. tesseract.js
// runs a WASM-based OCR entirely in-process (no network, no cost). On first
// use it downloads the ~15MB `eng.traineddata` language model to a local
// cache dir (`./tessdata`) — subsequent runs load instantly.
//
// Strategy: cache → local OCR → TrueCaptcha fallback (only if OCR result is
// empty OR confidence below threshold OR doesn't look like a valid captcha).
// This saves TrueCaptcha credits AND is often faster (~80-200ms vs 300-500ms
// round-trip). If tesseract.js fails to init (network blocked, disk full),
// the server logs the error and silently falls back to TrueCaptcha-only.

const LOCAL_OCR_ENABLED        = String(process.env.LOCAL_OCR_ENABLED ?? 'true') !== 'false';
const LOCAL_OCR_MIN_CONFIDENCE = parseInt(process.env.LOCAL_OCR_MIN_CONFIDENCE || '60', 10);
const LOCAL_OCR_MIN_LEN        = parseInt(process.env.LOCAL_OCR_MIN_LEN || '4', 10);
const LOCAL_OCR_MAX_LEN        = parseInt(process.env.LOCAL_OCR_MAX_LEN || '8', 10);
const LOCAL_OCR_CHARS          = process.env.LOCAL_OCR_CHARS
  || 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

let ocrWorker = null;
let ocrInitPromise = null;
const ocrStats = { attempts: 0, ok: 0, lowConf: 0, badFormat: 0, errors: 0, totalMs: 0 };

async function initLocalOcr() {
  if (!LOCAL_OCR_ENABLED) return null;
  if (ocrWorker) return ocrWorker;
  if (ocrInitPromise) return ocrInitPromise;
  ocrInitPromise = (async () => {
    try {
      const { createWorker } = require('tesseract.js');
      const w = await createWorker('eng', 1, {
        cachePath: path.join(__dirname, 'tessdata'),
        logger: () => {}, // silence progress noise
      });
      // Single-line mode + restrict alphabet → dramatically improves accuracy
      // on the 4-6 char SAP captchas.
      await w.setParameters({
        tessedit_pageseg_mode: '7', // single text line
        tessedit_char_whitelist: LOCAL_OCR_CHARS,
      });
      ocrWorker = w;
      log.info(`Local OCR ready (tesseract.js) — whitelist=${LOCAL_OCR_CHARS.length} chars, min-conf=${LOCAL_OCR_MIN_CONFIDENCE}%, TrueCaptcha=fallback`);
      return w;
    } catch (e) {
      log.warn(`Local OCR init failed: ${e.message} — falling back to TrueCaptcha-only`);
      return null;
    }
  })();
  return ocrInitPromise;
}

function looksLikeCaptcha(text) {
  if (!text) return false;
  const trimmed = text.replace(/\s+/g, '');
  if (trimmed.length < LOCAL_OCR_MIN_LEN || trimmed.length > LOCAL_OCR_MAX_LEN) return false;
  return /^[A-Za-z0-9]+$/.test(trimmed);
}

async function solveViaLocalOcr(base64Raw) {
  if (!LOCAL_OCR_ENABLED) return { solved: '', reason: 'disabled' };
  const worker = await initLocalOcr();
  if (!worker) return { solved: '', reason: 'init-failed' };
  const t0 = Date.now();
  ocrStats.attempts++;
  try {
    const buf = Buffer.from(base64Raw, 'base64');
    const { data } = await worker.recognize(buf);
    const raw = (data && data.text ? data.text : '').replace(/\s+/g, '');
    const conf = data && typeof data.confidence === 'number' ? data.confidence : 0;
    const ms = Date.now() - t0;
    ocrStats.totalMs += ms;
    if (!looksLikeCaptcha(raw)) {
      ocrStats.badFormat++;
      return { solved: '', reason: 'bad-format', raw, conf, ms };
    }
    if (conf < LOCAL_OCR_MIN_CONFIDENCE) {
      ocrStats.lowConf++;
      return { solved: '', reason: 'low-conf', raw, conf, ms };
    }
    ocrStats.ok++;
    return { solved: raw, reason: 'ok', conf, ms };
  } catch (e) {
    ocrStats.errors++;
    return { solved: '', reason: 'error', err: e.message, ms: Date.now() - t0 };
  }
}


// ---- External captcha (TrueCaptcha, fallback) -----------------------------

async function solveViaApi(base64Raw) {
  const t0 = Date.now();
  const payload = { userid: CREDS.userid, apikey: CREDS.apikey, data: base64Raw };
  try {
    const { statusCode, body } = await captchaPool.request({
      path: TRUECAPTCHA_PATH,
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(payload),
    });
    const text = await body.text();
    let json;
    try { json = JSON.parse(text); }
    catch {
      stats.apiErrors++;
      log.error({ statusCode, textPreview: text.slice(0, 200) }, 'TrueCaptcha non-JSON response');
      return '';
    }
    const solved = json.result || '';
    log.debug({ statusCode, ms: Date.now() - t0, solved }, 'TrueCaptcha response');
    return solved;
  } catch (e) {
    stats.apiErrors++;
    // Rotating error log: dump base64 preview so we can replay offline.
    log.error({
      err: e.message,
      base64Preview: base64Raw.slice(0, 80),
      base64Len: base64Raw.length,
    }, 'TrueCaptcha request failed');
    return '';
  }
}

// ---- Main solve dispatcher -------------------------------------------------
//
// Priority: cache → local OCR (tesseract.js) → TrueCaptcha API
// Local OCR result is accepted only if it meets format + confidence gates
// (see LOCAL_OCR_MIN_CONFIDENCE / LOCAL_OCR_MIN_LEN etc.). Otherwise falls
// through to TrueCaptcha so no bid is ever attempted with a bad solve.

async function solve(base64Input) {
  if (!base64Input) return { solved: '', source: 'empty' };
  const raw = stripDataUri(base64Input);
  const hash = sha256(raw);

  // 1) Cache-first (sub-ms)
  const hit = cacheHit(hash);
  if (hit) {
    stats.hits++;
    return { solved: hit, source: 'cache', hash };
  }

  stats.misses++;

  // 2) Local OCR (tesseract.js) — offline, free, ~80-200ms
  const ocr = await solveViaLocalOcr(raw);
  if (ocr.solved) {
    cachePut(hash, ocr.solved);
    return { solved: ocr.solved, source: 'local-ocr', hash, conf: ocr.conf, ms: ocr.ms };
  }

  // 3) TrueCaptcha fallback (paid, ~300-500ms)
  const solved = await solveViaApi(raw);
  if (solved && solved !== 'Redo') cachePut(hash, solved);
  return { solved, source: 'api', hash, ocrReason: ocr.reason };
}

// ---- Express app -----------------------------------------------------------

const app = express();
app.use(express.text({ type: '*/*', limit: '50mb' }));   // accept text/plain OR json

async function handleSolve(req, res) {
  const t0 = Date.now();
  try {
    const { base64Image } = parseBody(req);
    if (!base64Image) return res.status(400).json({ error: 'Base64 image data is required' });
    const { solved, source, hash, conf } = await solve(base64Image);
    const ms = Date.now() - t0;
    if (source === 'cache')          log.info({ ms, hash: hash.slice(0, 10) }, `HIT ${solved}`);
    else if (source === 'local-ocr') log.info({ ms, hash: hash?.slice(0, 10), conf: `${conf}%` }, `OCR ${solved}`);
    else                             log.info({ ms, hash: hash?.slice(0, 10) }, `API ${solved || '(empty)'}`);
    res.json({ solved });
  } catch (e) {
    log.error({ err: e.message, stack: e.stack }, 'solve handler failed');
    res.status(500).json({ solved: 'Redo', error: e.message });
  }
}

app.post('/',               handleSolve);
app.post('/solve-captcha',  handleSolve);   // legacy alias used by old bid-engine
app.post('/captcha',        handleSolve);
app.post('/upload-base64-image', handleSolve);

// ---- Cache invalidation ---------------------------------------------------
//
// When bid-engine gets "Wrong Captcha" from SAP, it POSTs the offending
// image here so we DROP its cached (wrong) solve — next time the same image
// appears, we force a fresh TrueCaptcha OCR. This eliminates the case where
// a wrong OCR result (like "=bg=" or "herrd") sits in the cache and keeps
// coming back as a HIT, guaranteeing repeated wrong-captcha rejections.
async function handleInvalidate(req, res) {
  try {
    const { base64Image, solved: reportedSolved } = parseBody(req);
    if (!base64Image) return res.status(400).json({ error: 'base64Image required' });
    const raw = stripDataUri(base64Image);
    const hash = sha256(raw);
    const hadIt = hashMap.has(hash);
    if (hadIt) {
      const wasSolved = hashMap.get(hash);
      hashMap.delete(hash);
      // Also remove from entries[] so it doesn't come back after next disk load
      entries = entries.filter((e) => e.hash !== hash);
      dirty = true;
      log.warn(
        { hash: hash.slice(0, 10), wasSolved, reportedSolved },
        `INVALIDATED wrong cache entry (SAP rejected "${wasSolved}")`,
      );
    }
    res.json({ ok: true, invalidated: hadIt, cacheSize: hashMap.size });
  } catch (e) {
    log.error({ err: e.message }, 'invalidate handler failed');
    res.status(500).json({ error: e.message });
  }
}

app.post('/invalidate', handleInvalidate);

app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    uptimeSec: Math.round((Date.now() - stats.startedAt) / 1000),
    cache: hashMap.size,
    hits: stats.hits,
    misses: stats.misses,
    apiErrors: stats.apiErrors,
    saves: stats.saves,
    hitRatePct: stats.hits + stats.misses > 0
      ? +(100 * stats.hits / (stats.hits + stats.misses)).toFixed(1) : 0,
    localOcr: {
      enabled: LOCAL_OCR_ENABLED,
      ready: !!ocrWorker,
      attempts: ocrStats.attempts,
      ok: ocrStats.ok,
      lowConf: ocrStats.lowConf,
      badFormat: ocrStats.badFormat,
      errors: ocrStats.errors,
      avgMs: ocrStats.attempts ? Math.round(ocrStats.totalMs / ocrStats.attempts) : 0,
    },
  });
});

// ---- Boot ------------------------------------------------------------------

loadCache();
// Warm up local OCR in the background so the first bid-window doesn't pay
// the model-load cost (~2s). If init fails we silently fall back to API-only.
if (LOCAL_OCR_ENABLED) initLocalOcr().catch(() => {});
setInterval(saveCache, CACHE_SAVE_MS).unref();
setInterval(() => {
  const total = stats.hits + stats.misses;
  if (!total) return;
  const ocrOk    = ocrStats.ok;
  const ocrTotal = ocrStats.attempts;
  const ocrAvg   = ocrTotal ? Math.round(ocrStats.totalMs / ocrTotal) : 0;
  log.info(
    `[metrics] cache=${hashMap.size} hits=${stats.hits} misses=${stats.misses} ` +
    `api-err=${stats.apiErrors} hit-rate=${(100 * stats.hits / total).toFixed(1)}% ` +
    `| local-ocr: ${ocrOk}/${ocrTotal} solved (low-conf=${ocrStats.lowConf} bad-format=${ocrStats.badFormat} err=${ocrStats.errors}, avg=${ocrAvg}ms)`
  );
}, parseInt(process.env.METRICS_INTERVAL_MS || '30000', 10)).unref();

const server = app.listen(PORT, '127.0.0.1', () => {
  log.info(`Captcha solver ready → http://127.0.0.1:${PORT} (loopback-only bind; endpoints: POST /, /solve-captcha, /captcha ; GET /health)`);
});
server.keepAliveTimeout = 30_000;
server.headersTimeout   = 35_000;

// Graceful shutdown → flush cache + terminate OCR worker
function shutdown(sig) {
  log.info(`${sig} — flushing cache…`);
  dirty = true;
  saveCache();
  if (ocrWorker) { try { ocrWorker.terminate(); } catch { /* ignore */ } }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGINT',  () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('uncaughtException', (e) => log.error({ err: e.message, stack: e.stack }, 'uncaughtException'));
process.on('unhandledRejection', (e) => log.error({ err: (e && e.message) || String(e) }, 'unhandledRejection'));
