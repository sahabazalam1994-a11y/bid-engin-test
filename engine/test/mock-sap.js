'use strict';

/**
 * Mock SAP OData server for end-to-end testing of bid-engine v4.
 *  - Simulates clock offset (Date header) and window opening on ITS clock
 *  - Captcha rotates on every fetch; only the latest is valid; empty before open
 *  - Save validates CSRF + captcha, ranks by arrival order
 *  - Writes test/captcha-map.test.json with hashes of its synthetic images
 *  - GET /mock/stats → everything the e2e test needs
 */

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = parseInt(process.env.MOCK_PORT || '9443', 10);
const CLOCK_OFFSET_MS = parseInt(process.env.MOCK_CLOCK_OFFSET_MS || '1500', 10);
const LATENCY_MS = parseInt(process.env.MOCK_LATENCY_MS || '20', 10);
const OPEN_MS = parseInt(process.env.MOCK_OPEN_MS || '30000', 10);
const CAPTCHA_UNLOCK_DELAY_MS = parseInt(process.env.MOCK_CAPTCHA_UNLOCK_DELAY_MS || '0', 10);
const UNKNOWN_RATE = parseFloat(process.env.MOCK_UNKNOWN_RATE || '0');
const WAF_BURST = parseInt(process.env.MOCK_WAF_BURST || '0', 10); // >N submits within 300ms → 406
const WAF_DATE_SKEW_MS = parseInt(process.env.MOCK_WAF_DATE_SKEW_MS || '0', 10); // Date header (WAF clock) vs backend clock
const WINDOW_MINUTES = (process.env.WINDOW_MINUTES || '15,45').split(',').map(Number);
const PFX = '/sap/opu/odata/sap/ZVC_TRANSPORTER_SRV';
const IST = 5.5 * 3_600_000;

const sapNow = () => Date.now() + CLOCK_OFFSET_MS;
function lastBoundary(ms) {
  const ist = ms + IST; const hs = ist - (ist % 3_600_000);
  for (let h = 0; h >= -1; h--) for (let i = WINDOW_MINUTES.length - 1; i >= 0; i--) { const b = hs + h * 3_600_000 + WINDOW_MINUTES[i] * 60_000; if (b <= ist) return b - IST; }
  return hs - IST;
}
const windowOpen = () => { const s = sapNow(); const b = lastBoundary(s); return s - b < OPEN_MS; };
const captchaUnlocked = () => { const s = sapNow(); const b = lastBoundary(s); return s - b >= CAPTCHA_UNLOCK_DELAY_MS && s - b < OPEN_MS; };

// Synthetic captcha set
const images = [];
const answers = new Map();
for (let i = 0; i < 40; i++) {
  const ans = crypto.randomBytes(3).toString('hex').slice(0, 5);
  const b64 = Buffer.from(`PNG-MOCK-${i}-${crypto.randomBytes(24).toString('hex')}`).toString('base64');
  images.push(b64); answers.set(b64, ans);
}
const unknownImages = Array.from({ length: 5 }, (_, i) => Buffer.from(`PNG-UNKNOWN-${i}-${crypto.randomBytes(24).toString('hex')}`).toString('base64'));
const mapOut = images.map((b64) => ({ hash: crypto.createHash('sha256').update(b64).digest('hex'), file: 'mock.png', result: answers.get(b64) }));
fs.writeFileSync(path.join(__dirname, 'captcha-map.test.json'), JSON.stringify(mapOut, null, 1));

const orders = [
  { SapOrderId: '9000000001', Vbeln: '1150000001', Destination: 'MUMBAI', SPI: '1164-BAG', ClubId: '', Freight: '1000.000', KunagName1: 'ACME', ShipFromWerks: '6924', BiddingRank: '0', BiddingAmount: '0.000', L1BidAmount: '0.000' },
  { SapOrderId: '9000000002', Vbeln: '1150000002', Destination: 'PUNE - STO', SPI: '', ClubId: '', Freight: '900.000', KunagName1: 'BETA', ShipFromWerks: '6924', BiddingRank: '0', BiddingAmount: '0.000', L1BidAmount: '0.000' },
  { SapOrderId: '9000000003', Vbeln: '1150000003', Destination: 'NAGPUR', SPI: '', ClubId: '', Freight: '900.000', KunagName1: 'BLOCKED CO', ShipFromWerks: '6924', BiddingRank: '0', BiddingAmount: '0.000', L1BidAmount: '0.000' },
];

const LATE_ORDER_AT_MS = parseInt(process.env.MOCK_LATE_ORDER_AT_MS || '0', 10); // publish a 4th matching order this long after open
const lateOrder = { SapOrderId: '9000000004', Vbeln: '1150000004', Destination: 'DELHI', SPI: '', ClubId: '', Freight: '1200.000', KunagName1: 'LATE CO', ShipFromWerks: '6924', BiddingRank: '0', BiddingAmount: '0.000', L1BidAmount: '0.000' };
function visibleOrders() {
  if (!LATE_ORDER_AT_MS) return orders;
  const win = lastBoundary(sapNow());
  return sapNow() >= win + LATE_ORDER_AT_MS ? [...orders, lateOrder] : orders;
}

const sessions = new Map(); // cookie → { token, activeCaptcha, activeAnswer }
const stats = { boundaries: [], captchaFetches: 0, captchaEmpty: 0, captchaIssued: 0, saves: [], wrongCaptcha: 0, csrfFail: 0, waf406: 0, sessionSetCalls: 0, orderListCalls: 0 };
const recentSubmits = [];
let lastWinKey = 0;

function sess(req) {
  const c = req.headers.cookie || 'anon';
  if (!sessions.has(c)) sessions.set(c, { token: crypto.randomBytes(12).toString('base64'), activeCaptcha: null, activeAnswer: null, id: `c${sessions.size + 1}` });
  return sessions.get(c);
}
function send(res, code, body, extra = {}) {
  const headers = { 'content-type': 'application/json', date: new Date(sapNow() + WAF_DATE_SKEW_MS).toUTCString(), connection: 'keep-alive', ...extra };
  setTimeout(() => { res.writeHead(code, headers); res.end(typeof body === 'string' ? body : JSON.stringify(body)); }, LATENCY_MS);
}
// SAP Gateway error XML with backend timestamp (UTC, µs) — taken at processing time
function gatewayNotFound(res) {
  const d = new Date(sapNow() + LATENCY_MS / 2);
  const p = (n, w = 2) => String(n).padStart(w, '0');
  const ts = `${d.getUTCFullYear()}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}.${p(d.getUTCMilliseconds(), 3)}0000`;
  stats.clockProbes = (stats.clockProbes || 0) + 1;
  send(res, 404, `<?xml version="1.0" encoding="utf-8"?><error xmlns="http://schemas.microsoft.com/ado/2007/08/dataservices/metadata"><code>005056A509B11ED199D8826D151F80FE</code><message xml:lang="en">The server has not found any resource matching the Data Services Request URI</message><innererror><transactionid>A26ED41FECD80230E006A8114348757E</transactionid><timestamp>${ts}</timestamp></innererror></error>`, { 'content-type': 'application/xml' });
}
function readBody(req) { return new Promise((r) => { let s = ''; req.on('data', (c) => (s += c)); req.on('end', () => r(s)); }); }

const server = http.createServer(async (req, res) => {
  const url = req.url;
  const s = sess(req);
  const win = lastBoundary(sapNow());
  if (win !== lastWinKey) { lastWinKey = win; stats.boundaries.push({ sapBoundary: win, localBoundary: win - CLOCK_OFFSET_MS }); }

  if (url === '/mock/stats') return send(res, 200, { ...stats, clockOffsetMs: CLOCK_OFFSET_MS, wafDateSkewMs: WAF_DATE_SKEW_MS, captchaUnlockDelayMs: CAPTCHA_UNLOCK_DELAY_MS, windowOpen: windowOpen(), sapNow: sapNow(), sessions: sessions.size }, { date: new Date().toUTCString() });
  if (url === '/mock/reset') { stats.saves = []; stats.wrongCaptcha = 0; return send(res, 200, { ok: true }); }

  if (url.startsWith(`${PFX}/SessionSet`)) {
    stats.sessionSetCalls++;
    return send(res, 200, { d: {} }, { 'x-csrf-token': s.token });
  }
  if (url.startsWith(`${PFX}/BidOrderListSet`)) {
    stats.orderListCalls++;
    await readBody(req);
    if (req.headers['x-csrf-token'] !== s.token) { stats.csrfFail++; return send(res, 403, 'CSRF token validation failed', { 'x-csrf-token': 'Required' }); }
    const list = windowOpen() ? visibleOrders().map((o) => {
      const mine = stats.saves.filter((b) => b.sapOrderId === o.SapOrderId && b.ok);
      const first = mine[0];
      return { ...o, BiddingAmount: first ? first.amount : '0.000', BiddingRank: first ? String(first.rank) : '0', L1BidAmount: first ? first.amount : '0.000' };
    }) : [];
    return send(res, 200, { d: { EvCaptchaFlag: 'X', NavBidSchVendors: { results: list }, NavBidPlntConf: { results: [{ BiddingDate: `/Date(${win})/`, SlotNumber: '1' }] } } });
  }
  if (url.startsWith(`${PFX}/EbiddingCaptchaSet`)) {
    stats.captchaFetches++;
    if (!captchaUnlocked()) { stats.captchaEmpty++; s.activeCaptcha = null; return send(res, 200, { d: { ImageString: '' } }); }
    const unknown = Math.random() < UNKNOWN_RATE;
    const img = unknown ? unknownImages[Math.floor(Math.random() * unknownImages.length)] : images[Math.floor(Math.random() * images.length)];
    s.activeCaptcha = img; s.activeAnswer = unknown ? null : answers.get(img);
    stats.captchaIssued++;
    if (stats.lastIssueWin !== win) {
      stats.lastIssueWin = win;
      const unlockLocal = (win - CLOCK_OFFSET_MS) + CAPTCHA_UNLOCK_DELAY_MS;
      (stats.unlockDetect = stats.unlockDetect || []).push({ window: win, detectMs: Date.now() - unlockLocal, session: s.id });
    }
    return send(res, 200, { d: { ImageString: img } });
  }
  if (url.startsWith(`${PFX}/EBiddingSaveSet`)) {
    const raw = await readBody(req);
    const now = Date.now();
    if (WAF_BURST) {
      recentSubmits.push(now);
      while (recentSubmits.length && now - recentSubmits[0] > 300) recentSubmits.shift();
      if (recentSubmits.length >= WAF_BURST) { stats.waf406++; return send(res, 406, '<!DOCTYPE html><html>Not Acceptable — indusguard</html>', { 'content-type': 'text/html' }); }
    }
    if (req.headers['x-csrf-token'] !== s.token) { stats.csrfFail++; return send(res, 403, 'CSRF token validation failed', { 'x-csrf-token': 'Required' }); }
    let body = {}; try { body = JSON.parse(raw); } catch (_) { /* ignore */ }
    const track = body.NavEBiddingTrackHis || [];
    const okCaptcha = s.activeAnswer && body.IvCaptchaValue === s.activeAnswer;
    const consumed = s.activeCaptcha; s.activeCaptcha = null; s.activeAnswer = null;
    const msg = (Type, Message) => ({ d: { Ev_Text: '', NavEBiddingMessage: { results: [{ Type, Message }] }, NavEBiddingTrackHis: { results: track.map((t) => ({ ...t, ChangeNo: okCaptcha ? crypto.randomBytes(16).toString('base64') : '', CreatedOn: okCaptcha ? `/Date(${sapNow()})/` : null, CreatedAt: okCaptcha ? 'PT10H30M00S' : 'PT0S', BiddingRank: okCaptcha ? '1' : '0', L1BidAmount: t.BiddingAmount })) } } });
    if (!okCaptcha || !consumed) {
      stats.wrongCaptcha++;
      stats.saves.push({ ok: false, at: now, sapOrderId: track[0]?.SapOrderId, reason: consumed ? 'wrong' : 'no-active-captcha', fromBoundaryMs: now - (win - CLOCK_OFFSET_MS), session: s.id });
      return send(res, 201, msg('E', 'Wrong Captcha'));
    }
    if (!windowOpen()) return send(res, 201, msg('E', 'Bidding time has ended'));
    for (const t of track) {
      const rank = stats.saves.filter((b) => b.ok && b.sapOrderId === t.SapOrderId).length + 1;
      stats.saves.push({ ok: true, at: now, sapOrderId: t.SapOrderId, amount: t.BiddingAmount, rank, fromBoundaryMs: now - (win - CLOCK_OFFSET_MS), session: s.id, captcha: body.IvCaptchaValue });
    }
    return send(res, 201, msg('S', 'Bidding Amount Saved Successfully.'));
  }
  if (url.startsWith(`${PFX}/`)) return gatewayNotFound(res);
  send(res, 404, { error: 'not found', url });
});

server.keepAliveTimeout = 30_000;
server.on('error', (e) => { console.error(`[mock-sap] ${e.message}`); process.exit(1); });
process.on('SIGINT', () => process.exit(0));
process.on('SIGTERM', () => process.exit(0));
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[mock-sap] listening http://127.0.0.1:${PORT}${PFX} | clock offset +${CLOCK_OFFSET_MS}ms | latency ${LATENCY_MS}ms | windows [${WINDOW_MINUTES.join(',')}] open ${OPEN_MS}ms | captcha unlock delay ${CAPTCHA_UNLOCK_DELAY_MS}ms | unknown-rate ${UNKNOWN_RATE} | waf-burst ${WAF_BURST}`);
  console.log(`[mock-sap] wrote ${mapOut.length} hashes → test/captcha-map.test.json`);
});
