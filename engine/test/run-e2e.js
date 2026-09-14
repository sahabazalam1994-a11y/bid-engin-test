'use strict';

/**
 * E2E: start mock SAP (+1500ms clock skew) → start engine (windows every
 * minute) → wait for one window → assert first save landed fast & correct.
 *   node test/run-e2e.js            (≈ 70-130s)
 */

const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const http = require('http');

const ROOT = path.join(__dirname, '..');
const PORT = 9443;
const ALL_MINUTES = Array.from({ length: 60 }, (_, i) => i).join(',');

function ensureTestFixtures() {
  const files = path.join(ROOT, 'files');
  if (!fs.existsSync(files)) fs.mkdirSync(files);
  fs.writeFileSync(path.join(files, 'input2.csv'), 'City Code Description,Special Process Indicator,Bidding Amount\nMUMBAI,1164,1234\nPUNE - STO,,999\nNAGPUR,,500\n');
  fs.writeFileSync(path.join(files, 'delete.csv'), 'Customer\nBLOCKED CO\n');
  fs.writeFileSync(path.join(files, 'priority.csv'), 'Vbeln\n1150000002\n');
  fs.writeFileSync(path.join(ROOT, 'cookie.txt'), 'SAP_SESSIONID=mock-s1; sess_map=abc');
  fs.writeFileSync(path.join(ROOT, 'cookie2.txt'), 'SAP_SESSIONID=mock-s2; sess_map=def');
  for (const f of ['token.txt', 'token2.txt']) { try { fs.unlinkSync(path.join(ROOT, f)); } catch (_) { /* ignore */ } }
}

const get = (p) => new Promise((resolve, reject) => http.get({ host: '127.0.0.1', port: PORT, path: p }, (r) => { let s = ''; r.on('data', (c) => (s += c)); r.on('end', () => resolve(JSON.parse(s))); }).on('error', reject));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function main() {
  try { require('child_process').execSync('pkill -f "test/mock-sap.js"; pkill -f "bid-engine.js"', { stdio: 'ignore' }); } catch (_) { /* none running */ }
  await sleep(500);
  ensureTestFixtures();
  const env = { ...process.env, WINDOW_MINUTES: ALL_MINUTES, MOCK_PORT: String(PORT), MOCK_CLOCK_OFFSET_MS: process.env.MOCK_CLOCK_OFFSET_MS || '1500', MOCK_OPEN_MS: '30000' };
  const mock = spawn('node', ['test/mock-sap.js'], { cwd: ROOT, env, stdio: ['ignore', 'inherit', 'inherit'] });
  await sleep(800);

  const engineEnv = {
    ...env,
    SAP_BASE_URL: `http://127.0.0.1:${PORT}/sap/opu/odata/sap/ZVC_TRANSPORTER_SRV`,
    CAPTCHA_MAP_FILE: 'test/captcha-map.test.json',
    HOT_POST_MS: '35000', HOT_PRE_MS: '20000', CLOCK_SYNC_LEAD_MS: '20000', CLOCK_SYNC_DURATION_MS: '5000',
    METRICS_INTERVAL_MS: '0', L1_UNDERCUT: 'false', LOG_LEVEL: process.env.LOG_LEVEL || 'info',
  };
  const engine = spawn('node', ['bid-engine.js'], { cwd: ROOT, env: engineEnv, stdio: ['ignore', 'inherit', 'inherit'] });

  // Wait until the next minute boundary + 12s
  const now = Date.now();
  const nextMin = now - (now % 60_000) + 60_000;
  const waitMs = nextMin - now + 12_000 + (nextMin - now < 25_000 ? 60_000 : 0); // need ≥25s of pre-warm
  console.log(`[e2e] waiting ${(waitMs / 1000).toFixed(0)}s for window + settle…`);
  await sleep(waitMs);

  const st = await get('/mock/stats');
  engine.kill('SIGINT'); mock.kill('SIGTERM');
  setTimeout(() => { try { engine.kill('SIGKILL'); mock.kill('SIGKILL'); } catch (_) { /* gone */ } }, 1500).unref();

  const okSaves = st.saves.filter((s) => s.ok);
  // Catch-up saves from an already-open window at engine start are correct behaviour but not boundary-aligned.
  const aligned = okSaves.filter((s) => s.fromBoundaryMs < 15_000).sort((a, b) => a.at - b.at);
  const first = aligned[0] || okSaves.sort((a, b) => a.at - b.at)[0];
  const results = [];
  const check = (name, cond, detail) => { results.push({ name, pass: !!cond, detail }); console.log(`${cond ? '✅' : '❌'} ${name}${detail ? ' — ' + detail : ''}`); };

  check('at least one bid saved', okSaves.length >= 1, `${okSaves.length} ok saves, ${st.wrongCaptcha} wrong-captcha`);
  check('priority order (9000000002) saved first', first && first.sapOrderId === '9000000002', first ? `first=${first.sapOrderId}` : 'none');
  check('blacklisted order (9000000003) never bid', !st.saves.some((s) => s.sapOrderId === '9000000003'));
  const maxFirst = parseInt(process.env.E2E_MAX_FIRST_MS || '400', 10);
  check('first save within ' + maxFirst + 'ms of SAP boundary', first && first.fromBoundaryMs >= -50 && first.fromBoundaryMs <= maxFirst, first ? `${first.fromBoundaryMs}ms after boundary (mock skew +${st.clockOffsetMs}ms)` : 'none');
  check('captcha lookup correct (no wrong-captcha before first success)', process.env.MOCK_UNKNOWN_RATE ? true : !st.saves.some((s) => !s.ok && first && s.at < first.at), `wrong=${st.wrongCaptcha}`);
  check('MUMBAI order saved at 1234', okSaves.some((s) => s.sapOrderId === '9000000001' && s.amount === '1234.000') || st.waf406 > 0, st.waf406 > 0 && !okSaves.some((s) => s.sapOrderId === '9000000001') ? 'skipped: mock WAF blocked all sessions for the remainder of the window (expected back-off)' : '');
  check('PUNE order saved at 999', okSaves.some((s) => s.sapOrderId === '9000000002' && s.amount === '999.000'));
  check('no CSRF failures', st.csrfFail === 0, `csrfFail=${st.csrfFail}`);
  check('captcha fetched only during/after unlock (no pre-boundary rotation)', st.captchaIssued <= okSaves.length + st.wrongCaptcha + 4 + (process.env.MOCK_UNKNOWN_RATE ? 20 : 0), `issued=${st.captchaIssued} empty=${st.captchaEmpty}`);
  if (process.env.MOCK_WAF_BURST) check('WAF 406 respected (engine backed off, saves still landed)', st.waf406 >= 1 && okSaves.length >= 1, `waf406=${st.waf406}`);

  const passed = results.filter((r) => r.pass).length;
  console.log(`\n[e2e] ${passed}/${results.length} checks passed`);
  fs.writeFileSync(path.join(__dirname, 'e2e-result.json'), JSON.stringify({ results, stats: st }, null, 2));
  process.exit(passed === results.length ? 0 : 1);
}

main().catch((e) => { console.error(e); process.exit(1); });
