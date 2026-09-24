# SAP Bid Engine — Rank-1 Hardening (v4.0)

## Original problem statement (summary)
Targeted rewrite of the timing/captcha path of an existing Node.js SAP bidding bot (`bid-engine.js` + `bidding.js`).
Facts: captcha set fixed (162 images, answers known → 0ms hash lookup); captcha rotates on every fetch and only exists
after window open; all vendors bid the same amount → pure latency race. Phases: (1) infra/co-location + clock,
(2) kill stale-captcha pre-fetch + EARLY_DROP, (3) embedded captcha map, (4) pre-warm everything except captcha,
(5) unlock detection + rapid serialized fire loop + multi-session, (6) WAF guard.

## User choices
- Existing code uploaded (bid-engine.js v3.35, bidding.js, data.json 162 hashes sha256(base64)→answer, creds.json)
- VPS already in Mumbai. SAP endpoint rise.eye2serve.com → AWS ap-south-1 (Mumbai), Indusface AppTrana WAF.
- Session parallelism: HYBRID (serialized per session, sessions in parallel w/ small stagger)
- Backend engine only; monitoring dashboard LATER.

## Architecture
`/app/engine/` — pure Node 20 CLI project (undici, csv-parser, dotenv). No FastAPI/React used.
- `bid-engine.js` v4.0 (single file): TCP_NODELAY keep-alive pool → SAP-clock sync (Date-header edge detection)
  → boundary scheduler (T-22s sync, T-300ms CSRF re-mint, T-oneWay FIRE) → armCaptcha (one post-boundary captcha per
  session, in parallel with back-to-back orders fetch) → fireItem (1 captcha fetch → Map lookup → submit, serialized per
  session) → dispatchItem (first item raced across sessions, rest round-robin) → classify() (ok/tied/wrong-captcha/ghost/
  time-ended/floor/reduce/auth/http-error/waf) → per-session WAF back-off; L1-undercut post-save kept.
- `logger.js`, `.env.example`, `README.md`, `tools/region-probe.js`, `tools/vps-tune.sh`
- `test/mock-sap.js` (clock skew, rotating captcha, WAF burst, unlock delay) + `test/run-e2e.js`
- Old code kept as `bid-engine.v3.35.backup.js`, `bidding.legacy.js` (unused).

## Implemented (2026-09-14)
- All 6 phases of the plan at code level. E2E: default 9/9 (first save boundary+38–43ms with +1.5s skew, 20ms RTT);
  hard mode (30% unknown captcha, WAF burst, 800ms unlock delay) 10/10.
- Testing agent iteration_1: engine clean; 2 test-harness determinism fixes applied.

## Implemented v4.1 (2026-09-18) — from 3 days of live logs
- Live evidence: captcha unlocks ~1.0s after Date-header boundary; serial probe granularity ~170ms → mostly 'tied';
  12 map answers rejected (OCR-polluted data.json); BidOrderListSet 2.7-3.7s at boundary.
- Backend (ABAP) clock sync via Gateway error XML <timestamp> (CLOCK_SOURCE=backend), Date-header kept as fallback/diag.
- Learned unlock lag (logs/unlock-lag-*.csv, logs/clock-state.json), first probe aimed to ARRIVE at boundary+lag+15ms,
  sessions phased RTT/N; observations only from bracketed/aimed probes, capped 5s (catch-up fires ignored).
- captcha-bad.json persistence + logs/wrong-captcha/*.png; optional CAPTCHA_FALLBACK_URL with auto-learn into data.json.
- ORDERS_FREEZE_MS=1500 (no order fetch in critical path when plan ready). SESSION_STAGGER_MS default 0.
- Mock: gateway 404 XML timestamp, MOCK_WAF_DATE_SKEW_MS, unlockDetect stats; e2e E2E_WINDOWS + lag checks (11/11).

## Implemented v4.2 (user request) — STRIKE_MODE
- `timed` (default per user): after unlock detect → STRIKE_PARALLEL=3 fetchers for STRIKE_WARM_MS=3000 (no save) → final fetch
  timed so save arrives at unlock+STRIKE_SAVE_AT_MS=4000; once per session per window (STRIKE_PER_ITEM to change);
  mid-window new matched orders (10→12) trigger the same. `instant` = v4.1 path. `ab` = alternate per window.
- e2e timed scenario 11/11 (save at unlock+4055ms, 102 warm fetches/session, no early save); instant 9/9 regression.
- Runner now evaluates the LAST window (catch-up saves at engine start were confusing checks).

## Backlog
- P1: User runs `tools/region-probe.js` on VPS; move to AWS ap-south-1 if TTFB p50 > 15ms; run `vps-tune.sh`.
- P1: First live windows: read `logs/fire-timing-*.csv`, tune FIRE_LEAD_MS / CSRF_REMINT_LEAD_MS / SESSION_STAGGER_MS.
- P2: Optional monitoring dashboard (live log/status).
- P2: Label any `logs/unknown-captcha/*.png` and append to data.json.
- P2: If SAP publishes orders BEFORE open, consider ARM at T-0 only (already handled: cached orders → immediate fire).
