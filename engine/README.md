# SAP Bid Engine v4.0 — Rank-1 Hardening

**The loop at window-open:** `fetch captcha → 0ms in-memory hash lookup → submit`, on a hot TCP_NODELAY
keep-alive connection, CSRF re-minted 300ms earlier, fired on **SAP's clock** (not local).

## What changed vs v3.35
| Removed (pure damage) | Why |
|---|---|
| Independent captcha pre-fetch poller | captcha rotates at window-open → pre-fetched answer is DOA |
| `EARLY_DROP` | can't work with captcha — it doesn't exist before open |
| `bidding.js` + TrueCaptcha + tesseract | 162 known images → lookup is in-process, no localhost hop |
| Parallel captcha probes | every extra fetch invalidates the previous captcha |
| Global submit mutex | replaced by per-session serialization + capped parallel sessions |

| Added | |
|---|---|
| Embedded captcha map (`data.json` → in-memory `Map`, hot-reloaded) | unknown hashes → `logs/unknown-captcha/*.png` + `.jsonl` |
| SAP clock sync (Date-header edge detection, ±~50ms) | fire at `boundary − offset − oneWayRTT` |
| Boundary scheduler | T-22s clock-sync → T-300ms CSRF re-mint → T-oneWay FIRE |
| Orders poller (100ms, from T-5s) as the **non-captcha** unlock signal | dispatches the instant SAP publishes orders |
| Serialized per-session fire loop, sessions in parallel (40ms stagger), first item raced | `FIRE_RACE_FIRST`, `SESSION_STAGGER_MS`, `MAX_INFLIGHT_SUBMITS` |
| Per-session WAF back-off (other sessions continue) + jitter | `wafActive(session)` |
| `logs/fire-timing-*.csv` | per attempt: captcha ms, submit ms, total from SAP boundary |

## Files
```
bid-engine.js            v4 engine (single file)
logger.js                tiny logger (stdout + logs/engine-YYYY-MM-DD.log)
data.json                162 captcha hashes → answers  (sha256 of the base64 string)
cookie.txt, cookie2.txt… one SAP session per file (all same vendor)
files/input2.csv, delete.csv, priority.csv
.env.example             copy to .env
tools/region-probe.js    run on VPS: SAP hosting region, RTT/jitter, ALPN, clock offset
tools/vps-tune.sh        chrony NTP + sysctl low-latency + BBR
test/mock-sap.js         mock SAP with clock skew, rotating captcha, ranking
test/run-e2e.js          end-to-end test (≈90s)
bid-engine.v3.35.backup.js, bidding.legacy.js   old code, not used
```

## Run
```bash
cp .env.example .env         # edit VENDOR_ID / PLANT_CODE if needed
yarn install                 # or npm i
node tools/region-probe.js   # Phase 1 check
node bid-engine.js           # or pm2 start bid-engine.js --name bid-engine
```

## Phase 1 — infrastructure (70% of the battle)
SAP endpoint `rise.eye2serve.com` resolves to **AWS ap-south-1 (Mumbai)** behind Indusface AppTrana WAF.
Target: an EC2 instance in **ap-south-1** (any AZ; try 1a/1b/1c and keep the one with lowest p50 TTFB
from `region-probe`). Run `sudo bash tools/vps-tune.sh` once. Aim for TTFB p50 < 10ms, jitter < 5ms.

## Tuning knobs (`.env`)
- `FIRE_LEAD_MS=-1` auto = measured one-way latency. Set explicitly after reading `fire-timing` CSV
  (if first captcha fetch is always empty → lower; if `captcha_ms` is high → raise).
- `CSRF_REMINT_LEAD_MS=300` — token minted this many ms before fire.
- `FIRE_RACE_FIRST=true` — all sessions race the first (priority) item; `SESSION_STAGGER_MS=40`.
- `MAX_INFLIGHT_SUBMITS=3` — concurrent submit cap; `SUBMIT_MIN_GAP_MS=0` — optional global spacing between submits (raise to 100-200 if the WAF ever 406s mid-window).
- `CAPTCHA_EMPTY_RETRY_MS=25` — re-fetch interval while SAP still returns an empty captcha (harmless: no token exists yet).
- `SAP_CLOCK_OFFSET_MS` — force a fixed offset (skips sync). Leave unset normally.
- `SAP_HTTP2=false` — only flip to true if `region-probe` shows ALPN `h2`.

## Adding an unknown captcha
Open `logs/unknown-captcha/<hash>.png`, read it, append `{"hash":"<hash>","result":"<answer>"}` to `data.json`.
The engine reloads the file automatically (5s watch).
