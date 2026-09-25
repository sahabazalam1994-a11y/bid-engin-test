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

## v4.1 — what the live logs (15–17 Sep) taught us, and what changed
| Finding (from `fire-timing-*.csv`, `out.log`) | Fix |
|---|---|
| Captcha unlocked **~1.0 s after** our boundary every window | Clock source was the WAF's `Date` header (Indusface proxy). Now we sync to the **ABAP backend clock** via the Gateway error XML `<timestamp>` (µs precision) — `CLOCK_SOURCE=backend`. Both offsets are logged so you can see the WAF-vs-backend delta. |
| Serial probes every ~170 ms → unlock noticed ~85 ms late on average → mostly `tied` | Engine **learns the unlock lag** per window (`logs/unlock-lag-*.csv`, persisted in `logs/clock-state.json`) and times the first probe to **arrive** at `boundary + lag + UNLOCK_MARGIN_MS`. With N sessions the probes are phased `RTT/N` apart so one of them lands within a few ms of the unlock. |
| 12 distinct map answers rejected as *Wrong Captcha* (`jw62K`, `arch`, `dsjcbka`, …) — OCR-polluted map, rejections lost on restart | Rejections persisted to `captcha-bad.json` (excluded on load) + image saved to `logs/wrong-captcha/<hash>__was-<answer>.png` for relabelling. Optional `CAPTCHA_FALLBACK_URL` (your old `bidding.js`) is used **only** for unknown/rejected hashes; an accepted fallback answer is auto-learned into `data.json`. |
| `BidOrderListSet` takes 2.7–3.7 s at the boundary | `ORDERS_FREEZE_MS=1500`: once the cached orders yield a plan, no order fetch is issued in the last 1.5 s — only captcha + submit are in flight at the open. Cached orders were already dispatched at T-0 (no fetch). |

Expected after 1–2 live windows: `🔓 captcha UNLOCK observed at boundary+~1000ms` → next window `⏲ holding first probe …` → first submit ≈ unlock + captcha RTT + ~20 ms (vs unlock + 85–170 ms before). **Add cookie2.txt / cookie3.txt** — each extra session halves the detection granularity.

## v4.2 — Strike modes (`STRIKE_MODE`)
| Mode | What happens after the captcha unlock is detected |
|---|---|
| `timed` (default, as requested) | **Boundary-anchored.** From `boundary + STRIKE_WARM_START_MS` (−5000 → 00:44:55) every session runs `STRIKE_PARALLEL=3` fetchers: fetch → hash → fetch → hash … **no save**, even if orders already match. At `boundary + STRIKE_SAVE_AT_MS` (+5000 → 00:45:05) **one session per order** does the final fetch → lookup → save (no session race). Orders that appear later in the window (10 → 12, matching CSV): the session warms `STRIKE_MIDWINDOW_WARM_MS=5000` then saves. `STRIKE_PER_ITEM=true` → every item warms separately. |
| `instant` | v4.1 behaviour: save with the first captcha after unlock (≈ unlock + 1 RTT). |
| `ab` | Alternate `timed` / `instant` per window → compare ranks in `logs/bid-log-*.csv` to prove which wins. |

Honest note: live logs show competitors' saves landing before ~1.4 s after the boundary (our `tied` results). `timed` saves at +5 s; if SAP ranks by arrival, `instant` should win. Run `STRIKE_MODE=ab` for a day and let the bid-log decide. WAF: 3 fetchers × 10 s ≈ 200 requests/session per window — drop `STRIKE_PARALLEL` to 1 if you see 406s.

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
