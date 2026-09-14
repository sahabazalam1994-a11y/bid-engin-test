'use strict';

/**
 * region-probe.js — run ON YOUR VPS. Tells you where SAP lives and how far
 * away you are (DNS, hosting, TCP/TLS/TTFB, jitter, SAP clock offset).
 *   node tools/region-probe.js [https://host:port/path]
 */

const dns = require('dns').promises;
const tls = require('tls');
const https = require('https');
const { performance } = require('perf_hooks');

const target = new URL(process.argv[2] || process.env.SAP_BASE_URL || 'https://rise.eye2serve.com:8443/sap/opu/odata/sap/ZVC_TRANSPORTER_SRV');
const N = parseInt(process.env.PROBE_SAMPLES || '20', 10);

const getJson = (url) => new Promise((resolve) => {
  https.get(url, { timeout: 6000, headers: { 'user-agent': 'region-probe' } }, (r) => { let s = ''; r.on('data', (c) => (s += c)); r.on('end', () => { try { resolve(JSON.parse(s)); } catch { resolve(null); } }); }).on('error', () => resolve(null)).on('timeout', () => resolve(null));
});

function tcpTlsProbe(host, port) {
  return new Promise((resolve) => {
    const t0 = performance.now();
    let tConn = 0;
    const sock = tls.connect({ host, port, servername: host, rejectUnauthorized: false, ALPNProtocols: ['h2', 'http/1.1'] }, () => {
      const tTls = performance.now();
      const req = `GET ${target.pathname}/ HTTP/1.1\r\nHost: ${host}:${port}\r\nUser-Agent: region-probe\r\nConnection: close\r\n\r\n`;
      const tSend = performance.now();
      sock.write(req);
      sock.once('data', (buf) => {
        const tFirst = performance.now();
        const m = /^date:\s*(.+)$/im.exec(buf.toString());
        const sapMs = m ? Date.parse(m[1]) : NaN;
        resolve({ tcp: tConn - t0, tls: tTls - tConn, ttfb: tFirst - tSend, alpn: sock.alpnProtocol, sapOffset: Number.isFinite(sapMs) ? Math.round(sapMs + 500 - (Date.now() - (tFirst - tSend) / 2)) : null });
        sock.destroy();
      });
    });
    sock.once('connect', () => { tConn = performance.now(); });
    sock.on('error', (e) => resolve({ error: e.message }));
    sock.setTimeout(8000, () => { resolve({ error: 'timeout' }); sock.destroy(); });
  });
}

const stat = (arr) => { const s = [...arr].sort((a, b) => a - b); const p = (q) => s[Math.min(s.length - 1, Math.floor(q * s.length))]; return { min: s[0], p50: p(0.5), p90: p(0.9), max: s[s.length - 1], jitter: p(0.9) - s[0] }; };
const fmt = (o) => Object.entries(o).map(([k, v]) => `${k}=${v.toFixed(1)}`).join(' ');

(async () => {
  const host = target.hostname; const port = parseInt(target.port || '443', 10);
  console.log(`\n== SAP endpoint: ${host}:${port}`);
  const ips = await dns.lookup(host, { all: true });
  console.log(`DNS: ${ips.map((i) => i.address).join(', ')}`);
  for (const { address } of ips) {
    const info = await getJson(`https://ipinfo.io/${address}/json`);
    if (info) console.log(`  ${address} → ${info.org || '?'} | ${info.city || '?'}, ${info.region || '?'}, ${info.country || '?'} | ${info.hostname || ''}`);
  }
  const me = await getJson('https://ipinfo.io/json');
  if (me) console.log(`\n== This VPS: ${me.ip} → ${me.org || '?'} | ${me.city || '?'}, ${me.region || '?'}, ${me.country || '?'}`);

  console.log(`\n== ${N} TCP+TLS+TTFB samples…`);
  const tcp = []; const tlsA = []; const ttfb = []; const off = []; let alpn = '';
  for (let i = 0; i < N; i++) {
    const r = await tcpTlsProbe(host, port);
    if (r.error) { console.log(`  sample ${i}: ${r.error}`); continue; }
    tcp.push(r.tcp); tlsA.push(r.tls); ttfb.push(r.ttfb); if (r.sapOffset != null) off.push(r.sapOffset); alpn = r.alpn;
  }
  if (tcp.length) {
    console.log(`TCP connect : ${fmt(stat(tcp))} ms`);
    console.log(`TLS handshk : ${fmt(stat(tlsA))} ms   (ALPN negotiated: ${alpn || 'http/1.1'} → ${alpn === 'h2' ? 'HTTP/2 available, try SAP_HTTP2=true' : 'HTTP/1.1 only, keep SAP_HTTP2=false'})`);
    console.log(`TTFB (RTT)  : ${fmt(stat(ttfb))} ms   ← this is your per-trip cost; 2 trips per bid`);
    if (off.length) { const s = stat(off); console.log(`SAP clock   : offset ≈ ${s.p50.toFixed(0)}ms (coarse, 1s Date header) — engine refines this by edge-detection`); }
    const p50 = stat(ttfb).p50;
    console.log(`\nVerdict: ${p50 < 5 ? '🏆 co-located (same AZ/region)' : p50 < 15 ? '✅ same region — good' : p50 < 40 ? '⚠️  same country, different DC — move to AWS ap-south-1' : '❌ far — move VPS to AWS ap-south-1 (Mumbai)'} (p50 TTFB ${p50.toFixed(1)}ms, jitter ${stat(ttfb).jitter.toFixed(1)}ms)`);
  }
})();
