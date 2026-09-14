'use strict';

const fs = require('fs');
const path = require('path');

const LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MIN = LEVELS[(process.env.LOG_LEVEL || 'info').toLowerCase()] || 20;
const DIR = path.join(__dirname, 'logs');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

let day = '';
let stream = null;
function out() {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) {
    if (stream) stream.end();
    day = today;
    stream = fs.createWriteStream(path.join(DIR, `engine-${today}.log`), { flags: 'a' });
  }
  return stream;
}

function istStamp() {
  const d = new Date();
  const s = d.toLocaleTimeString('en-GB', { timeZone: 'Asia/Kolkata', hour12: false });
  return `${s}.${String(d.getMilliseconds()).padStart(3, '0')}`;
}

function build(name) {
  const emit = (level) => (a, b) => {
    if (LEVELS[level] < MIN) return;
    let meta = '';
    let msg = a;
    if (typeof a === 'object' && a !== null) { meta = ' ' + JSON.stringify(a); msg = b || ''; }
    const line = `${istStamp()} ${level.toUpperCase().padEnd(5)} [${name}] ${msg}${meta}`;
    (level === 'error' ? process.stderr : process.stdout).write(line + '\n');
    try { out().write(line + '\n'); } catch (_) { /* ignore */ }
  };
  return { debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error') };
}

module.exports = { build };
