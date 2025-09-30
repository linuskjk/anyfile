const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const multer = require('multer');

const app = express();
const PORT = process.env.PORT || 3000;

// Behind Synology reverse proxy - trust first proxy hop so req.protocol is accurate
app.set('trust proxy', 1);

// If accessed via main domain with /anyfile path, redirect permanently to api subdomain
app.use((req, res, next) => {
  const host = (req.headers.host || '').toLowerCase();
  if (host === 'anyfile.uk' && req.originalUrl.startsWith('/anyfile')) {
    const target = 'https://anyfile.uk/';
    return res.redirect(301, target);
  }
  next();
});

// Optional debug middleware to log raw upload ingress rate. Change to true to enable
const DEBUG_UPLOAD = true; // Change to false to disable upload debug logging
if (DEBUG_UPLOAD) {
  app.use((req, res, next) => {
    if (req.method === 'POST' && (req.url.startsWith('/api/upload') || req.url.startsWith('/anyfile/api/upload'))) {
      const start = Date.now();
      let bytes = 0;
      let lastLog = start;
      req.on('data', chunk => {
        bytes += chunk.length;
        const now = Date.now();
        if (now - lastLog >= 1000) {
          const secs = (now - start) / 1000;
          const rate = bytes / secs;
          console.log(`[UPLOAD_DEBUG] ${bytes} bytes ${(bytes/1024/1024).toFixed(2)}MB in ${secs.toFixed(1)}s avg ${(rate/1024/1024).toFixed(2)}MB/s`);
          lastLog = now;
        }
      });
      req.on('end', () => {
        const secs = (Date.now() - start) / 1000;
        const rate = bytes / secs;
        console.log(`[UPLOAD_DEBUG] COMPLETE ${bytes} bytes ${(bytes/1024/1024).toFixed(2)}MB in ${secs.toFixed(2)}s avg ${(rate/1024/1024).toFixed(2)}MB/s`);
      });
    }
    next();
  });
}

// Simple cookie parser (tiny, avoids adding dependency). Returns object of key->value.
function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(';').forEach(part => {
    const idx = part.indexOf('=');
    if (idx === -1) return;
    const k = part.slice(0, idx).trim();
    const v = decodeURIComponent(part.slice(idx + 1).trim());
    if (k) out[k] = v;
  });
  return out;
}

const HTML_ESCAPE_LOOKUP = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;"
};

function escapeHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPE_LOOKUP[ch] || ch);
}

function formatBytesShort(bytes) {
  const num = typeof bytes === 'string' ? parseFloat(bytes) : bytes;
  if (!Number.isFinite(num) || num < 0) return '';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let value = num;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx++;
  }
  const precision = value >= 10 || idx === 0 ? 0 : 1;
  return `${value.toFixed(precision)} ${units[idx]}`;
}

function formatDateTime(isoString) {
  if (!isoString) return '';
  const d = new Date(isoString);
  if (!Number.isFinite(d.getTime())) return '';
  try {
    return d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
  } catch (err) {
    return d.toUTCString();
  }
}

// Assign or read persistent uploader ID cookie (random opaque id)
app.use((req, res, next) => {
  try {
    const cookies = parseCookies(req.headers.cookie || '');
    let uid = cookies['anysend_uid'];
    if (!uid || !/^[A-Za-z0-9_-]{8,}$/.test(uid)) {
      uid = crypto.randomBytes(9).toString('base64').replace(/[^A-Za-z0-9_-]/g,'').slice(0,12);
    }
    const secure = (req.protocol === 'https');
    // Cookie domain for cross-subdomain identity - change if needed
    const cookieDomain = '.anyfile.uk'; // Hardcoded cookie domain
    const domainSegment = cookieDomain ? `; Domain=${cookieDomain}` : '';
    // Always refresh cookie expiry to keep active users persistent
    res.setHeader('Set-Cookie', `anysend_uid=${uid}; Path=/; Max-Age=31536000; SameSite=Lax${secure ? '; Secure' : ''}${domainSegment}`);
    req.anysendUploaderId = uid;
  } catch (e) {
    console.warn('cookie parse failed', e);
  }
  next();
});

app.use((req, res, next) => {
  const headerPass = (req.headers['x-anysend-pass'] || req.headers['x-anyfile-pass'] || '').toString();
  if (PREMIUM_PASSWORD) {
    req.anysendTier = headerPass && headerPass === PREMIUM_PASSWORD ? 'premium' : 'standard';
  } else {
    // If no password configured, treat everyone as premium (optional override)
    req.anysendTier = headerPass ? 'premium' : 'standard';
  }
  req.anysendPassProvided = !!headerPass;
  next();
});

// CORS allowed origins - modify this list as needed
const allowedOrigins = ['https://anyfile.uk', 'https://upload.anyfile.uk', 'https://files.anyfile.uk'];
app.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin && allowedOrigins.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Vary', 'Origin');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  const corsHeaders = new Set([
    'Content-Type',
    'Accept',
    'X-Requested-With',
    'X-AnySend-Pass',
    'X-Anyfile-Pass',
    'x-anysend-pass',
    'x-anyfile-pass'
  ]);
  const requestedHeaders = (req.headers['access-control-request-headers'] || '')
    .split(',')
    .map(h => h && h.trim())
    .filter(Boolean);
  requestedHeaders.forEach(h => corsHeaders.add(h));
  res.setHeader('Access-Control-Allow-Headers', Array.from(corsHeaders).join(', '));
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// Plain probe endpoint to positively identify this Node instance through a reverse proxy
// Support both /__probe__ and /_probe for convenience
app.get(['/__probe__','/_probe'], (req, res) => {
  res.type('text/plain').send('ANYSEND_NODE_OK');
});

// ---------------------------------------------
// Upload configuration & validation (Step 5)
// ---------------------------------------------
// Rationale:
//  - Restrict extensions + MIME to reduce attack surface (no executables / scripts)
//  - Sanitize filenames server-side (remove path separators, control chars, limit length)
//  - Unique prefix prevents collisions & simple enumeration guessing
//  - Per-file size enforced by Multer, total size approximated client-side and validated per request
//  - Future hardening ideas: virus scanning hook, rate limiting, auth tokens, temporary signed URLs
// Tune these constants as needed
// Size limits removed (set to null / unlimited). WARNING: This allows arbitrarily large uploads.
const PER_FILE_LIMIT_BYTES = null; // unlimited
const TOTAL_REQUEST_LIMIT_BYTES = null; // unlimited cumulative
const ALLOWED_EXTENSIONS = [
  'png','jpg','jpeg','gif','webp','txt','pdf','md','zip'
];
const ALLOWED_MIME_PREFIXES = [
  'image/png','image/jpeg','image/gif','image/webp',
  'text/plain','application/pdf','text/markdown','application/zip','application/x-zip-compressed'
];
// File type restrictions: set to true to allow all file types (no restrictions)
const ALLOW_ALL = true; // Change to false to enable file type restrictions

// Ensure uploads directory exists
const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}
const SITES_DIR = path.join(UPLOAD_DIR, 'sites');
if (!fs.existsSync(SITES_DIR)) { fs.mkdirSync(SITES_DIR, { recursive: true }); }

const DAILY_LIMIT_BYTES = 1024 * 1024 * 1024; // 1 GB per day for standard users
const STANDARD_EXPIRE_DAYS = 7;
const PREMIUM_PASSWORD = (process.env.ANYSEND_PREMIUM_PASSWORD || '').trim();
const QUOTA_FILE = path.join(UPLOAD_DIR, 'quota_usage.jsonl');
const QUOTA_USAGE = new Map(); // key `${identifier}:${day}` -> total bytes uploaded that day
const DAY_MS = 24 * 60 * 60 * 1000;

function normalizeIp(value) {
  if (!value) return '';
  const trimmed = value.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('::ffff:')) {
    return trimmed.slice(7);
  }
  return trimmed;
}

function resolveClientIp(req) {
  const xfwd = (req.headers['x-forwarded-for'] || '')
    .split(',')
    .map(normalizeIp)
    .filter(Boolean);
  if (xfwd.length) {
    return xfwd[0];
  }
  const ip = normalizeIp(req.socket && req.socket.remoteAddress || '');
  return ip;
}

function resolveQuotaIdentifier(req) {
  const ip = resolveClientIp(req);
  if (ip) return ip;
  return req.anysendUploaderId || '';
}

function buildQuotaInfo(identifier, usedBytes, day, extra = {}) {
  if (!identifier && !extra.identifierType) {
    return null;
  }
  const limit = DAILY_LIMIT_BYTES;
  const used = Number(usedBytes) || 0;
  return {
    identifier,
    identifierType: extra.identifierType || (identifier ? 'ip' : 'id'),
    day,
    limit,
    used,
    remaining: Math.max(0, limit - used)
  };
}

function getQuotaSnapshotForRequest(req) {
  const tier = req.anysendTier === 'premium' ? 'premium' : 'standard';
  if (tier === 'premium') {
    return { tier, quota: null };
  }
  const identifier = resolveQuotaIdentifier(req);
  if (!identifier) {
    return { tier, quota: null };
  }
  const day = new Date().toISOString().slice(0, 10);
  const used = getDailyUsage(identifier, day);
  const ip = resolveClientIp(req);
  const identifierType = ip && ip === identifier ? 'ip' : 'id';
  const quota = buildQuotaInfo(identifier, used, day, {
    identifierType,
    ip,
    uploaderId: req.anysendUploaderId || ''
  });
  return { tier, quota };
}

// Locate the Synology web root so custom folders can be served live
const WEB_ROOT_CANDIDATES = [
  process.env.WEB_ROOT,
  '/volume1/web',
  '/web',
  '/synology-web',
  path.join(__dirname, '..', 'web'),
  path.join(__dirname, 'web-root')
].filter(Boolean);

let WEB_ROOT_DIR = null;
for (const cand of WEB_ROOT_CANDIDATES) {
  try {
    if (cand && fs.existsSync(cand) && fs.statSync(cand).isDirectory()) {
      WEB_ROOT_DIR = cand;
      break;
    }
  } catch (_) { /* ignore */ }
}
if (!WEB_ROOT_DIR) {
  WEB_ROOT_DIR = path.join(__dirname, 'web-root');
  try { fs.mkdirSync(WEB_ROOT_DIR, { recursive: true, mode: 0o755 }); } catch (_) {}
}
console.log('[sites] Serving custom folders from:', WEB_ROOT_DIR);

// Resolve the /p directory location. Prefer Synology web root if available.
const P_DIR_CANDIDATES = [
  process.env.P_DIR,
  WEB_ROOT_DIR ? path.join(WEB_ROOT_DIR, 'p') : null,
  path.join(__dirname, 'p')
].filter(Boolean);

let P_DIR = null;
for (const cand of P_DIR_CANDIDATES) {
  try {
    if (cand && fs.existsSync(cand)) { P_DIR = cand; break; }
  } catch (_) { /* ignore */ }
}
if (!P_DIR) {
  // Fall back to app-local p directory if none exist and ensure it exists
  P_DIR = path.join(__dirname, 'p');
  try { fs.mkdirSync(P_DIR, { recursive: true, mode: 0o755 }); } catch (_) {}
}
console.log('[/p] Serving from:', P_DIR);

// If a template is bundled in the app directory, sync it into P_DIR (prefers p_index_replacement.html)
(() => {
  const templateCandidates = [
    path.join(__dirname, 'p_index_replacement.html'),
    path.join(__dirname, 'custom_index.html')
  ];
  const src = templateCandidates.find(p => {
    try { return fs.existsSync(p); } catch { return false; }
  });
  if (!src) return;
  const dest = path.join(P_DIR, 'index.html');
  try {
    const srcHtml = fs.readFileSync(src, 'utf8');
    if (fs.existsSync(dest)) {
      console.log(`[/p] index.html already exists at ${dest}, leaving current content intact.`);
      return;
    }
    fs.writeFileSync(dest, srcHtml, 'utf8');
    console.log(`[/p] index.html created from template ${path.basename(src)}`);
  } catch (err) {
    console.warn('[/p] Failed to sync template into /p/index.html:', err);
  }
})();

// Legacy templates stay available for optional manual sync – we no longer cache them in memory.

// Dynamically serve any folder created under the Synology web root (e.g. /volume1/web/<name>)
const RESERVED_SITE_SLUGS = new Set(['api', 'anyfile', 'uploads', 'f', 'p']);

function createSynologySiteHandler() {
  return (req, res, next) => {
    const slug = (req.params.siteName || '').toLowerCase();
    if (!slug || RESERVED_SITE_SLUGS.has(slug)) return next();
    if (!WEB_ROOT_DIR) return next();

    const siteDir = path.join(WEB_ROOT_DIR, slug);
    let stat;
    try {
      stat = fs.statSync(siteDir);
    } catch (_) {
      return next();
    }
    if (!stat.isDirectory()) return next();

    const relPath = req.path === '/' || req.path === '' ? '/index.html' : req.path;
    const candidate = path.normalize(path.join(siteDir, '.' + relPath));
    if (!candidate.startsWith(siteDir)) {
      return res.status(403).type('text/plain').send('Forbidden');
    }

    fs.access(candidate, fs.constants.R_OK, (err) => {
      if (err) {
        if (relPath === '/index.html') {
          return res.status(404).type('text/html').send('<!DOCTYPE html><html><body><h1>Not Found</h1><p>No index.html in this folder.</p></body></html>');
        }
        return next();
      }
      const headers = {
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0'
      };
      res.sendFile(candidate, { headers }, (sendErr) => {
        if (sendErr) next(sendErr);
      });
    });
  };
}

app.use('/:siteName', createSynologySiteHandler());
app.use('/anyfile/:siteName', createSynologySiteHandler());

// In-memory caches for quick lookup
const INDEX_CACHE = new Map(); // storedName -> { originalName, uploaderId, size, mime, hash, time }
const SHARE_TOKENS = new Map(); // token -> { storedName, uploaderId, created }
const SHORT_LINKS = new Map(); // code -> { code, token, storedName, uploaderId, created }
const EXPIRE_DAYS = parseInt(process.env.ANYSEND_EXPIRE_DAYS || '', 10) > 0 ? parseInt(process.env.ANYSEND_EXPIRE_DAYS, 10) : null;

function isExpired(meta) {
  if (!meta) return false;
  if (meta.deleted) return true;
  if (meta.expireAt) {
    const ts = Date.parse(meta.expireAt);
    if (Number.isFinite(ts)) {
      return Date.now() > ts;
    }
  }
  if (EXPIRE_DAYS && meta.time) {
    const ts = Date.parse(meta.time);
    if (Number.isFinite(ts)) {
      return (Date.now() - ts) > EXPIRE_DAYS * 24 * 60 * 60 * 1000;
    }
  }
  return false;
}

// Helper: load existing metadata into memory (best effort)
function loadIndexCache() {
  const indexFile = path.join(UPLOAD_DIR, 'index.jsonl');
  try {
    if (!fs.existsSync(indexFile)) return;
    const data = fs.readFileSync(indexFile, 'utf8');
    data.split(/\n/).forEach(line => {
      if (!line.trim()) return;
      try {
        const obj = JSON.parse(line);
        if (obj && obj.storedName) {
          INDEX_CACHE.set(obj.storedName, obj);
        }
      } catch(_){}
    });
  } catch(e) {
    console.warn('Failed to warm index cache', e);
  }
}

function loadShareTokens() {
  const tokFile = path.join(UPLOAD_DIR, 'share_tokens.jsonl');
  try {
    if (!fs.existsSync(tokFile)) return;
    const data = fs.readFileSync(tokFile, 'utf8');
    data.split(/\n/).forEach(line => {
      if (!line.trim()) return;
      try {
        const obj = JSON.parse(line);
        if (obj && obj.token && obj.storedName) {
          SHARE_TOKENS.set(obj.token, obj);
        }
      } catch(_){}
    });
  } catch(e) {
    console.warn('Failed to warm share tokens', e);
  }
}

function loadShortLinks() {
  const slFile = path.join(UPLOAD_DIR, 'short_links.jsonl');
  try {
    if (!fs.existsSync(slFile)) return;
    const data = fs.readFileSync(slFile, 'utf8');
    data.split(/\n/).forEach(line => {
      if (!line.trim()) return;
      try {
        const obj = JSON.parse(line);
        if (obj && obj.code && obj.storedName) {
          SHORT_LINKS.set(obj.code, obj);
        }
      } catch(_){ }
    });
  } catch(e) {
    console.warn('Failed to warm short links', e);
  }
}

loadIndexCache();
loadShareTokens();
loadShortLinks();
loadQuotaUsage();

function loadQuotaUsage() {
  try {
    if (!fs.existsSync(QUOTA_FILE)) return;
    const data = fs.readFileSync(QUOTA_FILE, 'utf8');
    const lines = data.split(/\n/);
    const cutoff = Date.now() - 14 * 24 * 60 * 60 * 1000; // keep two weeks of history in memory
    for (const line of lines) {
      if (!line.trim()) continue;
      try {
        const obj = JSON.parse(line);
        if (!obj || !obj.day) continue;
        const identifier = obj.identifier || obj.uploaderIp || obj.ip || obj.uploaderId;
        if (!identifier) continue;
        const ts = obj.time ? Date.parse(obj.time) : Date.now();
        if (Number.isFinite(ts) && ts < cutoff) continue; // skip very old entries
        const key = quotaKey(identifier, obj.day);
        const prev = QUOTA_USAGE.get(key) || 0;
        const inc = Number(obj.bytes);
        const total = Number(obj.total);
        if (Number.isFinite(total) && total >= prev) {
          QUOTA_USAGE.set(key, total);
        } else if (Number.isFinite(inc) && inc > 0) {
          QUOTA_USAGE.set(key, prev + inc);
        }
      } catch (_) { /* skip malformed */ }
    }
  } catch (e) {
    console.warn('Failed to warm quota usage', e);
  }
}

function quotaKey(identifier, day) {
  return `${identifier || ''}:${day}`;
}

function getDailyUsage(identifier, day) {
  return QUOTA_USAGE.get(quotaKey(identifier, day)) || 0;
}

function addDailyUsage(identifier, day, bytes, metadata = {}) {
  const key = quotaKey(identifier, day);
  const prev = QUOTA_USAGE.get(key) || 0;
  const next = prev + bytes;
  QUOTA_USAGE.set(key, next);
  const entry = {
    identifier,
    identifierType: metadata.identifierType,
    uploaderId: metadata.uploaderId,
    ip: metadata.ip,
    day,
    bytes,
    total: next,
    time: new Date().toISOString()
  };
  try {
    fs.appendFile(QUOTA_FILE, JSON.stringify(entry) + '\n', (err) => {
      if (err) console.error('quota append failed', err);
    });
  } catch (e) {
    console.error('quota append exception', e);
  }
  cleanupQuotaMap();
  return next;
}

function cleanupQuotaMap() {
  const cutoff = Date.now() - 14 * 24 * 60 * 60 * 1000;
  for (const [key] of QUOTA_USAGE.entries()) {
    const idx = key.lastIndexOf(':');
    if (idx === -1) continue;
    const day = key.slice(idx + 1);
    if (!day) continue;
    const ts = Date.parse(day + 'T00:00:00Z');
    if (Number.isFinite(ts) && ts < cutoff) {
      QUOTA_USAGE.delete(key);
    }
  }
}

// Helper: sanitize and shorten filename
function sanitizeFilename(originalName) {
  const replaced = originalName
    .replace(/[^A-Za-z0-9._\-\s]/g, '_') // keep simple set
    .replace(/[\\/]/g, '_')
    .replace(/\s+/g, ' ') // collapse whitespace
    .trim();
  // Separate ext
  const maxLen = 120;
  let base = replaced;
  let ext = '';
  const idx = replaced.lastIndexOf('.');
  if (idx > 0 && idx < replaced.length - 1) {
    base = replaced.slice(0, idx);
    ext = replaced.slice(idx + 1).toLowerCase();
  }
  if (base.length > maxLen) base = base.slice(0, maxLen);
  return { base, ext, final: ext ? base + '.' + ext : base, extOnly: ext };
}

// Multer storage config with improved sanitization
const storage = multer.diskStorage({
  destination: function (req, file, cb) { cb(null, UPLOAD_DIR); },
  filename: function (req, file, cb) {
    const unique = Date.now().toString(36) + '-' + Math.random().toString(36).slice(2,8);
    const { final } = sanitizeFilename(file.originalname || 'file');
    cb(null, unique + '-' + final);
  }
});

// Track cumulative size per request (rough) using multer fileFilter and an accumulator
function makeFileFilter() {
  return function (req, file, cb) {
    if (!req.__totalBytes) req.__totalBytes = 0;
    const { extOnly } = sanitizeFilename(file.originalname || '');
    const lowerExt = (extOnly || '').toLowerCase();

    console.log(`[FILE_FILTER] File: ${file.originalname}, ext: ${lowerExt}, mime: ${file.mimetype}, ALLOW_ALL: ${ALLOW_ALL}`);

    if (!ALLOW_ALL) {
      console.log('[FILE_FILTER] Checking restrictions...');
      // Extension check
      if (!ALLOWED_EXTENSIONS.includes(lowerExt)) {
        console.log(`[FILE_FILTER] Extension ${lowerExt} not allowed`);
        req.__validationError = 'FILE_TYPE_DISALLOWED';
        return cb(null, false);
      }
      // MIME check (prefix match or direct match)
      const mime = (file.mimetype || '').toLowerCase();
      if (!ALLOWED_MIME_PREFIXES.includes(mime)) {
        console.log(`[FILE_FILTER] MIME ${mime} not allowed`);
        req.__validationError = 'MIME_DISALLOWED';
        return cb(null, false);
      }
    } else {
      console.log('[FILE_FILTER] ALLOW_ALL is true - skipping restrictions');
    }
    // NOTE: We cannot know file.size yet (streaming). We'll rely on per-file limit for big files.
    // Cumulative check is approximate; we increment after file complete in a custom handler below if desired.
    if (TOTAL_REQUEST_LIMIT_BYTES && req.__totalBytes > TOTAL_REQUEST_LIMIT_BYTES) {
      req.__validationError = 'TOTAL_SIZE_EXCEEDED';
      return cb(null, false);
    }
    console.log('[FILE_FILTER] File accepted');
    cb(null, true);
  };
}

const upload = multer({
  storage,
  // No fileSize limit when PER_FILE_LIMIT_BYTES is null
  limits: PER_FILE_LIMIT_BYTES ? { fileSize: PER_FILE_LIMIT_BYTES } : undefined,
  fileFilter: makeFileFilter()
});

// Metadata index file (JSON Lines). Each line: {time, originalName, storedName, size, mime, hash}
const INDEX_FILE = path.join(UPLOAD_DIR, 'index.jsonl');
const SHARE_TOKENS_FILE = path.join(UPLOAD_DIR, 'share_tokens.jsonl');
const SHORT_LINKS_FILE = path.join(UPLOAD_DIR, 'short_links.jsonl');

// Basic health check (multiple aliases to survive path rewrites or stripping)
const healthHandler = (req, res) => {
  res.json({ ok: true, time: new Date().toISOString(), path: req.originalUrl });
};
app.get(['/api/health','/anyfile/api/health','/health','/anyfile/health'], healthHandler);
// Mini-site API health
app.get(['/api/site/health','/anyfile/api/site/health'], (req, res) => {
  res.json({ ok: true, feature: 'site-publish', path: req.originalUrl });
});

// Debug endpoint to inspect what the server actually receives via proxy
app.get(['/api/whoami','/anyfile/api/whoami'], (req, res) => {
  res.json({
    ok: true,
    method: req.method,
    originalUrl: req.originalUrl,
    path: req.path,
    headers: {
      host: req.headers.host,
      'x-forwarded-host': req.headers['x-forwarded-host'],
      'x-forwarded-proto': req.headers['x-forwarded-proto'],
      'x-forwarded-for': req.headers['x-forwarded-for']
    }
  });
});

// Upload endpoint (root and prefixed)
app.post(['/api/upload','/anyfile/api/upload'], upload.array('files', 20), async (req, res) => {
  console.log(`[UPLOAD] Started processing ${req.files?.length || 0} files`);
  if (req.__validationError) {
    console.log(`[UPLOAD] Validation error: ${req.__validationError}`);
    const map = {
      FILE_TYPE_DISALLOWED: 415,
      MIME_DISALLOWED: 415,
      TOTAL_SIZE_EXCEEDED: 413
    };
    const status = map[req.__validationError] || 400;
    return res.status(status).json({ ok: false, error: req.__validationError });
  }
  if (!req.files || req.files.length === 0) {
    console.log('[UPLOAD] No files received');
    return res.status(400).json({ ok: false, error: 'NO_FILES' });
  }

  const tier = req.anysendTier === 'premium' ? 'premium' : 'standard';
  const uploaderId = req.anysendUploaderId || '';
  const uploaderIp = resolveClientIp(req);
  const quotaIdentifier = uploaderIp || uploaderId;
  const quotaIdentifierType = uploaderIp ? 'ip' : 'id';
  const nowMs = Date.now();
  const todayKey = new Date(nowMs).toISOString().slice(0, 10);
  const totalBytes = req.files.reduce((sum, file) => sum + (file.size || 0), 0);

  if (tier !== 'premium') {
    const used = getDailyUsage(quotaIdentifier, todayKey);
    if (used + totalBytes > DAILY_LIMIT_BYTES) {
      for (const f of req.files) {
        try { fs.unlinkSync(f.path); } catch (_) { /* ignore */ }
      }
      const quota = buildQuotaInfo(quotaIdentifier, used, todayKey, {
        identifierType: quotaIdentifierType,
        ip: uploaderIp,
        uploaderId
      });
      return res.status(403).json({ ok: false, error: 'DAILY_LIMIT_EXCEEDED', limit: DAILY_LIMIT_BYTES, used, remaining: quota ? quota.remaining : Math.max(0, DAILY_LIMIT_BYTES - used), quota, tier });
    }
  }

  const uploadOptions = parseUploadOptions(req.body || {});
  const expiry = resolveExpiry(tier, uploadOptions, nowMs);
  const deleteAfterDownload = !!expiry.deleteAfterDownload;
  const maxDownloads = deleteAfterDownload ? 1 : null;
  const remainingDownloads = deleteAfterDownload ? 1 : null;
  const expireAt = expiry.expireAt || null;
  const expireDays = expiry.expireDays != null ? expiry.expireDays : null;

  const responseFiles = [];
  const SKIP_HASH = true;
  console.log(`[UPLOAD] Processing ${req.files.length} files, tier=${tier}, SKIP_HASH=${SKIP_HASH}`);

  for (const f of req.files) {
    let digest = 'skipped';
    if (!SKIP_HASH) {
      const hash = crypto.createHash('sha256');
      try {
        await new Promise((resolve, reject) => {
          const stream = fs.createReadStream(f.path);
          stream.on('data', (chunk) => hash.update(chunk));
          stream.on('error', reject);
          stream.on('end', resolve);
        });
        digest = hash.digest('hex');
      } catch (e) {
        console.error('Hashing failed for', f.filename, e);
        return res.status(500).json({ ok: false, error: 'HASH_FAILED' });
      }
    }

    const legacyUrl = '/uploads/' + encodeURIComponent(f.filename);
    const primaryUrl = '/api/uploads/' + encodeURIComponent(f.filename);
    const prefixedUrl = '/anyfile/api/uploads/' + encodeURIComponent(f.filename);
    const downloadUrl = '/api/download/' + encodeURIComponent(f.filename);

    const meta = {
      time: new Date().toISOString(),
      originalName: f.originalname,
      storedName: f.filename,
      size: f.size,
      mime: f.mimetype,
      hash: digest,
      uploaderId,
      ip: uploaderIp,
      tier,
      expireAt,
      expireDays,
      deleteAfterDownload,
      maxDownloads,
      remainingDownloads,
      downloadCount: 0
    };

    writeMetaUpdate(f.filename, meta);

    responseFiles.push({
      field: f.fieldname,
      originalName: f.originalname,
      storedName: f.filename,
      size: f.size,
      mime: f.mimetype,
      hash: digest,
      url: downloadUrl,
      downloadUrl,
      primaryUrl,
      legacyUrl,
      prefixedUrl,
      expireAt,
      expireDays,
      deleteAfterDownload
    });
  }

  let quotaInfo = null;
  if (tier !== 'premium') {
    const total = addDailyUsage(quotaIdentifier, todayKey, totalBytes, {
      identifierType: quotaIdentifierType,
      ip: uploaderIp,
      uploaderId
    });
    quotaInfo = buildQuotaInfo(quotaIdentifier, total, todayKey, {
      identifierType: quotaIdentifierType,
      ip: uploaderIp,
      uploaderId
    });
  }

  console.log(`[UPLOAD] Sending response with ${responseFiles.length} files (tier=${tier})`);
  const payload = { ok: true, count: responseFiles.length, files: responseFiles, tier };
  if (quotaInfo) payload.quota = quotaInfo;
  res.json(payload);
});

// ------------------- P Directory Publish ----------------------
// POST /api/p/publish (multipart/form-data with files)
// Publishes files to the /p directory
app.post(['/api/p/publish','/anyfile/api/p/publish'], upload.array('files', 100), async (req, res) => {
  if (!req.files || req.files.length === 0) return res.status(400).json({ ok:false, error:'NO_FILES' });
  
  try {
    // Ensure /p directory exists
    if (!fs.existsSync(P_DIR)) {
      fs.mkdirSync(P_DIR, { recursive: true, mode: 0o755 });
    }
    
    const written = [];
    for (const f of req.files) {
      // Sanitize the filename to be safe for web
      const safe = (f.originalname || 'file').replace(/[^A-Za-z0-9._\-]/g, '_');
      const dest = path.join(P_DIR, safe);
      
      try {
        const src = f.path && fs.existsSync(f.path) ? f.path : path.join(UPLOAD_DIR, f.filename);
        fs.copyFileSync(src, dest);
        // Ensure file is readable by web server
        fs.chmodSync(dest, 0o644);
        written.push({ name: safe, size: f.size });
      } catch(err) {
        console.error('File publish error:', err);
        return res.status(500).json({ ok:false, error:'WRITE_ERROR', message: err.message });
      }
    }
    
    return res.json({ 
      ok: true, 
      count: written.length, 
      files: written,
      url: `${req.protocol}://${req.hostname}/p/` 
    });
  } catch(err) {
    console.error('P directory publish error:', err);
    return res.status(500).json({ ok:false, error:'SERVER_ERROR', message: err.message });
  }
});

// ------------------- Mini Site Publish ----------------------
// POST /api/site/publish?name=paul  (multipart/form-data with files)
app.post(['/api/site/publish','/anyfile/api/site/publish'], upload.array('files', 100), async (req, res) => {
  const nameRaw = (req.query.name || '').toString();
  const name = nameRaw.replace(/[^a-z0-9_-]/gi,'').toLowerCase();
  if (!name) return res.status(400).json({ ok:false, error:'NAME_REQUIRED' });
  if (!req.files || req.files.length === 0) return res.status(400).json({ ok:false, error:'NO_FILES' });
  // Require an index.html among uploaded files, unless there's exactly one HTML file which we'll promote to index.html
  const hasIndex = req.files.some(f => /(^|\/)index\.html$/i.test(f.originalname || ''));
  let promoteSingleHtmlToIndex = false;
  let singleHtmlOriginal = null;
  if (!hasIndex) {
    const htmlFiles = req.files.filter(f => /\.html?$/i.test(f.originalname || ''));
    if (htmlFiles.length === 1) {
      promoteSingleHtmlToIndex = true;
      singleHtmlOriginal = htmlFiles[0].originalname;
    } else {
      return res.status(400).json({ ok:false, error:'NO_INDEX_HTML' });
    }
  }
  const siteDir = path.join(SITES_DIR, name);
  try { fs.mkdirSync(siteDir, { recursive: true }); } catch(_) {}
  const written = [];
  for (const f of req.files) {
    // We received files into uploads/ with unique names; move/copy to the site folder with sanitized original names
    const safe = (f.originalname || 'file').replace(/[^A-Za-z0-9._\-\/]/g,'_').replace(/[\\]/g,'/');
    let rel = safe.split('/').filter(seg => seg && seg !== '.' && seg !== '..').join('/');
    // If we are promoting the single HTML file to index.html, override its destination name
    if (promoteSingleHtmlToIndex && f.originalname === singleHtmlOriginal) {
      rel = 'index.html';
    }
    const dest = path.join(siteDir, rel);
    // Ensure subdirectories
    const dir = path.dirname(dest);
    try { fs.mkdirSync(dir, { recursive: true }); } catch(_) {}
    try {
      const src = f.path && fs.existsSync(f.path) ? f.path : path.join(UPLOAD_DIR, f.filename);
      // Ensure the destination stays within siteDir
      const resolvedDest = path.resolve(dest);
      if (!resolvedDest.startsWith(path.resolve(siteDir) + path.sep) && resolvedDest !== path.resolve(siteDir)) {
        return res.status(400).json({ ok:false, error:'BAD_PATH' });
      }
      fs.copyFileSync(src, resolvedDest);
      // Remove temp uploaded file to avoid polluting uploads root
      try { if (src && src !== resolvedDest) fs.unlink(src, () => {}); } catch(_) {}
    } catch(e) {
      return res.status(500).json({ ok:false, error:'COPY_FAILED', file: f.originalname });
    }
    written.push({ name: rel, size: f.size });
  }
  res.json({ ok:true, name, files: written, url: `/${name}` });
});

// Serve files from the /p directory with auto-directory listing
app.use('/p', (req, res, next) => {
  const requestPath = req.path || '/';
  const ensureDir = () => {
    try { fs.mkdirSync(P_DIR, { recursive: true, mode: 0o755 }); } catch (_) {}
  };
  ensureDir();

  const noCache = (response) => {
    response.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    response.setHeader('Pragma', 'no-cache');
    response.setHeader('Expires', '0');
  };

  if (requestPath === '/' || requestPath === '') {
    const indexFile = path.join(P_DIR, 'index.html');
    if (fs.existsSync(indexFile)) {
      noCache(res);
      return res.sendFile(indexFile, err => err && next(err));
    }
    try {
      const files = fs.readdirSync(P_DIR)
        .filter(file => !file.startsWith('.'))
        .map(file => {
          const filePath = path.join(P_DIR, file);
          const stats = fs.statSync(filePath);
          return {
            name: file,
            isDirectory: stats.isDirectory(),
            size: stats.size,
            mtime: stats.mtime
          };
        });

      const html = `<!DOCTYPE html>
<html>
<head>
  <title>p.anyfile.uk - Files</title>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>
    body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
    h1 { color: #2A7B9B; }
    .files { margin-top: 20px; }
    .file-list { list-style: none; padding: 0; }
    .file-list li { padding: 10px; border-bottom: 1px solid #eee; }
    .file-list a { color: #2A7B9B; text-decoration: none; }
    .file-list a:hover { text-decoration: underline; }
    .empty { color: #666; font-style: italic; }
  </style>
</head>
<body>
  <h1>p.anyfile.uk</h1>
  <div class="files">
    <h2>Files</h2>
    ${files.length === 0 ? '<p class="empty">No files available.</p>' : 
    `<ul class="file-list">
      ${files.map(file => 
        `<li><a href="/p/${file.name}">${file.name}</a> 
        (${file.isDirectory ? 'Directory' : formatSize(file.size)}, 
        ${new Date(file.mtime).toLocaleString()})</li>`
      ).join('')}
    </ul>`}
  </div>
  <p><a href="/">Back to Anyfile</a></p>
</body>
</html>`;

      res.setHeader('Content-Type', 'text/html');
      noCache(res);
      return res.send(html);
    } catch (err) {
      console.error('Error generating /p directory listing:', err);
    }
  }

  const staticMiddleware = express.static(P_DIR, {
    fallthrough: true,
    dotfiles: 'deny',
    etag: false,
    cacheControl: false,
    maxAge: 0,
    setHeaders(res) { noCache(res); }
  });

  staticMiddleware(req, res, (err) => {
    if (err) return next(err);
    if (requestPath === '/' || requestPath === '') return next();
    return res.status(404).type('text/html').send('<!DOCTYPE html><html><body><h1>Not Found</h1></body></html>');
  });
});

// Helper function to format file sizes
function formatSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  else if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  else if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
  else return (bytes / (1024 * 1024 * 1024)).toFixed(1) + ' GB';
}

function getMetaForStoredName(storedName) {
  if (!storedName) return null;
  let meta = INDEX_CACHE.get(storedName);
  if (meta && !meta.deleted && isExpired(meta)) {
    softDeleteStoredFile(storedName, meta, 'expired');
    meta = INDEX_CACHE.get(storedName);
  }
  if (meta && meta.deleted) return null;
  if (meta) return meta;
  try {
    if (!fs.existsSync(INDEX_FILE)) return null;
    const data = fs.readFileSync(INDEX_FILE, 'utf8');
    const lines = data.trim().split(/\n/);
    for (let i = lines.length - 1; i >= 0; i--) {
      const line = lines[i];
      if (!line || !line.trim()) continue;
      try {
        const obj = JSON.parse(line);
        if (obj && obj.storedName === storedName) {
          INDEX_CACHE.set(storedName, obj);
          meta = obj;
          break;
        }
      } catch (_) { /* ignore malformed line */ }
    }
  } catch (_) { /* ignore */ }
  if (meta && !meta.deleted && isExpired(meta)) {
    softDeleteStoredFile(storedName, meta, 'expired');
    meta = INDEX_CACHE.get(storedName);
  }
  if (!meta || meta.deleted) return null;
  return meta;
}

function findShareTokenRecord(storedName, uploaderId) {
  for (const record of SHARE_TOKENS.values()) {
    if (record && record.storedName === storedName) {
      if (!uploaderId || record.uploaderId === uploaderId) {
        return record;
      }
    }
  }
  return null;
}

function findShortLinkRecord(storedName, uploaderId) {
  for (const record of SHORT_LINKS.values()) {
    if (record && record.storedName === storedName) {
      if (!uploaderId || record.uploaderId === uploaderId) {
        return record;
      }
    }
  }
  return null;
}

function writeMetaUpdate(storedName, meta) {
  if (!storedName || !meta) return;
  const toStore = { ...meta, storedName };
  INDEX_CACHE.set(storedName, toStore);
  try {
    fs.appendFile(INDEX_FILE, JSON.stringify(toStore) + '\n', (err) => {
      if (err) console.error('index append failed', err);
    });
  } catch (e) {
    console.error('index append exception', e);
  }
}

function softDeleteStoredFile(storedName, meta, reason) {
  if (!storedName) return;
  const now = new Date().toISOString();
  const deletedMeta = {
    ...(meta || {}),
    storedName,
    time: now,
    deleted: true,
    deleteReason: reason || 'deleted',
    deletedAt: now
  };
  writeMetaUpdate(storedName, deletedMeta);
  const fullPath = path.join(UPLOAD_DIR, storedName);
  try {
    fs.unlink(fullPath, () => {});
  } catch (_) { /* ignore */ }
}

function recordDownload(storedName, meta) {
  if (!storedName || !meta || meta.deleted) return;
  const now = new Date().toISOString();
  const updated = {
    ...meta,
    storedName,
    time: now,
    downloadCount: (meta.downloadCount || 0) + 1,
    lastDownloadAt: now
  };
  if (typeof meta.remainingDownloads === 'number') {
    const remaining = meta.remainingDownloads - 1;
    updated.remainingDownloads = remaining;
    if (remaining <= 0) {
      softDeleteStoredFile(storedName, updated, 'max-downloads');
      return;
    }
  }
  writeMetaUpdate(storedName, updated);
}

function parseUploadOptions(body) {
  if (!body) return {};
  const raw = body['upload-options'] ?? body['uploadOptions'] ?? body['options'];
  if (!raw) return {};
  if (typeof raw === 'object') return raw;
  if (typeof raw === 'string') {
    try {
      return JSON.parse(raw);
    } catch (e) {
      console.warn('Failed to parse upload options JSON', e);
      return {};
    }
  }
  return {};
}

function resolveExpiry(tier, options, nowMs) {
  const tierValue = tier === 'premium' ? 'premium' : 'standard';
  const baseMs = Number.isFinite(nowMs) ? nowMs : Date.now();
  let expireDaysRaw = options.expireDays;
  if (typeof expireDaysRaw === 'string') {
    const lower = expireDaysRaw.trim().toLowerCase();
    if (lower === 'never' || lower === 'none') {
      expireDaysRaw = 0;
    } else if (/^\d+$/.test(lower)) {
      expireDaysRaw = parseInt(lower, 10);
    } else {
      const num = Number(lower);
      expireDaysRaw = Number.isFinite(num) ? num : null;
    }
  }
  if (typeof expireDaysRaw !== 'number' || !Number.isFinite(expireDaysRaw)) {
    expireDaysRaw = null;
  }
  if (expireDaysRaw != null && expireDaysRaw < 0) expireDaysRaw = null;

  let expireDays = null;
  let expireAt = null;

  if (tierValue === 'standard') {
    const days = expireDaysRaw && expireDaysRaw > 0 ? Math.min(expireDaysRaw, STANDARD_EXPIRE_DAYS) : STANDARD_EXPIRE_DAYS;
    expireDays = days;
    expireAt = new Date(baseMs + days * DAY_MS).toISOString();
  } else {
    if (expireDaysRaw === 0) {
      expireDays = null;
      expireAt = null;
    } else if (expireDaysRaw && expireDaysRaw > 0) {
      expireDays = expireDaysRaw;
      expireAt = new Date(baseMs + expireDaysRaw * DAY_MS).toISOString();
    } else if (options.expireAt) {
      const parsed = Date.parse(options.expireAt);
      if (Number.isFinite(parsed) && parsed > baseMs) {
        expireAt = new Date(parsed).toISOString();
        expireDays = Math.max(0, Math.round((parsed - baseMs) / DAY_MS));
      }
    } else {
      expireDays = null;
      expireAt = null;
    }
  }

  const deleteAfterDownload = !!(options.deleteAfterDownload || options.deleteOnDownload || options.deleteAfterFirstDownload);

  return {
    expireAt,
    expireDays,
    deleteAfterDownload
  };
}

function randomId(length) {
  let out = '';
  while (out.length < length) {
    out += crypto.randomBytes(6).toString('base64').replace(/[^A-Za-z0-9]/g, '');
  }
  return out.slice(0, length);
}

function createShareToken(storedName, uploaderId) {
  let token;
  do {
    token = randomId(24);
  } while (SHARE_TOKENS.has(token));
  const record = {
    token,
    storedName,
    uploaderId,
    created: new Date().toISOString()
  };
  SHARE_TOKENS.set(token, record);
  try {
    fs.appendFile(SHARE_TOKENS_FILE, JSON.stringify(record) + '\n', (err) => {
      if (err) console.error('share token append failed', err);
    });
  } catch (e) {
    console.error('share token append exception', e);
  }
  return record;
}

function createShortLink(tokenRecord, storedName, uploaderId) {
  let code;
  do {
    code = randomId(8).slice(0, 8);
  } while (SHORT_LINKS.has(code));
  const record = {
    code,
    token: tokenRecord.token,
    storedName,
    uploaderId,
    created: new Date().toISOString()
  };
  SHORT_LINKS.set(code, record);
  try {
    fs.appendFile(SHORT_LINKS_FILE, JSON.stringify(record) + '\n', (err) => {
      if (err) console.error('short link append failed', err);
    });
  } catch (e) {
    console.error('short link append exception', e);
  }
  return record;
}

function refreshShortLinkToken(record, tokenRecord) {
  if (!record || !record.code) {
    return createShortLink(tokenRecord, tokenRecord.storedName, tokenRecord.uploaderId);
  }
  const updated = {
    ...record,
    token: tokenRecord.token,
    updated: new Date().toISOString()
  };
  SHORT_LINKS.set(updated.code, updated);
  try {
    fs.appendFile(SHORT_LINKS_FILE, JSON.stringify(updated) + '\n', (err) => {
      if (err) console.error('short link refresh append failed', err);
    });
  } catch (e) {
    console.error('short link refresh append exception', e);
  }
  return updated;
}

function makeAbsoluteUrl(req, relativePath, opts = {}) {
  const options = opts || {};
  const forwardedProto = (req.headers['x-forwarded-proto'] || '').split(',')[0].trim();
  const proto = forwardedProto || req.protocol || 'https';
  const forwardedHost = (req.headers['x-forwarded-host'] || '').split(',')[0].trim();
  let host = forwardedHost || req.headers.host || req.hostname || '';
  if (options.preferFilesSubdomain && host) {
    host = host.replace(/^(upload\.|api\.)/i, 'files.');
  }
  if (!host) return relativePath;
  return `${proto}://${host.replace(/\/$/, '')}${relativePath}`;
}

// Serve mini sites at /:name (only those under uploads/sites)
app.use('/:siteName', (req, res, next) => {
  const n = (req.params.siteName || '').toString();
  // Avoid conflicting with known API or reserved paths
  if (['api','anyfile','uploads','f','p','s'].includes(n)) return next();
  const dir = path.join(SITES_DIR, n);
  if (!fs.existsSync(dir)) return next();
  // If requesting the root of site, serve index.html; else static
  if (req.path === '/' || req.path === '') {
    const idx = path.join(dir, 'index.html');
    if (fs.existsSync(idx)) return res.sendFile(idx);
  }
  express.static(dir, { fallthrough: true })(req, res, next);
});

// ---------------------------------------------
// Files listing endpoint: returns recent uploads (metadata only)
// GET /api/files?limit=50
// ---------------------------------------------
function readLastLines(filePath, maxLines, maxBytes) {
  return new Promise((resolve, reject) => {
    fs.stat(filePath, (err, stat) => {
      if (err) {
        if (err.code === 'ENOENT') return resolve([]);
        return reject(err);
      }
      const fileSize = stat.size;
      const chunkSize = 8192;
      let pos = fileSize;
      let buffer = Buffer.alloc(0);
      let lines = [];
      const fdOpen = fs.createReadStream(filePath, { start: Math.max(0, fileSize - Math.min(maxBytes, fileSize)), end: fileSize });
      fdOpen.on('data', d => { buffer = Buffer.concat([buffer, d]); });
      fdOpen.on('error', reject);
      fdOpen.on('end', () => {
        const text = buffer.toString('utf8');
        // Split and filter empty
        lines = text.split(/\n/).filter(l => l.trim().length);
        // We only want the last maxLines lines
        if (lines.length > maxLines) lines = lines.slice(lines.length - maxLines);
        resolve(lines);
      });
    });
  });
}

app.get(['/api/files','/anyfile/api/files'], async (req, res) => {
  const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 50));
  try {
    const rawLines = await readLastLines(INDEX_FILE, limit, 512 * 1024); // read up to last 512KB
    const entries = [];
    for (let i = rawLines.length - 1; i >= 0; i--) { // newest last in file, so reverse iterate
      const line = rawLines[i];
      try {
        const obj = JSON.parse(line);
        const dl = '/api/download/' + encodeURIComponent(obj.storedName);
        obj.url = dl;
        obj.downloadUrl = dl;
        // Attach a synthetic recency index so we can resolve newest properly later
        obj.__recency = Date.now() + i; // not exact timestamp order but ensures stable ordering
        entries.push(obj);
      } catch (e) {
        // skip malformed
      }
    }
    // Filter: show ONLY this user's own uploads (privacy of listing)
    const userId = req.anysendUploaderId || '';
    let resultEntries;
    if (req.query.all === '1') {
      // explicit override to view all (could restrict later)
      resultEntries = entries;
    } else {
      resultEntries = userId ? entries.filter(e => e.uploaderId === userId) : [];
    }
    // Build a dedupe map keeping the most recent non-deleted state; since we reversed, need to compare timestamps
    const dedup = new Map();
    for (const e of resultEntries) {
      const existing = dedup.get(e.storedName);
      if (!existing) {
        dedup.set(e.storedName, e);
      } else {
        // Choose the one that is not deleted; if both or one deleted, keep the one with later time
        const existingTime = Date.parse(existing.time || '') || 0;
        const currentTime = Date.parse(e.time || '') || 0;
        if (currentTime >= existingTime) {
          dedup.set(e.storedName, e);
        }
      }
    }
    let final = Array.from(dedup.values());
    // Final filtering: remove deleted or expired
    final = final.filter(e => !e.deleted && !isExpired(e));
    const snapshot = getQuotaSnapshotForRequest(req);
    const responseBody = { ok: true, count: final.length, files: final };
    if (snapshot) {
      if (snapshot.tier) responseBody.tier = snapshot.tier;
      if (Object.prototype.hasOwnProperty.call(snapshot, 'quota')) {
        responseBody.quota = snapshot.quota;
      }
    }
    res.json(responseBody);
  } catch (e) {
    console.error('files listing failed', e);
    res.status(500).json({ ok: false, error: 'LIST_FAILED' });
  }
});

// Debug route to list registered routes (not for production hardening; can remove later)
app.get('/api/debug/routes', (req, res) => {
  try {
    const routes = [];
    app._router.stack.forEach(layer => {
      if (layer.route && layer.route.path) {
        const methods = Object.keys(layer.route.methods).filter(m => layer.route.methods[m]);
        routes.push({ path: layer.route.path, methods });
      } else if (layer.name === 'router' && layer.handle.stack) {
        layer.handle.stack.forEach(r => {
          if (r.route) {
            const methods = Object.keys(r.route.methods).filter(m => r.route.methods[m]);
            routes.push({ path: r.route.path, methods });
          }
        });
      }
    });
    res.json({ ok: true, routes });
  } catch (e) {
    res.status(500).json({ ok: false, error: 'ROUTE_ENUM_FAILED' });
  }
});

// ---------------- Private / Guarded Download & Share Tokens -----------------
// Remove public static exposure of raw upload directory for privacy.

// Improved file sender with:
//  - Content-Length header
//  - Range requests (resume / partial)
//  - Cache-Control tuned for public vs private
//  - Accept-Ranges header
//  - Optional immutable caching for shared links
function sendFileWithDisposition(req, res, fullPath, originalName, mime, opts = {}) {
  let stat;
  try { stat = fs.statSync(fullPath); } catch { return res.status(404).end(); }
  const size = stat.size;
  const safeName = originalName || path.basename(fullPath);
  const isHead = req.method === 'HEAD';
  const isPublic = !!opts.public; // shared link / token
  // Headers
  res.setHeader('Content-Type', mime || 'application/octet-stream');
  res.setHeader('Content-Disposition', `attachment; filename="${safeName.replace(/"/g,'')}"`);
  res.setHeader('Accept-Ranges', 'bytes');
  if (isPublic) {
    // Long cache for immutable shared file content
    res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
  } else {
    res.setHeader('Cache-Control', 'private, max-age=600');
  }
  let start = 0;
  let end = size - 1;
  let statusCode = 200;
  const range = req.headers['range'];
  if (range && /^bytes=/.test(range)) {
    const m = range.replace(/bytes=/,'').split(',')[0].trim();
    const parts = m.split('-');
    const s = parts[0] ? parseInt(parts[0],10) : 0;
    const e = parts[1] ? parseInt(parts[1],10) : (size -1);
    if (!isNaN(s) && !isNaN(e) && s <= e && e < size) {
      start = s; end = e; statusCode = 206;
      res.setHeader('Content-Range', `bytes ${start}-${end}/${size}`);
    }
  }
  const chunkLen = (end - start) + 1;
  res.setHeader('Content-Length', chunkLen);
  if (isHead) return res.status(statusCode).end();
  res.status(statusCode);
  const stream = fs.createReadStream(fullPath, { start, end });
  // Optional debug download throughput logging
  const DEBUG_DOWNLOAD = true; // Change to false to disable download debug logging
  if (DEBUG_DOWNLOAD) {
    const began = Date.now();
    let sent = 0;
    let lastLog = began;
    stream.on('data', (chunk) => {
      sent += chunk.length;
      const now = Date.now();
      if (now - lastLog >= 1000) {
        const secs = (now - began) / 1000;
        const rate = sent / secs;
        console.log(`[DOWNLOAD_DEBUG] ${sent} bytes ${(sent/1024/1024).toFixed(2)}MB in ${secs.toFixed(1)}s avg ${(rate/1024/1024).toFixed(2)}MB/s (${safeName})`);
        lastLog = now;
      }
    });
    stream.on('end', () => {
      const secs = (Date.now() - began) / 1000;
      const rate = sent / secs;
      console.log(`[DOWNLOAD_DEBUG] COMPLETE ${sent} bytes ${(sent/1024/1024).toFixed(2)}MB in ${secs.toFixed(2)}s avg ${(rate/1024/1024).toFixed(2)}MB/s (${safeName})`);
    });
  }
  stream.on('error', () => { if (!res.headersSent) res.status(500); res.end(); });
  stream.pipe(res);
}

const shareBodyParser = express.json({ limit: '10kb' });

function renderLandingPageHtml(options) {
  const opts = options || {};
  const fileName = escapeHtml(opts.fileName || 'Download ready');
  const sizeText = opts.sizeText ? escapeHtml(opts.sizeText) : '';
  const expireText = opts.expireText ? escapeHtml(opts.expireText) : '';
  const remainingText = typeof opts.remainingDownloads === 'number' ? escapeHtml(`${opts.remainingDownloads} download${opts.remainingDownloads === 1 ? '' : 's'} left`) : '';
  const metaParts = [sizeText, remainingText, expireText].filter(Boolean);
  const metaHtml = metaParts.length ? `<p class="details">${metaParts.join(' • ')}</p>` : '';
  const downloadHref = escapeHtml(opts.downloadPath || opts.downloadAbsoluteUrl || '#');
  const downloadAttr = opts.fileName ? ` download="${escapeHtml(opts.fileName)}"` : '';
  const canonical = opts.downloadAbsoluteUrl ? `<link rel="canonical" href="${escapeHtml(opts.downloadAbsoluteUrl)}">` : '';
  const note = opts.deleteAfterDownload ? '<p class="note">This is a one-time download link. The file will be deleted after you download it.</p>' : '';

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>${fileName} — AnySend</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
${canonical}
<style>
  :root { color-scheme: light dark; font-family: "Segoe UI", system-ui, sans-serif; background: #0f1420; color: #111; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 2rem; background: linear-gradient(135deg,#101522,#1f2937); }
  main { background: rgba(255,255,255,0.95); color: #111; padding: 2rem 2.5rem; border-radius: 18px; max-width: 460px; width: 100%; box-shadow: 0 20px 45px rgba(15,23,42,0.35); }
  @media (prefers-color-scheme: dark) {
    body { background: radial-gradient(circle at top,#1f2937,#0f172a 60%); }
    main { background: rgba(15,23,42,0.92); color: #f8fafc; box-shadow: 0 18px 50px rgba(2,6,23,0.55); }
  }
  h1 { font-size: 1.5rem; margin: 0 0 1rem 0; }
  .filename { font-weight: 600; font-size: 1.1rem; margin-bottom: 0.5rem; word-break: break-word; }
  .details { margin: 0 0 1.2rem 0; color: rgba(15,23,42,0.66); font-size: 0.95rem; }
  @media (prefers-color-scheme: dark) { .details { color: rgba(226,232,240,0.74); } }
  .download-btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.75rem 1.6rem; background: linear-gradient(135deg,#2563eb,#7c3aed); color: #fff; text-decoration: none; border-radius: 999px; font-weight: 600; transition: transform 0.18s ease, box-shadow 0.18s ease; box-shadow: 0 14px 25px rgba(37,99,235,0.35); }
  .download-btn:hover { transform: translateY(-1px); box-shadow: 0 18px 32px rgba(124,58,237,0.4); }
  .note { margin-top: 1.4rem; font-size: 0.9rem; color: rgba(15,23,42,0.65); }
  @media (prefers-color-scheme: dark) { .note { color: rgba(226,232,240,0.8); } }
</style>
</head>
<body>
<main>
  <h1>Download ready</h1>
  <p class="filename">${fileName}</p>
  ${metaHtml || '<p class="details">Secure file transfer via AnySend</p>'}
  <a class="download-btn" href="${downloadHref}" rel="noopener"${downloadAttr}>Download now</a>
  ${note}
</main>
</body>
</html>`;
}

function renderLandingNotFoundHtml() {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Link unavailable — AnySend</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<style>
  :root { color-scheme: light dark; font-family: "Segoe UI", system-ui, sans-serif; }
  body { margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center; background: #0f172a; color: #f8fafc; padding: 2rem; }
  main { background: rgba(15,23,42,0.9); padding: 2rem 2.5rem; border-radius: 20px; max-width: 420px; width: 100%; box-shadow: 0 25px 35px rgba(2,6,23,0.55); text-align: center; }
  h1 { margin: 0 0 1rem 0; font-size: 1.6rem; }
  p { margin: 0.4rem 0; color: rgba(226,232,240,0.86); }
  a { color: #60a5fa; text-decoration: none; }
</style>
</head>
<body>
<main>
  <h1>Link unavailable</h1>
  <p>This transfer link may have expired or the file was already downloaded.</p>
  <p><a href="/">Return to AnySend</a></p>
</main>
</body>
</html>`;
}

function buildShareResponse(req, storedName, tokenRecord, shortRecord, meta) {
  const shareUrl = '/api/d/' + encodeURIComponent(tokenRecord.token);
  const shortUrl = '/f/' + encodeURIComponent(shortRecord.code);
  const absoluteUrl = makeAbsoluteUrl(req, shortUrl, { preferFilesSubdomain: true });
  const landingUrl = '/s/' + encodeURIComponent(shortRecord.code);
  const landingAbsoluteUrl = makeAbsoluteUrl(req, landingUrl, { preferFilesSubdomain: true });
  const downloadAbsoluteUrl = makeAbsoluteUrl(req, shareUrl, { preferFilesSubdomain: true });
  const metaInfo = meta && !meta.deleted ? meta : getMetaForStoredName(storedName);
  const resp = {
    ok: true,
    storedName,
    token: tokenRecord.token,
    code: shortRecord.code,
    shareUrl,
    shortUrl,
    absoluteUrl,
    landingUrl,
    landingAbsoluteUrl,
    downloadAbsoluteUrl
  };
  resp.downloadUrl = shareUrl;
  if (metaInfo) {
    resp.expireAt = metaInfo.expireAt || null;
    resp.expireDays = metaInfo.expireDays != null ? metaInfo.expireDays : null;
    resp.deleteAfterDownload = !!metaInfo.deleteAfterDownload;
    if (typeof metaInfo.remainingDownloads === 'number') {
      resp.remainingDownloads = metaInfo.remainingDownloads;
    }
  }
  return resp;
}

function handleShareRequest(req, res) {
  const id = req.params.id;
  const meta = getMetaForStoredName(id);
  if (!meta || meta.deleted || isExpired(meta)) {
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }
  if (meta.uploaderId !== req.anysendUploaderId) {
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }
  const fullPath = path.join(UPLOAD_DIR, id);
  if (!fs.existsSync(fullPath)) {
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }

  let tokenRecord = findShareTokenRecord(id, meta.uploaderId);
  if (!tokenRecord || !SHARE_TOKENS.has(tokenRecord.token)) {
    tokenRecord = createShareToken(id, meta.uploaderId);
  }

  if (!tokenRecord || !tokenRecord.token) {
    return res.status(500).json({ ok: false, error: 'TOKEN_CREATE_FAILED' });
  }

  let shortRecord = findShortLinkRecord(id, meta.uploaderId);
  if (!shortRecord || !shortRecord.code || !SHORT_LINKS.has(shortRecord.code)) {
    shortRecord = createShortLink(tokenRecord, id, meta.uploaderId);
  } else if (shortRecord.token !== tokenRecord.token) {
    shortRecord = refreshShortLinkToken(shortRecord, tokenRecord);
  }

  const responseBody = buildShareResponse(req, id, tokenRecord, shortRecord, meta);
  res.json(responseBody);
}

app.post(['/api/share/:id', '/anyfile/api/share/:id'], shareBodyParser, handleShareRequest);
app.post(['/api/short/:id', '/anyfile/api/short/:id'], shareBodyParser, handleShareRequest);

// Owner-only download
app.get(['/api/download/:id','/anyfile/api/download/:id'], (req, res) => {
  const id = req.params.id;
  const meta = getMetaForStoredName(id);
  if (!meta) {
    return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  }
  if (meta.deleted || isExpired(meta)) {
    return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  }
  if (meta.uploaderId !== req.anysendUploaderId) {
    return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  }
  const fullPath = path.join(UPLOAD_DIR, id);
  if (!fs.existsSync(fullPath)) return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  if (req.method !== 'HEAD') {
    res.once('finish', () => recordDownload(id, meta));
  }
  sendFileWithDisposition(req, res, fullPath, meta.originalName, meta.mime, { public: false });
});

function sharedDownloadHandler(req, res) {
  const token = req.params.token;
  const tokenRecord = SHARE_TOKENS.get(token);
  if (!tokenRecord || !tokenRecord.storedName) {
    if (req.method === 'HEAD') return res.status(404).end();
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }
  const meta = getMetaForStoredName(tokenRecord.storedName);
  if (!meta || meta.deleted || isExpired(meta)) {
    if (req.method === 'HEAD') return res.status(404).end();
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }
  const fullPath = path.join(UPLOAD_DIR, tokenRecord.storedName);
  if (!fs.existsSync(fullPath)) {
    if (req.method === 'HEAD') return res.status(404).end();
    return res.status(404).json({ ok: false, error: 'NOT_FOUND' });
  }
  if (req.method !== 'HEAD') {
    res.once('finish', () => recordDownload(tokenRecord.storedName, meta));
  }
  sendFileWithDisposition(req, res, fullPath, meta.originalName, meta.mime, { public: true });
}

app.get(['/api/d/:token', '/anyfile/api/d/:token'], sharedDownloadHandler);
app.head(['/api/d/:token', '/anyfile/api/d/:token'], sharedDownloadHandler);

app.get(['/s/:code', '/anyfile/s/:code'], (req, res) => {
  const notFound = () => {
    res.status(404);
    res.set('Cache-Control', 'no-store');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    return res.type('html').send(renderLandingNotFoundHtml());
  };

  const code = req.params.code;
  const record = SHORT_LINKS.get(code);
  if (!record || !record.token) {
    return notFound();
  }
  const tokenRecord = SHARE_TOKENS.get(record.token);
  if (!tokenRecord || !tokenRecord.storedName) {
    return notFound();
  }
  const meta = getMetaForStoredName(tokenRecord.storedName);
  if (!meta || meta.deleted || isExpired(meta)) {
    return notFound();
  }

  const sharePath = '/api/d/' + encodeURIComponent(record.token);
  const prefix = req.originalUrl && req.originalUrl.startsWith('/anyfile/') ? '/anyfile' : '';
  const downloadPath = `${prefix}${sharePath}`;

  if (!meta.deleteAfterDownload) {
    res.set('Cache-Control', 'no-store');
    res.set('X-Robots-Tag', 'noindex, nofollow');
    return res.redirect(302, downloadPath);
  }

  const html = renderLandingPageHtml({
    fileName: meta.originalName || 'Download ready',
    sizeText: formatBytesShort(meta.size),
    expireText: formatDateTime(meta.expireAt),
    remainingDownloads: typeof meta.remainingDownloads === 'number' ? Math.max(meta.remainingDownloads, 0) : null,
    downloadPath,
    downloadAbsoluteUrl: makeAbsoluteUrl(req, sharePath, { preferFilesSubdomain: true }),
    deleteAfterDownload: !!meta.deleteAfterDownload
  });

  res.status(200);
  res.set('Cache-Control', 'no-store');
  res.set('X-Robots-Tag', 'noindex, nofollow');
  res.type('html').send(html);
});

app.get(['/f/:code', '/anyfile/f/:code'], (req, res) => {
  const code = req.params.code;
  const record = SHORT_LINKS.get(code);
  if (!record || !record.token) {
    return res.status(404).type('text/plain').send('Not found');
  }
  const tokenRecord = SHARE_TOKENS.get(record.token);
  if (!tokenRecord) {
    return res.status(404).type('text/plain').send('Not found');
  }
  const prefix = req.originalUrl && req.originalUrl.startsWith('/anyfile/') ? '/anyfile' : '';
  const target = `${prefix}/api/d/${encodeURIComponent(record.token)}`;
  res.set('Cache-Control', 'no-store');
  res.redirect(302, target);
});


// Delete endpoint (owner) - soft delete via tombstone + remove file
app.post(['/api/files/delete/:id','/anyfile/api/files/delete/:id'], express.json({ limit: '5kb'}), (req, res) => {
  const id = req.params.id;
  const meta = getMetaForStoredName(id);
  if (!meta) return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  if (meta.uploaderId !== req.anysendUploaderId) return res.status(404).json({ ok:false, error:'NOT_FOUND' }); // hide existence
  if (meta.deleted) return res.status(404).json({ ok:false, error:'NOT_FOUND' });
  softDeleteStoredFile(id, meta, 'user');
  res.json({ ok:true, deleted:true });
});

// Unmatched API routes (both root and prefixed) -> JSON 404
app.use(['/api','/anyfile/api'], (req, res, next) => {
  if (req.path && req.path !== '/') {
    return res.status(404).json({ ok: false, error: 'API_NOT_FOUND', path: req.originalUrl });
  }
  next();
});

// Error handler for Multer limits
app.use(function (err, req, res, next) {
  if (err && err.code === 'LIMIT_FILE_SIZE') {
    return res.status(413).json({ ok: false, error: 'FILE_TOO_LARGE' });
  }
  if (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ ok: false, error: 'UPLOAD_FAILED' });
  }
  next();
});

// (Upload static routes moved above API 404 middleware)

// Serve static files from current directory
app.use(express.static(__dirname));

// Fallback to index.html for root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`AnySend server running at http://localhost:${PORT}`);
});

/*
Future (Storage Strategy Roadmap):
1. Deduplication: Before storing, compute hash via temp file or stream-to-temp, then reuse existing stored file if hash matches (store metadata only).
2. Sharding: Place files under uploads/ab/cd/<hash>-filename using first 4 hex chars of hash to avoid large single directory.
3. Cleanup: Periodic job (cron / scheduled task) reading index.jsonl to remove files older than N days or above total size threshold.
4. Integrity check: Re-hash sampled files periodically to detect bit-rot.
5. Metadata index upgrade: Move from JSONL to SQLite or LiteFS for queryable listing (for share links & search).
*/
