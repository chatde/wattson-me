#!/usr/bin/env node
// Wattson.me — AI For the World
// Zero-dependency Node.js server — Pull-based architecture
// Nodes poll for work, process locally, post results back.

const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ── Load .env (zero-dep dotenv) ─────────────────────────────────────────────

try {
  const envPath = path.join(__dirname, '.env');
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, 'utf8').split('\n');
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const idx = trimmed.indexOf('=');
      if (idx === -1) continue;
      const key = trimmed.slice(0, idx).trim();
      const val = trimmed.slice(idx + 1).trim();
      if (!process.env[key]) process.env[key] = val;
    }
  }
} catch {
  // Non-critical
}

// ── Config ─────────────────────────────────────────────────────────────────────

const CONFIG = {
  port: parseInt(process.env.PORT || '8093', 10),
  host: process.env.HOST || '0.0.0.0',
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT_PER_MIN || '20', 10),
  rateLimitPerHour: parseInt(process.env.RATE_LIMIT_PER_HOUR || '100', 10),
  maxInputLength: parseInt(process.env.MAX_INPUT_LENGTH || '500', 10),
  ipSalt: process.env.IP_SALT || 'change-me',
  corsOrigin: process.env.CORS_ORIGIN || 'https://wattson.me',
  logFile: process.env.LOG_FILE || path.join(__dirname, 'conversations.jsonl'),
  nodeSecret: process.env.NODE_SECRET || '',
  jobTimeoutMs: parseInt(process.env.JOB_TIMEOUT_MS || '60000', 10),
  jobCleanupIntervalMs: parseInt(process.env.JOB_CLEANUP_INTERVAL_MS || '60000', 10),
  maxQueueSize: parseInt(process.env.MAX_QUEUE_SIZE || '100', 10),
  nodeStaleMs: parseInt(process.env.NODE_STALE_MS || '120000', 10),
  googleClientId: process.env.GOOGLE_CLIENT_ID || '',
};

const PUBLIC_DIR = path.join(__dirname, 'public');
const TOKENS_FILE = path.join(__dirname, 'tokens.json');
const REGISTRY_STATE_FILE = path.join(__dirname, 'registry-state.json');

// ── Token Storage ─────────────────────────────────────────────────────────────

let contributorTokens = {};

function loadTokens() {
  try {
    if (fs.existsSync(TOKENS_FILE)) {
      contributorTokens = JSON.parse(fs.readFileSync(TOKENS_FILE, 'utf8'));
    }
  } catch {
    contributorTokens = {};
  }
}

let saveTokensTimer = null;

function saveTokens() {
  if (saveTokensTimer) return; // Already scheduled
  saveTokensTimer = setTimeout(() => {
    saveTokensTimer = null;
    try {
      fs.writeFileSync(TOKENS_FILE, JSON.stringify(contributorTokens, null, 2));
    } catch {
      // Non-critical
    }
  }, 5000); // Debounce: write at most every 5 seconds
}

function saveTokensNow() {
  if (saveTokensTimer) { clearTimeout(saveTokensTimer); saveTokensTimer = null; }
  try {
    fs.writeFileSync(TOKENS_FILE, JSON.stringify(contributorTokens, null, 2));
  } catch {
    // Non-critical
  }
}

function generateToken() {
  return 'wm_' + crypto.randomBytes(16).toString('hex');
}

loadTokens();

// ── Registry Persistence ─────────────────────────────────────────────────────

let saveRegistryTimer = null;

function loadRegistryState() {
  try {
    if (fs.existsSync(REGISTRY_STATE_FILE)) {
      const data = JSON.parse(fs.readFileSync(REGISTRY_STATE_FILE, 'utf8'));
      if (typeof data.totalQueries === 'number') registry.totalQueries = data.totalQueries;
      if (Array.isArray(data.nodes)) {
        for (const saved of data.nodes) {
          // Mark all restored nodes as offline until they poll again
          saved.status = 'offline';
          registry.nodes.push(saved);
        }
      }
    }
  } catch {
    // Non-critical
  }
}

function saveRegistryState() {
  if (saveRegistryTimer) return;
  saveRegistryTimer = setTimeout(() => {
    saveRegistryTimer = null;
    try {
      fs.writeFileSync(REGISTRY_STATE_FILE, JSON.stringify({
        totalQueries: registry.totalQueries,
        nodes: registry.nodes,
      }, null, 2));
    } catch {
      // Non-critical
    }
  }, 5000);
}

function saveRegistryStateNow() {
  if (saveRegistryTimer) { clearTimeout(saveRegistryTimer); saveRegistryTimer = null; }
  try {
    fs.writeFileSync(REGISTRY_STATE_FILE, JSON.stringify({
      totalQueries: registry.totalQueries,
      nodes: registry.nodes,
    }, null, 2));
  } catch {
    // Non-critical
  }
}

// ── Google JWT Verification (zero dependencies) ──────────────────────────────

let googleKeysCache = null;
let googleKeysCacheTime = 0;
const GOOGLE_KEYS_TTL = 3600000; // 1 hour

function fetchGoogleKeys() {
  return new Promise((resolve, reject) => {
    https.get('https://www.googleapis.com/oauth2/v3/certs', (res) => {
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          googleKeysCache = parsed.keys;
          googleKeysCacheTime = Date.now();
          resolve(googleKeysCache);
        } catch (err) {
          reject(new Error('Failed to parse Google keys'));
        }
      });
      res.on('error', reject);
    }).on('error', reject);
  });
}

async function getGoogleKeys() {
  if (googleKeysCache && (Date.now() - googleKeysCacheTime < GOOGLE_KEYS_TTL)) {
    return googleKeysCache;
  }
  return fetchGoogleKeys();
}

function base64urlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64');
}

async function verifyGoogleJWT(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  // Decode header to get kid
  const header = JSON.parse(base64urlDecode(parts[0]).toString('utf8'));
  if (!header.kid) throw new Error('Missing kid in JWT header');

  // Fetch Google's public keys
  const keys = await getGoogleKeys();
  const key = keys.find(k => k.kid === header.kid);
  if (!key) throw new Error('Key not found for kid');

  // Convert JWK to PEM
  const pubKey = crypto.createPublicKey({ key, format: 'jwk' });

  // Verify signature
  const signedContent = parts[0] + '.' + parts[1];
  const signature = base64urlDecode(parts[2]);
  const isValid = crypto.createVerify('RSA-SHA256')
    .update(signedContent)
    .verify(pubKey, signature);

  if (!isValid) throw new Error('Invalid signature');

  // Decode and validate payload
  const payload = JSON.parse(base64urlDecode(parts[1]).toString('utf8'));

  if (payload.iss !== 'accounts.google.com' && payload.iss !== 'https://accounts.google.com') {
    throw new Error('Invalid issuer');
  }
  if (payload.aud !== CONFIG.googleClientId) {
    throw new Error('Invalid audience');
  }
  if (payload.exp * 1000 < Date.now()) {
    throw new Error('Token expired');
  }

  return { email: payload.email, name: payload.name, picture: payload.picture };
}

// ── Registry (in-memory) ──────────────────────────────────────────────────────

const registry = { nodes: [], totalQueries: 0, networkVersion: '0.2.0' };
loadRegistryState();

// ── Job Queue ─────────────────────────────────────────────────────────────────

const jobs = new Map(); // jobId -> { id, messages, status, createdAt, nodeId, res, timer, message, clientIP }
const pendingConfigs = new Map(); // nodeId -> { powerMode }

// ── Rate Limiter ──────────────────────────────────────────────────────────────

const rateBuckets = new Map();

function checkRateLimit(ip) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);
  if (!bucket) {
    bucket = {
      minute: { count: 0, resetAt: now + 60000 },
      hour: { count: 0, resetAt: now + 3600000 },
    };
    rateBuckets.set(ip, bucket);
  }

  if (now > bucket.minute.resetAt) {
    bucket.minute = { count: 0, resetAt: now + 60000 };
  }
  if (now > bucket.hour.resetAt) {
    bucket.hour = { count: 0, resetAt: now + 3600000 };
  }

  bucket.minute.count++;
  bucket.hour.count++;

  if (bucket.minute.count > CONFIG.rateLimitPerMin) return false;
  if (bucket.hour.count > CONFIG.rateLimitPerHour) return false;
  return true;
}

// Clean old buckets every 10 minutes
const rateLimitCleanup = setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (now > bucket.hour.resetAt) rateBuckets.delete(ip);
  }
}, 600000);
rateLimitCleanup.unref();

// ── Security ──────────────────────────────────────────────────────────────────

function hashIP(ip) {
  return crypto.createHash('sha256').update(CONFIG.ipSalt + ip).digest('hex').slice(0, 12);
}

function hashToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

function stripHtml(str) {
  return str.replace(/<[^>]*>/g, '');
}

function sanitizeOutput(str) {
  if (typeof str !== 'string') return '';
  // Strip <think> tags (qwen3 sometimes leaks these)
  let clean = str.replace(/<think>[\s\S]*?<\/think>/g, '');
  // Strip remaining HTML
  clean = stripHtml(clean);
  // Strip markdown bold
  clean = clean.replace(/\*\*(.*?)\*\*/g, '$1');
  // Limit length
  if (clean.length > 2000) clean = clean.slice(0, 2000) + '...';
  return clean.trim();
}

function getClientIP(req) {
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) return forwarded.split(',')[0].trim();
  return req.socket.remoteAddress || '0.0.0.0';
}

// ── Fog Logging ──────────────────────────────────────────────────────────────
// Keeps the shape of conversations, loses the words.

const FOG_CATEGORIES = [
  ['science', /\b(why|how|what)\b.*(work|cause|happen|make|create|form)/i],
  ['science', /\b(planet|star|atom|cell|dna|species|evolv|gravity|quantum|physic|chemi)/i],
  ['math', /\b(calculat|equation|formula|algebra|geometry|percent|fraction|math|solve)\b/i],
  ['math', /\d+\s*[\+\-\*\/\^]\s*\d+/],
  ['code', /\b(code|program|function|variable|javascript|python|html|css|api|debug|error|bug)\b/i],
  ['history', /\b(history|war|century|ancient|empire|king|queen|president|revolution)\b/i],
  ['health', /\b(health|symptom|disease|medic|doctor|pain|diet|exercise|vitamin)\b/i],
  ['creative', /\b(write|story|poem|song|joke|idea|creative|imagine|design)\b/i],
  ['personal', /\b(feel|happy|sad|anxious|depress|love|relationship|friend|family)\b/i],
  ['general', /./],
];

function fogCategory(message) {
  for (const [cat, rx] of FOG_CATEGORIES) {
    if (rx.test(message)) return cat;
  }
  return 'general';
}

const LOG_MAX_BYTES = 5 * 1024 * 1024; // 5MB

function rotateLogIfNeeded() {
  try {
    const stat = fs.statSync(CONFIG.logFile);
    if (stat.size >= LOG_MAX_BYTES) {
      const backup = CONFIG.logFile + '.1';
      fs.renameSync(CONFIG.logFile, backup);
    }
  } catch {
    // File doesn't exist yet or can't stat — fine
  }
}

function fogLog(hashedIP, message, responseMs, ok) {
  if (CONFIG.logFile === '/dev/null') return;
  try {
    rotateLogIfNeeded();
    const entry = JSON.stringify({
      t: new Date().toISOString(),
      ip: hashedIP,
      fog: {
        hash: crypto.createHash('sha256').update(message).digest('hex').slice(0, 16),
        words: message.split(/\s+/).length,
        chars: message.length,
        category: fogCategory(message),
      },
      ms: responseMs,
      ok,
    }) + '\n';
    fs.appendFileSync(CONFIG.logFile, entry);
  } catch {
    // Non-critical, don't crash
  }
}

// ── MIME Types ────────────────────────────────────────────────────────────────

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.webp': 'image/webp',
  '.woff2': 'font/woff2',
  '.webmanifest': 'application/manifest+json',
  '.sh': 'text/x-shellscript; charset=utf-8',
};

// ── Static File Server ──────────────────────────────────────────────────────

function serveStatic(req, res, urlPath) {
  // Block null bytes
  if (urlPath.includes('\0')) {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }

  // SPA routing: map known routes to index.html
  let filePath;
  const cleanPath = urlPath.split('?')[0];

  if (cleanPath === '/' || cleanPath === '/about' || cleanPath === '/start' ||
      cleanPath === '/meet' || cleanPath === '/connect' || cleanPath === '/dashboard') {
    filePath = path.join(PUBLIC_DIR, 'index.html');
  } else {
    filePath = path.join(PUBLIC_DIR, cleanPath);
  }

  // Resolve and check for directory traversal
  const resolved = path.resolve(filePath);
  if (!resolved.startsWith(PUBLIC_DIR)) {
    res.writeHead(403);
    res.end('Forbidden');
    return;
  }

  fs.readFile(resolved, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    const ext = path.extname(resolved).toLowerCase();
    const contentType = MIME_TYPES[ext] || 'application/octet-stream';
    const cacheControl = ext === '.html' ? 'no-cache' : 'public, max-age=300';
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': cacheControl });
    res.end(data);
  });
}

// ── API Routes ──────────────────────────────────────────────────────────────

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 10000) { // 10KB max body
        req.destroy();
        reject(new Error('Body too large'));
        return;
      }
      body += chunk;
    });
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        reject(new Error('Invalid JSON'));
      }
    });
    req.on('error', reject);
  });
}

// ── Chat (creates a job, holds response until node delivers result) ─────────

async function handleChat(req, res, clientIP) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    sendJSON(res, 400, { error: err.message });
    return;
  }

  // Validate message
  if (!body.message || typeof body.message !== 'string') {
    sendJSON(res, 400, { error: 'Message is required and must be a string' });
    return;
  }

  const message = stripHtml(body.message).trim();
  if (!message) {
    sendJSON(res, 400, { error: 'Message cannot be empty' });
    return;
  }

  if (message.length > CONFIG.maxInputLength) {
    sendJSON(res, 400, { error: `Message exceeds ${CONFIG.maxInputLength} characters` });
    return;
  }

  // Check for online inference nodes
  const onlineNodes = registry.nodes.filter(n => n.role === 'inference' && n.status === 'online');
  if (onlineNodes.length === 0) {
    sendJSON(res, 503, { error: 'No inference nodes available. Please try again later.' });
    return;
  }

  // Check queue capacity
  if (jobs.size >= CONFIG.maxQueueSize) {
    sendJSON(res, 503, { error: 'Server is busy. Please try again in a moment.' });
    return;
  }

  // Build Ollama messages
  const messages = [
    {
      role: 'system',
      content: 'You are Wattson, a friendly AI that lives on a network of people\'s devices around the world. You answer questions helpfully, concisely, and warmly. You\'re powered by donated devices — phones, laptops, Raspberry Pis. Keep answers brief (2-3 sentences for simple questions, more for complex ones). Be genuine, not corporate.',
    },
  ];

  // Add history (max 6 messages)
  if (Array.isArray(body.history)) {
    for (const h of body.history.slice(-6)) {
      if (h && typeof h.text === 'string' && (h.role === 'user' || h.role === 'assistant')) {
        messages.push({ role: h.role, content: h.text.slice(0, CONFIG.maxInputLength) });
      }
    }
  }

  messages.push({ role: 'user', content: message });

  // Create job
  const jobId = crypto.randomUUID();
  const job = {
    id: jobId,
    messages,
    status: 'pending',
    createdAt: Date.now(),
    nodeId: null,
    message,     // original message for fog logging
    clientIP,
    res: null,
    timer: null,
  };

  // Set timeout — respond to user if no node delivers in time
  job.timer = setTimeout(() => {
    if (jobs.has(jobId)) {
      job.status = 'expired';
      sendJSON(res, 504, { error: 'All nodes are busy. Please try again in a moment.' });
      jobs.delete(jobId);
    }
  }, CONFIG.jobTimeoutMs);

  job.res = res;
  jobs.set(jobId, job);

  // Handle client disconnect
  req.on('close', () => {
    if (jobs.has(jobId) && job.status === 'pending') {
      clearTimeout(job.timer);
      jobs.delete(jobId);
    }
  });
}

// ── Node Authentication ─────────────────────────────────────────────────────

function authenticateNode(req, res) {
  if (!CONFIG.nodeSecret && Object.keys(contributorTokens).length === 0) {
    sendJSON(res, 403, { error: 'Node authentication is disabled' });
    return null;
  }

  const secret = req.headers['x-node-secret'];
  if (!secret) {
    sendJSON(res, 401, { error: 'Invalid or missing secret' });
    return null;
  }

  // Check master secret first (timing-safe), then contributor tokens (hash lookup)
  const isMaster = CONFIG.nodeSecret && secret.length === CONFIG.nodeSecret.length &&
    crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(CONFIG.nodeSecret));
  const isContributor = !isMaster && contributorTokens[secret];

  if (!isMaster && !isContributor) {
    sendJSON(res, 401, { error: 'Invalid or missing secret' });
    return null;
  }

  // Update lastUsed for contributor tokens
  if (isContributor) {
    contributorTokens[secret].lastUsed = new Date().toISOString();
    saveTokens();
  }

  const nodeId = req.headers['x-node-id'];
  if (!nodeId) {
    sendJSON(res, 401, { error: 'Missing X-Node-Id header' });
    return null;
  }

  const node = registry.nodes.find(n => n.id === nodeId);
  if (!node) {
    sendJSON(res, 401, { error: 'Unregistered node' });
    return null;
  }

  return node;
}

// ── Node Poll (nodes fetch jobs from the queue) ─────────────────────────────

function handlePoll(req, res) {
  const node = authenticateNode(req, res);
  if (!node) return;

  // Update node liveness
  node.lastSeen = new Date().toISOString();
  node.status = 'online';

  // Check for pending config update
  const pendingConfig = pendingConfigs.get(node.id);
  if (pendingConfig) {
    pendingConfigs.delete(node.id);
    // Apply config server-side
    if (pendingConfig.powerMode) node.powerMode = pendingConfig.powerMode;
  }

  // Monitor nodes heartbeat but never get jobs
  if (node.role === 'monitor') {
    if (pendingConfig) {
      sendJSON(res, 200, { configUpdate: pendingConfig });
    } else {
      res.writeHead(204);
      res.end();
    }
    return;
  }

  // Find oldest pending job
  let oldestJob = null;
  for (const [, job] of jobs) {
    if (job.status === 'pending') {
      if (!oldestJob || job.createdAt < oldestJob.createdAt) {
        oldestJob = job;
      }
    }
  }

  if (!oldestJob) {
    if (pendingConfig) {
      sendJSON(res, 200, { configUpdate: pendingConfig });
    } else {
      res.writeHead(204);
      res.end();
    }
    return;
  }

  // Mark as processing
  oldestJob.status = 'processing';
  oldestJob.nodeId = node.id;

  const pollResponse = {
    jobId: oldestJob.id,
    messages: oldestJob.messages,
  };
  if (pendingConfig) pollResponse.configUpdate = pendingConfig;

  sendJSON(res, 200, pollResponse);
}

// ── Node Result (nodes post processed results back) ─────────────────────────

async function handleResult(req, res, jobId) {
  const node = authenticateNode(req, res);
  if (!node) return;

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    sendJSON(res, 400, { error: err.message });
    return;
  }

  if (!body.response || typeof body.response !== 'string') {
    sendJSON(res, 400, { error: 'response is required and must be a string' });
    return;
  }

  const job = jobs.get(jobId);
  if (!job) {
    sendJSON(res, 404, { error: 'Job not found' });
    return;
  }

  if (job.status !== 'processing') {
    sendJSON(res, 409, { error: 'Job is not in processing state' });
    return;
  }

  // Sanitize the response
  const response = sanitizeOutput(body.response);
  if (!response) {
    sendJSON(res, 400, { error: 'Response was empty after sanitization' });
    return;
  }

  // Calculate elapsed time
  const elapsed = Date.now() - job.createdAt;

  // Update node stats
  node.queriesServed = (node.queriesServed || 0) + 1;
  node.averageResponseMs = node.averageResponseMs
    ? node.averageResponseMs * 0.7 + elapsed * 0.3
    : elapsed;
  registry.totalQueries++;
  saveRegistryState();

  // Fog log
  fogLog(hashIP(job.clientIP), job.message, elapsed, true);

  // Respond to the held chat request
  if (job.res) {
    clearTimeout(job.timer);
    sendJSON(job.res, 200, { response });
  }

  // Clean up job
  jobs.delete(jobId);

  // Ack to the node
  sendJSON(res, 200, { ok: true });
}

// ── Node Registration ─────────────────────────────────────────────────────

async function handleRegister(req, res) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  // Check secret (master or contributor token)
  if (!CONFIG.nodeSecret && Object.keys(contributorTokens).length === 0) {
    sendJSON(res, 403, { error: 'Registration is disabled' });
    return;
  }

  const secret = req.headers['x-node-secret'];
  const isMasterReg = CONFIG.nodeSecret && secret && secret.length === CONFIG.nodeSecret.length &&
    crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(CONFIG.nodeSecret));
  if (!secret || (!isMasterReg && !contributorTokens[secret])) {
    sendJSON(res, 401, { error: 'Invalid or missing secret' });
    return;
  }

  // Update lastUsed for contributor tokens
  if (contributorTokens[secret]) {
    contributorTokens[secret].lastUsed = new Date().toISOString();
    saveTokens();
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    sendJSON(res, 400, { error: err.message });
    return;
  }

  // Validate required fields
  if (!body.name || typeof body.name !== 'string') {
    sendJSON(res, 400, { error: 'name is required' });
    return;
  }

  const role = body.role || 'inference';
  if (role !== 'inference' && role !== 'monitor') {
    sendJSON(res, 400, { error: 'role must be "inference" or "monitor"' });
    return;
  }

  // Generate unique ID
  const nodeNum = registry.nodes.length + 1;
  const tsBase36 = Date.now().toString(36);
  const randHex = crypto.randomBytes(2).toString('hex');
  const nodeId = `node-${nodeNum}-${tsBase36}-${randHex}`;

  const newNode = {
    id: nodeId,
    name: stripHtml(body.name).slice(0, 50),
    type: body.type || 'unknown',
    role,
    model: body.model || null,
    modelSize: body.modelSize || null,
    status: 'online',
    powerMode: body.powerMode || 'FULL_FORCE',
    specs: body.specs || {},
    joinedAt: new Date().toISOString(),
    lastSeen: new Date().toISOString(),
    queriesServed: 0,
    averageResponseMs: 0,
    ownerTokenHash: contributorTokens[secret] ? hashToken(secret) : null,
  };

  registry.nodes.push(newNode);
  saveRegistryState();

  // Return safe node data
  sendJSON(res, 201, {
    node: {
      id: newNode.id,
      name: newNode.name,
      type: newNode.type,
      role: newNode.role,
      status: newNode.status,
      powerMode: newNode.powerMode,
    },
  });
}

// ── Network Info ────────────────────────────────────────────────────────────

function handleNetwork(req, res) {
  const safeNodes = registry.nodes.map(n => ({
    id: n.id,
    name: n.name,
    type: n.type,
    role: n.role || 'inference',
    model: n.model,
    modelSize: n.modelSize,
    status: n.status,
    powerMode: n.powerMode,
    specs: n.specs,
    joinedAt: n.joinedAt,
    lastSeen: n.lastSeen,
    queriesServed: n.queriesServed || 0,
    averageResponseMs: n.averageResponseMs ? Math.round(n.averageResponseMs) : null,
  }));

  const inferenceNodes = safeNodes.filter(n => n.role === 'inference');
  const monitorNodes = safeNodes.filter(n => n.role === 'monitor');

  sendJSON(res, 200, {
    nodes: safeNodes,
    totalQueries: registry.totalQueries,
    deviceCount: safeNodes.length,
    onlineCount: safeNodes.filter(n => n.status === 'online').length,
    inferenceCount: inferenceNodes.length,
    inferenceOnline: inferenceNodes.filter(n => n.status === 'online').length,
    monitorCount: monitorNodes.length,
    monitorOnline: monitorNodes.filter(n => n.status === 'online').length,
    networkVersion: registry.networkVersion,
    pendingJobs: [...jobs.values()].filter(j => j.status === 'pending').length,
    processingJobs: [...jobs.values()].filter(j => j.status === 'processing').length,
  });
}

// ── Setup (auto-detect device, return steps) ────────────────────────────────

function handleSetup(req, res) {
  const ua = req.headers['user-agent'] || '';

  // Parse ?device= query param (allows frontend device chooser to override UA detection)
  const urlObj = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const deviceParam = (urlObj.searchParams.get('device') || '').toLowerCase();

  // Map device param to OS
  const deviceToOS = {
    iphone: 'ios', ipad: 'ios',
    android: 'android',
    mac: 'mac',
    windows: 'windows',
    linux: 'linux', pi: 'linux',
  };

  let os, device, supported, model, steps, message, role;

  // If ?device= is set for iOS, return monitor role
  if (deviceParam && deviceToOS[deviceParam] === 'ios') {
    os = 'ios';
    device = 'mobile';
    supported = true;
    role = 'monitor';
    model = null;
    steps = [
      { title: 'Add to Home Screen', command: 'In Safari: tap Share → "Add to Home Screen". This installs Wattson as a PWA for a native app experience.' },
    ];
    message = 'Your iPhone becomes a network monitor node. It tracks which devices are online, network health, and response times — no Ollama needed.';
  } else {
    // Determine OS from device param or UA
    const effectiveOS = deviceParam ? (deviceToOS[deviceParam] || null) : null;

    if (effectiveOS === 'android' || (!effectiveOS && /Android/i.test(ua))) {
      os = 'android';
      device = 'mobile';
      supported = true;
      model = 'qwen3:1.7b';
      steps = [
        { title: 'Install Termux', command: 'Download Termux from F-Droid:\nhttps://f-droid.org/en/packages/com.termux/' },
        { title: 'Install Ollama', command: 'pkg update && pkg install ollama && ollama serve &' },
        { title: 'Pull a model', command: 'ollama pull qwen3:1.7b' },
        { title: 'Start contributing', command: 'curl -O https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js\n\nWATTSON_SERVER=https://wattson.me \\\nNODE_SECRET=YOUR_TOKEN \\\nMODEL=qwen3:1.7b \\\nnode wattson-client.js' },
      ];
    } else if (effectiveOS === 'mac' || (!effectiveOS && /Macintosh/i.test(ua))) {
      os = 'mac';
      device = 'desktop';
      supported = true;
      model = 'llama3.1:8b-q4';
      steps = [
        { title: 'Install Ollama', command: 'brew install ollama' },
        { title: 'Pull a model', command: 'ollama pull llama3.1:8b-q4' },
        { title: 'Start contributing', command: 'curl -O https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js\n\nWATTSON_SERVER=https://wattson.me \\\nNODE_SECRET=YOUR_TOKEN \\\nMODEL=llama3.1:8b-q4 \\\nnode wattson-client.js' },
      ];
    } else if (effectiveOS === 'windows' || (!effectiveOS && /Windows/i.test(ua))) {
      os = 'windows';
      device = 'desktop';
      supported = true;
      model = 'llama3.1:8b-q4';
      steps = [
        { title: 'Install Ollama', command: 'Download from https://ollama.ai/download and install' },
        { title: 'Pull a model', command: 'ollama pull llama3.1:8b-q4' },
        { title: 'Start contributing', command: 'Invoke-WebRequest -Uri "https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js" -OutFile "wattson-client.js"\n\n$env:WATTSON_SERVER="https://wattson.me"\n$env:NODE_SECRET="YOUR_TOKEN"\n$env:MODEL="llama3.1:8b-q4"\nnode wattson-client.js' },
      ];
    } else if (effectiveOS === 'linux' || (!effectiveOS && /Linux/i.test(ua))) {
      os = 'linux';
      device = 'desktop';
      supported = true;
      model = 'qwen3:1.7b';
      steps = [
        { title: 'Install Ollama', command: 'curl -fsSL https://ollama.ai/install.sh | sh' },
        { title: 'Pull a model', command: 'ollama pull qwen3:1.7b' },
        { title: 'Start contributing', command: 'curl -O https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js\n\nWATTSON_SERVER=https://wattson.me \\\nNODE_SECRET=YOUR_TOKEN \\\nMODEL=qwen3:1.7b \\\nnode wattson-client.js' },
      ];
    } else if (!effectiveOS && /iPhone|iPad|iPod/i.test(ua)) {
      // iOS without ?device= param — backward compatible: unsupported
      os = 'ios';
      device = 'mobile';
      supported = false;
      model = null;
      steps = [];
      message = 'iOS doesn\'t support Ollama yet. You can contribute using an Android phone, laptop, or desktop instead.';
      role = 'inference';
    } else {
      os = 'unknown';
      device = 'unknown';
      supported = true;
      model = 'qwen3:1.7b';
      steps = [
        { title: 'Install Ollama', command: 'curl -fsSL https://ollama.ai/install.sh | sh' },
        { title: 'Pull a model', command: 'ollama pull qwen3:1.7b' },
        { title: 'Start contributing', command: 'curl -O https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js\n\nWATTSON_SERVER=https://wattson.me \\\nNODE_SECRET=YOUR_TOKEN \\\nMODEL=qwen3:1.7b \\\nnode wattson-client.js' },
      ];
    }

    if (!role) role = 'inference';
  }

  // Quick one-liner for bash-compatible platforms
  let quickCommand = null;
  if (supported && role === 'inference' && os !== 'windows') {
    if (os === 'android') {
      quickCommand = 'curl -fsSL https://wattson.me/setup-termux.sh | bash -s -- YOUR_TOKEN';
    } else {
      quickCommand = 'curl -fsSL https://wattson.me/setup.sh | bash';
    }
  }

  const result = { os, device, supported, model, steps, role };
  if (quickCommand) result.quickCommand = quickCommand;
  if (message) result.message = message;
  sendJSON(res, 200, result);
}

// ── Health ───────────────────────────────────────────────────────────────────

function handleHealth(req, res) {
  const inferenceNodes = registry.nodes.filter(n => n.role === 'inference');
  const monitorNodes = registry.nodes.filter(n => n.role === 'monitor');
  const inferenceOnline = inferenceNodes.filter(n => n.status === 'online').length;
  const monitorOnline = monitorNodes.filter(n => n.status === 'online').length;

  const status = inferenceOnline > 0 ? 'healthy' : 'degraded';
  sendJSON(res, 200, {
    status,
    inferenceNodes: inferenceNodes.length,
    inferenceOnline,
    monitorNodes: monitorNodes.length,
    monitorOnline,
    pendingJobs: [...jobs.values()].filter(j => j.status === 'pending').length,
    processingJobs: [...jobs.values()].filter(j => j.status === 'processing').length,
    totalQueries: registry.totalQueries,
    uptime: process.uptime(),
  });
}

// ── Auth Endpoints ──────────────────────────────────────────────────────────

async function handleAuthGoogle(req, res) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  if (!CONFIG.googleClientId) {
    sendJSON(res, 503, { error: 'Google Sign-In is not configured' });
    return;
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    sendJSON(res, 400, { error: err.message });
    return;
  }

  if (!body.credential || typeof body.credential !== 'string') {
    sendJSON(res, 400, { error: 'credential is required' });
    return;
  }

  let googleUser;
  try {
    googleUser = await verifyGoogleJWT(body.credential);
  } catch (err) {
    sendJSON(res, 401, { error: 'Invalid Google credential: ' + err.message });
    return;
  }

  // Check if this email already has a token
  for (const [token, info] of Object.entries(contributorTokens)) {
    if (info.email === googleUser.email) {
      // Update profile info
      info.name = googleUser.name;
      info.picture = googleUser.picture;
      info.lastUsed = new Date().toISOString();
      saveTokens();
      sendJSON(res, 200, { token, name: info.name, email: info.email });
      return;
    }
  }

  // Create new token
  const token = generateToken();
  contributorTokens[token] = {
    email: googleUser.email,
    name: googleUser.name,
    picture: googleUser.picture,
    createdAt: new Date().toISOString(),
    lastUsed: new Date().toISOString(),
  };
  saveTokens();

  sendJSON(res, 200, { token, name: googleUser.name, email: googleUser.email });
}

function handleAuthMe(req, res) {
  if (req.method !== 'GET') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    sendJSON(res, 401, { error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7);
  const info = contributorTokens[token];
  if (!info) {
    sendJSON(res, 401, { error: 'Invalid token' });
    return;
  }

  sendJSON(res, 200, {
    email: info.email,
    name: info.name,
    picture: info.picture,
    createdAt: info.createdAt,
    lastUsed: info.lastUsed,
  });
}

async function handleAuthRevoke(req, res) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    sendJSON(res, 401, { error: 'Missing or invalid Authorization header' });
    return;
  }

  const token = authHeader.slice(7);
  if (!contributorTokens[token]) {
    sendJSON(res, 401, { error: 'Invalid token' });
    return;
  }

  // Remove orphaned nodes owned by this token
  const tokenHash = hashToken(token);
  for (let i = registry.nodes.length - 1; i >= 0; i--) {
    if (registry.nodes[i].ownerTokenHash === tokenHash) {
      pendingConfigs.delete(registry.nodes[i].id);
      registry.nodes.splice(i, 1);
    }
  }

  delete contributorTokens[token];
  saveTokens();
  saveRegistryState();
  sendJSON(res, 200, { ok: true });
}

// ── Contributor Endpoints ────────────────────────────────────────────────────

function authenticateContributor(req, res) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    sendJSON(res, 401, { error: 'Missing or invalid Authorization header' });
    return null;
  }
  const token = authHeader.slice(7);
  if (!contributorTokens[token]) {
    sendJSON(res, 401, { error: 'Invalid token' });
    return null;
  }
  return token;
}

function handleContributorNodes(req, res) {
  if (req.method !== 'GET') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const token = authenticateContributor(req, res);
  if (!token) return;

  const owned = registry.nodes
    .filter(n => n.ownerTokenHash === hashToken(token))
    .map(n => ({
      id: n.id,
      name: n.name,
      type: n.type,
      role: n.role,
      model: n.model,
      status: n.status,
      powerMode: n.powerMode,
      specs: n.specs,
      joinedAt: n.joinedAt,
      lastSeen: n.lastSeen,
      queriesServed: n.queriesServed || 0,
      averageResponseMs: n.averageResponseMs ? Math.round(n.averageResponseMs) : null,
    }));

  sendJSON(res, 200, { nodes: owned });
}

async function handleContributorConfig(req, res, nodeId) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const token = authenticateContributor(req, res);
  if (!token) return;

  const node = registry.nodes.find(n => n.id === nodeId);
  if (!node) {
    sendJSON(res, 404, { error: 'Node not found' });
    return;
  }
  if (node.ownerTokenHash !== hashToken(token)) {
    sendJSON(res, 403, { error: 'Not your node' });
    return;
  }

  let body;
  try {
    body = await readBody(req);
  } catch (err) {
    sendJSON(res, 400, { error: err.message });
    return;
  }

  const validModes = ['FULL_FORCE', 'HALF_FORCE', 'ECO'];
  if (!body.powerMode || !validModes.includes(body.powerMode)) {
    sendJSON(res, 400, { error: 'powerMode must be FULL_FORCE, HALF_FORCE, or ECO' });
    return;
  }

  pendingConfigs.set(nodeId, { powerMode: body.powerMode });
  sendJSON(res, 200, { ok: true, queued: true });
}

function handleContributorRemoveNode(req, res, nodeId) {
  if (req.method !== 'DELETE') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const token = authenticateContributor(req, res);
  if (!token) return;

  const idx = registry.nodes.findIndex(n => n.id === nodeId);
  if (idx === -1) {
    sendJSON(res, 404, { error: 'Node not found' });
    return;
  }
  if (registry.nodes[idx].ownerTokenHash !== hashToken(token)) {
    sendJSON(res, 403, { error: 'Not your node' });
    return;
  }

  registry.nodes.splice(idx, 1);
  pendingConfigs.delete(nodeId);
  saveRegistryState();
  sendJSON(res, 200, { ok: true });
}

function handleAuthTokens(req, res) {
  if (req.method !== 'GET') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  const secret = req.headers['x-node-secret'];
  const isMasterAdmin = CONFIG.nodeSecret && secret && secret.length === CONFIG.nodeSecret.length &&
    crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(CONFIG.nodeSecret));
  if (!isMasterAdmin) {
    sendJSON(res, 401, { error: 'Admin access required' });
    return;
  }

  const tokens = Object.entries(contributorTokens).map(([token, info]) => ({
    token: token.slice(0, 7) + '...',
    email: info.email,
    name: info.name,
    createdAt: info.createdAt,
    lastUsed: info.lastUsed,
  }));

  sendJSON(res, 200, { tokens, count: tokens.length });
}

// ── Response Helper ─────────────────────────────────────────────────────────

function sendJSON(res, statusCode, data) {
  if (res.writableEnded || res.headersSent) return;
  try {
    const body = JSON.stringify(data);
    res.writeHead(statusCode, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
  } catch {
    // Response already sent or connection closed
  }
}

// ── Server ──────────────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const clientIP = getClientIP(req);
  let pathname;
  try {
    pathname = new URL(req.url, `http://${req.headers.host || 'localhost'}`).pathname;
  } catch {
    res.writeHead(400);
    res.end('Bad request');
    return;
  }

  // Security headers on ALL responses
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://accounts.google.com; style-src 'self' 'unsafe-inline' https://accounts.google.com; frame-src https://accounts.google.com; img-src 'self' data:; connect-src 'self'");
  if (CONFIG.corsOrigin !== '*' && CONFIG.corsOrigin.startsWith('https://')) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }

  // CORS
  const origin = req.headers.origin;
  if (CONFIG.corsOrigin === '*' || origin === CONFIG.corsOrigin || origin === `http://localhost:${CONFIG.port}`) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Node-Secret, X-Node-Id, Authorization');
    res.setHeader('Vary', 'Origin');
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Rate limiting (skip for authenticated node endpoints — they have their own auth)
  const isNodeEndpoint = pathname.startsWith('/api/nodes/');
  if (!isNodeEndpoint && !checkRateLimit(clientIP)) {
    sendJSON(res, 429, { error: 'Too many requests. Please slow down.' });
    return;
  }

  // API routes — auth
  if (pathname === '/api/auth/config') {
    sendJSON(res, 200, { clientId: CONFIG.googleClientId || null });
  } else if (pathname === '/api/auth/google') {
    handleAuthGoogle(req, res).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname === '/api/auth/me') {
    handleAuthMe(req, res);
  } else if (pathname === '/api/auth/revoke') {
    handleAuthRevoke(req, res).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname === '/api/auth/tokens') {
    handleAuthTokens(req, res);
  }
  // API routes — contributor
  else if (pathname === '/api/contributor/nodes') {
    handleContributorNodes(req, res);
  } else if (pathname.startsWith('/api/contributor/nodes/') && pathname.endsWith('/config')) {
    const parts = pathname.split('/');
    const contribNodeId = parts[4]; // /api/contributor/nodes/:id/config
    handleContributorConfig(req, res, contribNodeId).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname.startsWith('/api/contributor/nodes/') && req.method === 'DELETE') {
    const parts = pathname.split('/');
    const contribNodeId = parts[4]; // /api/contributor/nodes/:id
    handleContributorRemoveNode(req, res, contribNodeId);
  }
  // API routes
  else if (pathname === '/api/chat') {
    handleChat(req, res, clientIP).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname === '/api/nodes/poll') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handlePoll(req, res);
  } else if (pathname.startsWith('/api/nodes/result/')) {
    if (req.method !== 'POST') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    const jobId = pathname.slice('/api/nodes/result/'.length);
    handleResult(req, res, jobId).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname === '/api/nodes/register') {
    handleRegister(req, res).catch(function() { sendJSON(res, 500, { error: 'Internal error' }); });
  } else if (pathname === '/api/setup') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleSetup(req, res);
  } else if (pathname === '/api/network') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleNetwork(req, res);
  } else if (pathname === '/health') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleHealth(req, res);
  } else if (pathname.startsWith('/api/')) {
    sendJSON(res, 404, { error: 'Not found' });
  } else {
    // Static files / SPA
    serveStatic(req, res, pathname);
  }
});

// ── Job Cleanup ─────────────────────────────────────────────────────────────

let jobCleanupTimer = null;

function startJobCleanup() {
  jobCleanupTimer = setInterval(() => {
    const now = Date.now();
    // Purge old jobs (safety net — timeout should handle most)
    for (const [id, job] of jobs) {
      if (now - job.createdAt > CONFIG.jobTimeoutMs * 2) {
        if (job.timer) clearTimeout(job.timer);
        if (job.res) {
          sendJSON(job.res, 504, { error: 'Request expired' });
        }
        jobs.delete(id);
      }
    }
    // Mark stale nodes offline
    const nodeIds = new Set();
    for (const node of registry.nodes) {
      nodeIds.add(node.id);
      if (node.lastSeen && (now - new Date(node.lastSeen).getTime() > CONFIG.nodeStaleMs)) {
        node.status = 'offline';
      }
    }
    // Clean up pendingConfigs for nodes that no longer exist
    for (const [nodeId] of pendingConfigs) {
      if (!nodeIds.has(nodeId)) pendingConfigs.delete(nodeId);
    }
  }, CONFIG.jobCleanupIntervalMs);
}

// ── Start ───────────────────────────────────────────────────────────────────

server.listen(CONFIG.port, CONFIG.host, () => {
  const mode = process.env.NODE_ENV === 'test' ? 'TEST' : 'PRODUCTION';
  process.stdout.write(`[wattson.me] ${mode} server listening on ${CONFIG.host}:${CONFIG.port}\n`);
  startJobCleanup();
});

// Graceful shutdown
function shutdown() {
  process.stdout.write('[wattson.me] Shutting down...\n');
  if (jobCleanupTimer) clearInterval(jobCleanupTimer);
  clearInterval(rateLimitCleanup);
  saveTokensNow();
  saveRegistryStateNow();

  // Resolve any pending held responses
  for (const [id, job] of jobs) {
    if (job.timer) clearTimeout(job.timer);
    if (job.res) {
      sendJSON(job.res, 503, { error: 'Server shutting down' });
    }
    jobs.delete(id);
  }

  server.close(() => {
    process.exit(0);
  });
  // Force exit after 5s
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Export for testing
module.exports = { server, registry, contributorTokens, pendingConfigs, saveRegistryStateNow, loadRegistryState, REGISTRY_STATE_FILE };
