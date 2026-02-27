#!/usr/bin/env node
// Wattson.me — AI For the World
// Zero-dependency Node.js server

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

// ── Config ─────────────────────────────────────────────────────────────────────

const CONFIG = {
  port: parseInt(process.env.PORT || '8093', 10),
  host: process.env.HOST || '0.0.0.0',
  ollamaUrl: process.env.OLLAMA_URL || 'http://192.168.5.48:11434',
  chatModel: process.env.CHAT_MODEL || 'wattson:chat',
  mindBridgeUrl: process.env.MIND_BRIDGE_URL || 'http://localhost:8081',
  rateLimitPerMin: parseInt(process.env.RATE_LIMIT_PER_MIN || '20', 10),
  rateLimitPerHour: parseInt(process.env.RATE_LIMIT_PER_HOUR || '100', 10),
  maxInputLength: parseInt(process.env.MAX_INPUT_LENGTH || '500', 10),
  ipSalt: process.env.IP_SALT || 'change-me',
  corsOrigin: process.env.CORS_ORIGIN || 'https://wattson.me',
  logFile: process.env.LOG_FILE || path.join(__dirname, 'conversations.jsonl'),
  nodeSecret: process.env.NODE_SECRET || '',
  healthCheckIntervalMs: parseInt(process.env.HEALTH_CHECK_INTERVAL_MS || '30000', 10),
  healthCheckTimeoutMs: parseInt(process.env.HEALTH_CHECK_TIMEOUT_MS || '5000', 10),
  maxConsecutiveFailures: parseInt(process.env.MAX_CONSECUTIVE_FAILURES || '3', 10),
  registrySaveIntervalMs: parseInt(process.env.REGISTRY_SAVE_INTERVAL_MS || '60000', 10),
};

const PUBLIC_DIR = path.join(__dirname, 'public');

// ── Registry ───────────────────────────────────────────────────────────────────

let registry = { nodes: [], totalQueries: 0, networkVersion: '0.1.0' };
const registryPath = path.join(__dirname, 'registry.json');
try {
  registry = JSON.parse(fs.readFileSync(registryPath, 'utf8'));
} catch {
  // Use defaults
}

// ── Rate Limiter ───────────────────────────────────────────────────────────────

const rateBuckets = new Map(); // ip -> { minute: { count, resetAt }, hour: { count, resetAt } }

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
setInterval(() => {
  const now = Date.now();
  for (const [ip, bucket] of rateBuckets) {
    if (now > bucket.hour.resetAt) rateBuckets.delete(ip);
  }
}, 600000);

// ── Security ───────────────────────────────────────────────────────────────────

function hashIP(ip) {
  return crypto.createHash('sha256').update(CONFIG.ipSalt + ip).digest('hex').slice(0, 12);
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

// ── HTTP Helpers ───────────────────────────────────────────────────────────────

function proxyGet(targetUrl, timeoutMs = 10000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      timeout: timeoutMs,
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error('Invalid JSON response'));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.end();
  });
}

function proxyPost(targetUrl, body, timeoutMs = 120000) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(targetUrl);
    const payload = typeof body === 'string' ? body : JSON.stringify(body);
    const req = http.request({
      hostname: parsed.hostname,
      port: parsed.port,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: timeoutMs,
    }, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        try {
          resolve(JSON.parse(data));
        } catch {
          reject(new Error('Invalid JSON response'));
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    req.write(payload);
    req.end();
  });
}

// ── Logging ────────────────────────────────────────────────────────────────────

function logConversation(hashedIP, message, response) {
  if (CONFIG.logFile === '/dev/null') return;
  try {
    const entry = JSON.stringify({
      t: new Date().toISOString(),
      ip: hashedIP,
      q: message.slice(0, 200),
      a: (response || '').slice(0, 200),
    }) + '\n';
    fs.appendFileSync(CONFIG.logFile, entry);
  } catch {
    // Non-critical, don't crash
  }
}

// ── Health Check Daemon ────────────────────────────────────────────────────

async function checkNodeHealth(node) {
  const start = Date.now();
  const url = node.role === 'monitor'
    ? node.healthUrl
    : (node.ollamaUrl ? node.ollamaUrl + '/api/tags' : null);

  if (!url) return;

  try {
    await proxyGet(url, CONFIG.healthCheckTimeoutMs);
    const latency = Date.now() - start;
    node.latencyMs = latency;
    node.lastHealthCheck = new Date().toISOString();
    node.lastHealthOk = new Date().toISOString();
    node.failureCount = 0;
    node.status = 'online';
  } catch {
    node.lastHealthCheck = new Date().toISOString();
    node.failureCount = (node.failureCount || 0) + 1;
    node.latencyMs = null;
    if (node.failureCount >= CONFIG.maxConsecutiveFailures) {
      node.status = 'offline';
    }
  }
}

async function runHealthChecks() {
  await Promise.allSettled(registry.nodes.map(n => checkNodeHealth(n)));
}

let healthCheckTimer = null;
let registrySaveTimer = null;

function startHealthDaemon() {
  // Initial check after 5s
  setTimeout(() => {
    runHealthChecks();
  }, 5000);

  // Periodic checks
  healthCheckTimer = setInterval(() => {
    runHealthChecks();
  }, CONFIG.healthCheckIntervalMs);

  // Periodic registry save
  registrySaveTimer = setInterval(() => {
    try {
      fs.writeFile(registryPath, JSON.stringify(registry, null, 2), () => {});
    } catch { /* best effort */ }
  }, CONFIG.registrySaveIntervalMs);
}

// ── Smart Routing ─────────────────────────────────────────────────────────

function selectNode() {
  const candidates = registry.nodes.filter(n =>
    n.role === 'inference' && n.status === 'online'
  );

  if (candidates.length === 0) return null;

  // Sort: powerMode priority (FULL_FORCE > HALF_FORCE > ECO), then lowest latency, then fewest failures
  const powerOrder = { 'FULL_FORCE': 0, 'HALF_FORCE': 1, 'ECO': 2 };
  candidates.sort((a, b) => {
    const pa = powerOrder[a.powerMode] ?? 1;
    const pb = powerOrder[b.powerMode] ?? 1;
    if (pa !== pb) return pa - pb;
    const la = a.latencyMs ?? 9999;
    const lb = b.latencyMs ?? 9999;
    if (la !== lb) return la - lb;
    return (a.failureCount || 0) - (b.failureCount || 0);
  });

  return candidates;
}

// ── MIME Types ──────────────────────────────────────────────────────────────────

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
};

// ── Static File Server ─────────────────────────────────────────────────────────

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
    res.writeHead(200, { 'Content-Type': contentType, 'Cache-Control': 'public, max-age=300' });
    res.end(data);
  });
}

// ── API Routes ─────────────────────────────────────────────────────────────────

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

  const candidates = selectNode();
  if (!candidates || candidates.length === 0) {
    sendJSON(res, 503, { error: 'No inference nodes available. Please try again later.' });
    return;
  }

  let lastError = null;
  for (const node of candidates) {
    try {
      const start = Date.now();
      const result = await proxyPost(`${node.ollamaUrl}/api/chat`, {
        model: node.model || CONFIG.chatModel,
        messages,
        stream: false,
        think: false,
        options: { num_ctx: 512, num_predict: 256, temperature: 0.8 },
      });

      const response = sanitizeOutput(result.message?.content || '');
      if (!response) {
        lastError = 'Empty response from AI';
        node.failureCount = (node.failureCount || 0) + 1;
        continue;
      }

      const elapsed = Date.now() - start;
      node.queriesServed = (node.queriesServed || 0) + 1;
      // Exponential moving average for response time
      node.averageResponseMs = node.averageResponseMs
        ? node.averageResponseMs * 0.7 + elapsed * 0.3
        : elapsed;
      registry.totalQueries++;
      logConversation(hashIP(clientIP), message, response);

      sendJSON(res, 200, { response });
      return;
    } catch {
      node.failureCount = (node.failureCount || 0) + 1;
      lastError = 'Node failed';
    }
  }

  sendJSON(res, 502, { error: 'AI is currently unavailable. Please try again.' });
}

async function handleState(req, res) {
  try {
    const state = await proxyGet(`${CONFIG.mindBridgeUrl}/api/state`);
    sendJSON(res, 200, state);
  } catch {
    sendJSON(res, 502, { error: 'Mind bridge unavailable' });
  }
}

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
    lastHealthCheck: n.lastHealthCheck,
    lastHealthOk: n.lastHealthOk,
    queriesServed: n.queriesServed || 0,
    averageResponseMs: n.averageResponseMs ? Math.round(n.averageResponseMs) : null,
    failureCount: n.failureCount || 0,
    latencyMs: n.latencyMs,
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
  });
}

async function handleHealth(req, res) {
  let mindBridgeAlive = false;

  try {
    await proxyGet(`${CONFIG.mindBridgeUrl}/api/state`, 5000);
    mindBridgeAlive = true;
  } catch { /* offline */ }

  const inferenceNodes = registry.nodes.filter(n => (n.role || 'inference') === 'inference');
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
    mindBridgeAlive,
    uptime: process.uptime(),
  });
}

// ── Node Registration ─────────────────────────────────────────────────────

async function handleRegister(req, res) {
  if (req.method !== 'POST') {
    sendJSON(res, 405, { error: 'Method not allowed' });
    return;
  }

  // Check secret
  if (!CONFIG.nodeSecret) {
    sendJSON(res, 403, { error: 'Registration is disabled' });
    return;
  }

  const secret = req.headers['x-node-secret'];
  if (!secret || secret !== CONFIG.nodeSecret) {
    sendJSON(res, 401, { error: 'Invalid or missing secret' });
    return;
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

  // Inference nodes require ollamaUrl
  if (role === 'inference') {
    if (!body.ollamaUrl || typeof body.ollamaUrl !== 'string') {
      sendJSON(res, 400, { error: 'ollamaUrl is required for inference nodes' });
      return;
    }

    // Validate URL
    try {
      new URL(body.ollamaUrl);
    } catch {
      sendJSON(res, 400, { error: 'ollamaUrl must be a valid URL' });
      return;
    }

    // Check for duplicate ollamaUrl
    const dup = registry.nodes.find(n => n.ollamaUrl === body.ollamaUrl);
    if (dup) {
      sendJSON(res, 409, { error: 'A node with this ollamaUrl already exists' });
      return;
    }

    // Verify reachable
    try {
      await proxyGet(body.ollamaUrl + '/api/tags', CONFIG.healthCheckTimeoutMs);
    } catch {
      sendJSON(res, 422, { error: 'Could not reach ollamaUrl — is Ollama running?' });
      return;
    }
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
    role: role,
    model: body.model || null,
    modelSize: body.modelSize || null,
    ollamaUrl: role === 'inference' ? body.ollamaUrl : undefined,
    healthUrl: body.healthUrl || undefined,
    status: 'online',
    powerMode: body.powerMode || 'FULL_FORCE',
    specs: body.specs || {},
    joinedAt: new Date().toISOString(),
    lastHealthCheck: null,
    lastHealthOk: null,
    queriesServed: 0,
    averageResponseMs: 0,
    failureCount: 0,
    latencyMs: null,
  };

  registry.nodes.push(newNode);

  // Save immediately
  try {
    fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
  } catch { /* best effort */ }

  // Return safe node data (no ollamaUrl/healthUrl)
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

// ── Response Helper ────────────────────────────────────────────────────────────

function sendJSON(res, statusCode, data) {
  const body = JSON.stringify(data);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

// ── Server ─────────────────────────────────────────────────────────────────────

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
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');

  // CORS
  const origin = req.headers.origin;
  if (CONFIG.corsOrigin === '*' || origin === CONFIG.corsOrigin || origin === 'http://localhost:8093') {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  }

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Rate limiting
  if (!checkRateLimit(clientIP)) {
    sendJSON(res, 429, { error: 'Too many requests. Please slow down.' });
    return;
  }

  // API routes
  if (pathname === '/api/chat') {
    handleChat(req, res, clientIP);
  } else if (pathname === '/api/state') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleState(req, res);
  } else if (pathname === '/api/network') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleNetwork(req, res);
  } else if (pathname === '/health') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handleHealth(req, res);
  } else if (pathname === '/api/nodes/register') {
    handleRegister(req, res);
  } else if (pathname.startsWith('/api/')) {
    sendJSON(res, 404, { error: 'Not found' });
  } else {
    // Static files / SPA
    serveStatic(req, res, pathname);
  }
});

server.listen(CONFIG.port, CONFIG.host, () => {
  const mode = process.env.NODE_ENV === 'test' ? 'TEST' : 'PRODUCTION';
  process.stdout.write(`[wattson.me] ${mode} server listening on ${CONFIG.host}:${CONFIG.port}\n`);
  startHealthDaemon();
});

// Graceful shutdown
function shutdown() {
  process.stdout.write('[wattson.me] Shutting down...\n');
  if (healthCheckTimer) clearInterval(healthCheckTimer);
  if (registrySaveTimer) clearInterval(registrySaveTimer);
  server.close(() => {
    // Save registry
    try {
      fs.writeFileSync(registryPath, JSON.stringify(registry, null, 2));
    } catch { /* best effort */ }
    process.exit(0);
  });
  // Force exit after 5s
  setTimeout(() => process.exit(1), 5000);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

// Export for testing
module.exports = server;
