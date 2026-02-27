#!/usr/bin/env node
// Wattson.me — AI For the World
// Zero-dependency Node.js server — Pull-based architecture
// Nodes poll for work, process locally, post results back.

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

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
  jobTimeoutMs: parseInt(process.env.JOB_TIMEOUT_MS || '25000', 10),
  jobCleanupIntervalMs: parseInt(process.env.JOB_CLEANUP_INTERVAL_MS || '60000', 10),
  maxQueueSize: parseInt(process.env.MAX_QUEUE_SIZE || '100', 10),
  nodeStaleMs: parseInt(process.env.NODE_STALE_MS || '120000', 10),
};

const PUBLIC_DIR = path.join(__dirname, 'public');

// ── Registry (in-memory) ──────────────────────────────────────────────────────

const registry = { nodes: [], totalQueries: 0, networkVersion: '0.2.0' };

// ── Job Queue ─────────────────────────────────────────────────────────────────

const jobs = new Map(); // jobId -> { id, messages, status, createdAt, nodeId, res, timer, message, clientIP }

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

function fogLog(hashedIP, message, responseMs, ok) {
  if (CONFIG.logFile === '/dev/null') return;
  try {
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
  if (!CONFIG.nodeSecret) {
    sendJSON(res, 403, { error: 'Node authentication is disabled' });
    return null;
  }

  const secret = req.headers['x-node-secret'];
  if (!secret || secret !== CONFIG.nodeSecret) {
    sendJSON(res, 401, { error: 'Invalid or missing secret' });
    return null;
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
    res.writeHead(204);
    res.end();
    return;
  }

  // Mark as processing
  oldestJob.status = 'processing';
  oldestJob.nodeId = node.id;

  sendJSON(res, 200, {
    jobId: oldestJob.id,
    messages: oldestJob.messages,
  });
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
  };

  registry.nodes.push(newNode);

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
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(self), geolocation=()');

  // CORS
  const origin = req.headers.origin;
  if (CONFIG.corsOrigin === '*' || origin === CONFIG.corsOrigin || origin === `http://localhost:${CONFIG.port}`) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Node-Secret, X-Node-Id');
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
  } else if (pathname === '/api/nodes/poll') {
    if (req.method !== 'GET') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    handlePoll(req, res);
  } else if (pathname.startsWith('/api/nodes/result/')) {
    if (req.method !== 'POST') { sendJSON(res, 405, { error: 'Method not allowed' }); return; }
    const jobId = pathname.slice('/api/nodes/result/'.length);
    handleResult(req, res, jobId);
  } else if (pathname === '/api/nodes/register') {
    handleRegister(req, res);
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
    for (const node of registry.nodes) {
      if (node.lastSeen && (now - new Date(node.lastSeen).getTime() > CONFIG.nodeStaleMs)) {
        node.status = 'offline';
      }
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
module.exports = server;
