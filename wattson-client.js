#!/usr/bin/env node
// Wattson Network Contributor Client
// Zero-dependency. Download and run to contribute your device.
//
// Usage:
//   WATTSON_SERVER=https://wattson.me NODE_SECRET=xxx node wattson-client.js
//
// Config (env vars):
//   WATTSON_SERVER  — Server URL (required)
//   NODE_SECRET     — Shared secret (required)
//   OLLAMA_URL      — Local Ollama (default: http://localhost:11434)
//   NODE_NAME       — Display name (default: hostname)
//   MODEL           — Ollama model (default: wattson:chat)
//   POWER_MODE      — FULL_FORCE | HALF_FORCE | ECO (default: FULL_FORCE)
//   POLL_INTERVAL_MS — Poll delay when idle (default: 5000)

const http = require('http');
const https = require('https');
const os = require('os');

const SERVER = process.env.WATTSON_SERVER;
const SECRET = process.env.NODE_SECRET;
const OLLAMA_URL = process.env.OLLAMA_URL || 'http://localhost:11434';
const NODE_NAME = process.env.NODE_NAME || os.hostname();
const MODEL = process.env.MODEL || 'wattson:chat';
const POWER_MODE = process.env.POWER_MODE || 'FULL_FORCE';
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || '5000', 10);

if (!SERVER) { fatal('WATTSON_SERVER is required (e.g. https://wattson.me)'); }
if (!SECRET) { fatal('NODE_SECRET is required'); }

let nodeId = null;
let running = true;
let consecutive401s = 0;

// ── HTTP ────────────────────────────────────────────────────────────────────

function fetchJSON(method, url, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const mod = parsed.protocol === 'https:' ? https : http;
    const payload = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
        ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {}),
      },
      timeout: 30000,
    };
    const req = mod.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
        if (data.length > 1048576) { res.destroy(); reject(new Error('Response too large')); return; }
      });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Timeout')); });
    if (payload) req.write(payload);
    req.end();
  });
}

// ── Register ────────────────────────────────────────────────────────────────

async function register() {
  const totalMem = Math.round(os.totalmem() / 1024 / 1024 / 1024 * 10) / 10;
  const cpuModel = os.cpus().length > 0 ? os.cpus()[0].model : 'unknown';
  const res = await fetchJSON('POST', `${SERVER}/api/nodes/register`, {
    name: NODE_NAME,
    role: 'inference',
    type: os.platform() === 'android' ? 'phone' : os.platform(),
    model: MODEL,
    powerMode: POWER_MODE,
    specs: { ram: `${totalMem}GB`, cpu: cpuModel, os: os.platform() },
  }, { 'X-Node-Secret': SECRET });

  if (res.status !== 201) {
    throw new Error(`Registration failed (${res.status}): ${JSON.stringify(res.body)}`);
  }

  nodeId = res.body.node.id;
  log(`Registered as ${nodeId} (${NODE_NAME})`);
}

// ── Poll Loop ───────────────────────────────────────────────────────────────

async function pollLoop() {
  while (running) {
    try {
      const res = await fetchJSON('GET', `${SERVER}/api/nodes/poll`, null, {
        'X-Node-Secret': SECRET,
        'X-Node-Id': nodeId,
      });

      if (res.status === 204) {
        consecutive401s = 0;
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      if (res.status === 401) {
        consecutive401s++;
        if (consecutive401s >= 3) {
          log('Node unregistered — attempting re-registration...');
          consecutive401s = 0;
          try {
            await register();
            log('Re-registered successfully');
          } catch (err) {
            log(`Re-registration failed: ${err.message} — retrying in 30s`);
            await sleep(30000);
          }
          continue;
        }
        log(`Poll 401 (${consecutive401s}/3)`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      if (res.status !== 200) {
        consecutive401s = 0;
        log(`Poll error: ${res.status}`);
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      consecutive401s = 0;

      // Handle config updates
      if (res.body.configUpdate) {
        const cfg = res.body.configUpdate;
        log(`Config update received: powerMode=${cfg.powerMode}`);
      }

      // No job — config-only response
      if (!res.body.jobId) {
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      const { jobId, messages } = res.body;
      log(`Job ${jobId} received`);

      const start = Date.now();
      try {
        const ollamaRes = await fetchJSON('POST', `${OLLAMA_URL}/api/chat`, {
          model: MODEL,
          messages,
          stream: false,
          think: false,
          options: { num_ctx: 512, num_predict: 256, temperature: 0.8 },
        });

        const response = ollamaRes.body?.message?.content || '';
        const elapsed = Date.now() - start;

        const resultRes = await fetchJSON('POST', `${SERVER}/api/nodes/result/${jobId}`, {
          response,
        }, { 'X-Node-Secret': SECRET, 'X-Node-Id': nodeId });

        if (resultRes.status === 200) {
          log(`Job ${jobId} done (${elapsed}ms)`);
        } else {
          log(`Result rejected (${resultRes.status}): ${JSON.stringify(resultRes.body)}`);
        }
      } catch (err) {
        log(`Ollama error: ${err.message}`);
      }
    } catch (err) {
      log(`Network error: ${err.message}`);
      await sleep(POLL_INTERVAL_MS);
    }
  }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

function log(msg) {
  process.stdout.write(`[wattson] ${new Date().toISOString().slice(11, 19)} ${msg}\n`);
}

function fatal(msg) {
  process.stderr.write(`Error: ${msg}\n`);
  process.exit(1);
}

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

// ── Main ────────────────────────────────────────────────────────────────────

async function main() {
  log(`Connecting to ${SERVER}...`);
  try {
    await register();
  } catch (err) {
    fatal(err.message);
  }
  log(`Polling every ${POLL_INTERVAL_MS}ms (model: ${MODEL})`);
  pollLoop();
}

process.on('SIGINT', () => { running = false; log('Shutting down...'); });
process.on('SIGTERM', () => { running = false; log('Shutting down...'); });

main();
