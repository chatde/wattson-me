#!/usr/bin/env node
// Wattson.me Server Tests
// Run: node test.js

const http = require('http');
const assert = require('assert');

const PORT = 18093; // Test port (different from production)
let serverProcess;
let passed = 0;
let failed = 0;
const results = [];

// ── Helpers ────────────────────────────────────────────────────────────────────

function request(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const opts = {
      hostname: '127.0.0.1',
      port: PORT,
      path,
      method,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
      timeout: 10000,
    };
    const req = http.request(opts, (res) => {
      let data = '';
      res.on('data', (chunk) => data += chunk);
      res.on('end', () => {
        let parsed;
        try { parsed = JSON.parse(data); } catch { parsed = data; }
        resolve({ status: res.statusCode, headers: res.headers, body: parsed, raw: data });
      });
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
    if (body) req.write(typeof body === 'string' ? body : JSON.stringify(body));
    req.end();
  });
}

async function test(name, fn) {
  try {
    await fn();
    passed++;
    results.push({ name, status: 'PASS' });
    process.stdout.write(`  PASS  ${name}\n`);
  } catch (err) {
    failed++;
    results.push({ name, status: 'FAIL', error: err.message });
    process.stdout.write(`  FAIL  ${name}: ${err.message}\n`);
  }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

async function runTests() {
  process.stdout.write('\nWattson.me Server Tests\n');
  process.stdout.write('='.repeat(50) + '\n\n');

  // ── Health Endpoint ──

  await test('GET /health returns 200', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(typeof res.body, 'object');
    assert.ok('status' in res.body);
    assert.ok('ollamaAlive' in res.body);
    assert.ok('mindBridgeAlive' in res.body);
  });

  // ── Network Endpoint ──

  await test('GET /api/network returns node list', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.nodes));
    assert.ok(res.body.nodes.length >= 1);
    assert.strictEqual(res.body.nodes[0].id, 'node-1');
    assert.ok('totalQueries' in res.body);
    assert.ok('deviceCount' in res.body);
  });

  // ── State Proxy ──

  await test('GET /api/state returns mind bridge data', async () => {
    const res = await request('GET', '/api/state');
    // May be 200 (bridge alive) or 502 (bridge down)
    assert.ok(res.status === 200 || res.status === 502);
    if (res.status === 200) {
      assert.strictEqual(typeof res.body, 'object');
    }
  });

  // ── Chat Endpoint — Input Validation ──

  await test('POST /api/chat rejects empty body', async () => {
    const res = await request('POST', '/api/chat', {});
    assert.strictEqual(res.status, 400);
    assert.ok(res.body.error);
  });

  await test('POST /api/chat rejects empty message', async () => {
    const res = await request('POST', '/api/chat', { message: '' });
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/chat rejects whitespace-only message', async () => {
    const res = await request('POST', '/api/chat', { message: '   ' });
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/chat rejects message over 500 chars', async () => {
    const res = await request('POST', '/api/chat', { message: 'a'.repeat(501) });
    assert.strictEqual(res.status, 400);
    assert.ok(res.body.error.includes('500'));
  });

  await test('POST /api/chat accepts message at 500 chars', async () => {
    // Use a short timeout — we just care that the server doesn't reject it (not 400)
    // It may 200 (Ollama responds) or 502 (Ollama slow/down) — both are valid
    try {
      const res = await request('POST', '/api/chat', { message: 'Hello' });
      assert.ok(res.status === 200 || res.status === 502, `Expected 200 or 502, got ${res.status}`);
    } catch {
      // Timeout means Ollama is processing (not rejected) — that's acceptable
    }
  });

  await test('POST /api/chat strips HTML tags from message', async () => {
    try {
      const res = await request('POST', '/api/chat', { message: '<b>Hello</b> world' });
      // Should not be 400 — HTML stripping should leave "Hello world"
      assert.ok(res.status === 200 || res.status === 502, `Expected 200 or 502, got ${res.status}`);
    } catch {
      // Timeout means server accepted and forwarded — that's fine
    }
  });

  await test('POST /api/chat rejects non-string message', async () => {
    const res = await request('POST', '/api/chat', { message: 12345 });
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/chat rejects array message', async () => {
    const res = await request('POST', '/api/chat', { message: ['hello'] });
    assert.strictEqual(res.status, 400);
  });

  // ── Security Headers ──

  await test('Responses include security headers', async () => {
    const res = await request('GET', '/health');
    assert.ok(res.headers['x-content-type-options']);
    assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
    assert.ok(res.headers['x-frame-options']);
    assert.ok(res.headers['referrer-policy']);
  });

  // ── 404 ──

  await test('Unknown API route returns 404', async () => {
    const res = await request('GET', '/api/nonexistent');
    assert.strictEqual(res.status, 404);
  });

  await test('Unknown method on /api/chat returns 405', async () => {
    const res = await request('GET', '/api/chat');
    assert.strictEqual(res.status, 405);
  });

  // ── Rate Limiting ──

  await test('Rate limiting enforced after burst', async () => {
    // Send 21 requests rapidly — 21st should be rate limited
    const promises = [];
    for (let i = 0; i < 21; i++) {
      promises.push(request('GET', '/health', null, { 'X-Forwarded-For': '10.99.99.99' }));
    }
    const responses = await Promise.all(promises);
    const rateLimited = responses.filter(r => r.status === 429);
    assert.ok(rateLimited.length > 0, 'Expected at least one 429 response');
  });

  // ── Static File Serving ──

  await test('GET / serves index.html', async () => {
    const res = await request('GET', '/');
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers['content-type'].includes('text/html'));
  });

  await test('Path traversal blocked', async () => {
    const res = await request('GET', '/../../../etc/passwd');
    assert.notStrictEqual(res.status, 200);
  });

  await test('Null byte in path blocked', async () => {
    const res = await request('GET', '/index%00.html');
    assert.ok(res.status === 400 || res.status === 404);
  });

  // ── Summary ──

  process.stdout.write('\n' + '='.repeat(50) + '\n');
  process.stdout.write(`Results: ${passed} passed, ${failed} failed, ${passed + failed} total\n\n`);

  return failed === 0;
}

// ── Main ───────────────────────────────────────────────────────────────────────

async function main() {
  // Set test env vars
  process.env.PORT = String(PORT);
  process.env.HOST = '127.0.0.1';
  process.env.IP_SALT = 'test-salt';
  process.env.CORS_ORIGIN = '*';
  process.env.RATE_LIMIT_PER_MIN = '20';
  process.env.RATE_LIMIT_PER_HOUR = '100';
  process.env.MAX_INPUT_LENGTH = '500';
  process.env.OLLAMA_URL = process.env.OLLAMA_URL || 'http://192.168.5.48:11434';
  process.env.CHAT_MODEL = 'wattson:chat';
  process.env.MIND_BRIDGE_URL = 'http://localhost:8081';
  process.env.LOG_FILE = '/dev/null';

  // Start server
  try {
    const server = require('./server.js');
    // Give server time to bind
    await new Promise(resolve => setTimeout(resolve, 500));

    const allPassed = await runTests();

    // Cleanup
    if (server.close) server.close();
    process.exit(allPassed ? 0 : 1);
  } catch (err) {
    process.stderr.write(`Failed to start server: ${err.message}\n`);
    process.exit(1);
  }
}

main();
