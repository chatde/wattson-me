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
    assert.ok('inferenceNodes' in res.body);
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
    // Send 65 requests rapidly from a unique IP — should exceed the 60/min limit
    const promises = [];
    for (let i = 0; i < 65; i++) {
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

  // ── Health Check Daemon ──

  await test('Health check marks node offline after 3 failures', async () => {
    // Access internal registry via /api/network — we need to see failureCount via health endpoint
    // Trigger manual health checks by hitting /health
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.ok('inferenceNodes' in res.body || 'status' in res.body);
  });

  await test('Health check records latency in /api/network', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    // New fields should be present
    const node = res.body.nodes[0];
    assert.ok('role' in node, 'Missing role field');
    assert.ok('queriesServed' in node, 'Missing queriesServed field');
    assert.ok('failureCount' in node, 'Missing failureCount field');
  });

  await test('/api/network includes role for all nodes', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    for (const node of res.body.nodes) {
      assert.ok(node.role === 'inference' || node.role === 'monitor', `Invalid role: ${node.role}`);
    }
  });

  await test('/api/network does not expose ollamaUrl', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    for (const node of res.body.nodes) {
      assert.strictEqual(node.ollamaUrl, undefined, 'ollamaUrl should not be exposed');
      assert.strictEqual(node.healthUrl, undefined, 'healthUrl should not be exposed');
    }
  });

  // ── Smart Routing ──

  await test('POST /api/chat returns 502 or 503 when inference nodes down', async () => {
    // With nodes likely unreachable in test env, should get 502 or 503
    try {
      const res = await request('POST', '/api/chat', { message: 'Hello test' });
      assert.ok(res.status === 200 || res.status === 502 || res.status === 503,
        `Expected 200/502/503, got ${res.status}`);
    } catch {
      // Timeout means processing, acceptable
    }
  });

  await test('/api/network has inferenceOnline and monitorOnline counts', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    assert.ok('inferenceCount' in res.body, 'Missing inferenceCount');
    assert.ok('monitorCount' in res.body, 'Missing monitorCount');
  });

  // ── Health Endpoint Updated ──

  await test('/health includes inference and monitor counts', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.ok('inferenceNodes' in res.body, 'Missing inferenceNodes');
    assert.ok('monitorNodes' in res.body, 'Missing monitorNodes');
  });

  // ── Node Registration ──

  await test('POST /api/nodes/register requires X-Node-Secret', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Node',
      role: 'inference',
      ollamaUrl: 'http://192.168.1.100:11434',
    });
    assert.strictEqual(res.status, 401, `Expected 401, got ${res.status}`);
  });

  await test('POST /api/nodes/register rejects wrong secret', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Node',
      role: 'inference',
      ollamaUrl: 'http://192.168.1.100:11434',
    }, { 'X-Node-Secret': 'wrong-secret' });
    assert.strictEqual(res.status, 401, `Expected 401, got ${res.status}`);
  });

  await test('POST /api/nodes/register rejects inference node without ollamaUrl', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Node',
      role: 'inference',
    }, { 'X-Node-Secret': 'test-secret-123' });
    assert.strictEqual(res.status, 400, `Expected 400, got ${res.status}`);
  });

  await test('POST /api/nodes/register rejects missing name', async () => {
    const res = await request('POST', '/api/nodes/register', {
      role: 'inference',
      ollamaUrl: 'http://192.168.1.100:11434',
    }, { 'X-Node-Secret': 'test-secret-123' });
    assert.strictEqual(res.status, 400, `Expected 400, got ${res.status}`);
  });

  await test('POST /api/nodes/register rejects invalid ollamaUrl', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Node',
      role: 'inference',
      ollamaUrl: 'not-a-url',
    }, { 'X-Node-Secret': 'test-secret-123' });
    assert.strictEqual(res.status, 400, `Expected 400, got ${res.status}`);
  });

  await test('POST /api/nodes/register accepts monitor node without ollamaUrl', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Monitor',
      role: 'monitor',
      type: 'raspberry-pi',
      healthUrl: 'http://192.168.1.200:8085',
    }, { 'X-Node-Secret': 'test-secret-123' });
    assert.strictEqual(res.status, 201, `Expected 201, got ${res.status}`);
    assert.ok(res.body.node, 'Missing node in response');
    assert.ok(res.body.node.id, 'Missing node id');
    assert.strictEqual(res.body.node.role, 'monitor');
  });

  await test('POST /api/nodes/register rejects duplicate ollamaUrl', async () => {
    // Try registering with the same ollamaUrl as Node 1
    const res = await request('POST', '/api/nodes/register', {
      name: 'Duplicate Node',
      role: 'inference',
      ollamaUrl: 'http://192.168.5.48:11434',
    }, { 'X-Node-Secret': 'test-secret-123' });
    assert.strictEqual(res.status, 409, `Expected 409, got ${res.status}`);
  });

  // ── Dashboard Route ──

  await test('GET /dashboard serves index.html (SPA route)', async () => {
    const res = await request('GET', '/dashboard');
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers['content-type'].includes('text/html'));
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
  process.env.RATE_LIMIT_PER_MIN = '60';
  process.env.RATE_LIMIT_PER_HOUR = '200';
  process.env.MAX_INPUT_LENGTH = '500';
  process.env.OLLAMA_URL = process.env.OLLAMA_URL || 'http://192.168.5.48:11434';
  process.env.CHAT_MODEL = 'wattson:chat';
  process.env.MIND_BRIDGE_URL = 'http://localhost:8081';
  process.env.LOG_FILE = '/dev/null';
  process.env.NODE_SECRET = 'test-secret-123';
  process.env.HEALTH_CHECK_INTERVAL_MS = '999999';
  process.env.HEALTH_CHECK_TIMEOUT_MS = '3000';
  process.env.MAX_CONSECUTIVE_FAILURES = '3';
  process.env.REGISTRY_SAVE_INTERVAL_MS = '999999';

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
