#!/usr/bin/env node
// Wattson.me Server Tests — Pull-Based Architecture
// Run: node test.js

const http = require('http');
const assert = require('assert');

const PORT = 18093; // Test port (different from production)
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

let registeredNodeId = null;
const AUTH = { 'X-Node-Secret': 'test-secret-123' };

async function runTests() {
  process.stdout.write('\nWattson.me Server Tests (Pull-Based Architecture)\n');
  process.stdout.write('='.repeat(50) + '\n\n');

  // ── Health Endpoint ──

  await test('GET /health returns 200', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.strictEqual(typeof res.body, 'object');
    assert.ok('status' in res.body);
    assert.ok('inferenceNodes' in res.body);
    assert.ok('pendingJobs' in res.body);
    assert.ok('uptime' in res.body);
  });

  // ── Chat Input Validation ──

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

  await test('POST /api/chat rejects non-string message', async () => {
    const res = await request('POST', '/api/chat', { message: 12345 });
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/chat rejects array message', async () => {
    const res = await request('POST', '/api/chat', { message: ['hello'] });
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/chat strips HTML tags from message', async () => {
    // With no nodes registered, should get 503 (not 400 — HTML stripping leaves valid text)
    const res = await request('POST', '/api/chat', { message: '<b>Hello</b> world' });
    assert.strictEqual(res.status, 503, `Expected 503 (no nodes), got ${res.status}`);
  });

  await test('POST /api/chat returns 503 when no nodes registered', async () => {
    const res = await request('POST', '/api/chat', { message: 'Hello' });
    assert.strictEqual(res.status, 503);
    assert.ok(res.body.error.includes('No inference'));
  });

  // ── Security Headers ──

  await test('Responses include security headers', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.headers['x-content-type-options'], 'nosniff');
    assert.ok(res.headers['x-frame-options']);
    assert.ok(res.headers['referrer-policy']);
  });

  // ── 404/405 ──

  await test('Unknown API route returns 404', async () => {
    const res = await request('GET', '/api/nonexistent');
    assert.strictEqual(res.status, 404);
  });

  await test('GET /api/chat returns 405', async () => {
    const res = await request('GET', '/api/chat');
    assert.strictEqual(res.status, 405);
  });

  // ── Rate Limiting ──

  await test('Rate limiting enforced after burst', async () => {
    const promises = [];
    for (let i = 0; i < 65; i++) {
      promises.push(request('GET', '/health', null, { 'X-Forwarded-For': '10.99.99.99' }));
    }
    const responses = await Promise.all(promises);
    const rateLimited = responses.filter(r => r.status === 429);
    assert.ok(rateLimited.length > 0, 'Expected at least one 429 response');
  });

  // ── Static Files ──

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

  await test('GET /dashboard serves index.html (SPA route)', async () => {
    const res = await request('GET', '/dashboard');
    assert.strictEqual(res.status, 200);
    assert.ok(res.headers['content-type'].includes('text/html'));
  });

  // ── Node Registration ──

  await test('POST /api/nodes/register requires X-Node-Secret', async () => {
    const res = await request('POST', '/api/nodes/register', { name: 'Test Node' });
    assert.strictEqual(res.status, 401);
  });

  await test('POST /api/nodes/register rejects wrong secret', async () => {
    const res = await request('POST', '/api/nodes/register',
      { name: 'Test Node' },
      { 'X-Node-Secret': 'wrong-secret' }
    );
    assert.strictEqual(res.status, 401);
  });

  await test('POST /api/nodes/register rejects missing name', async () => {
    const res = await request('POST', '/api/nodes/register',
      { role: 'inference' }, AUTH
    );
    assert.strictEqual(res.status, 400);
  });

  await test('POST /api/nodes/register accepts valid inference node', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Phone',
      role: 'inference',
      type: 'phone',
      model: 'wattson:chat',
      modelSize: '1.7b',
      powerMode: 'FULL_FORCE',
      specs: { ram: '4GB' },
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.node);
    assert.ok(res.body.node.id);
    assert.strictEqual(res.body.node.role, 'inference');
    registeredNodeId = res.body.node.id;
  });

  await test('POST /api/nodes/register accepts monitor node', async () => {
    const res = await request('POST', '/api/nodes/register', {
      name: 'Test Monitor',
      role: 'monitor',
      type: 'raspberry-pi',
    }, AUTH);
    assert.strictEqual(res.status, 201);
    assert.ok(res.body.node);
    assert.strictEqual(res.body.node.role, 'monitor');
  });

  // ── Node Poll ──

  await test('GET /api/nodes/poll requires auth (401 without secret)', async () => {
    const res = await request('GET', '/api/nodes/poll');
    assert.strictEqual(res.status, 401);
  });

  await test('GET /api/nodes/poll requires X-Node-Id (401 without)', async () => {
    const res = await request('GET', '/api/nodes/poll', null, AUTH);
    assert.strictEqual(res.status, 401);
  });

  await test('GET /api/nodes/poll rejects unregistered node ID', async () => {
    const res = await request('GET', '/api/nodes/poll', null, {
      ...AUTH, 'X-Node-Id': 'node-fake-123',
    });
    assert.strictEqual(res.status, 401);
  });

  await test('GET /api/nodes/poll returns 204 when queue empty', async () => {
    const res = await request('GET', '/api/nodes/poll', null, {
      ...AUTH, 'X-Node-Id': registeredNodeId,
    });
    assert.strictEqual(res.status, 204);
  });

  // ── End-to-End Flow ──

  await test('Full flow: chat → poll → result → response delivered', async () => {
    const nodeAuth = { ...AUTH, 'X-Node-Id': registeredNodeId };

    // 1. Fire chat request (don't await — it's held open)
    const chatPromise = request('POST', '/api/chat', { message: 'What is 2+2?' });

    // 2. Give server time to create the job
    await new Promise(r => setTimeout(r, 100));

    // 3. Poll for the job
    const pollRes = await request('GET', '/api/nodes/poll', null, nodeAuth);
    assert.strictEqual(pollRes.status, 200);
    assert.ok(pollRes.body.jobId);
    assert.ok(Array.isArray(pollRes.body.messages));

    // 4. Post result
    const resultRes = await request('POST', `/api/nodes/result/${pollRes.body.jobId}`, {
      response: 'The answer is 4.',
    }, nodeAuth);
    assert.strictEqual(resultRes.status, 200);
    assert.ok(resultRes.body.ok);

    // 5. Chat request should now resolve with the response
    const chatRes = await chatPromise;
    assert.strictEqual(chatRes.status, 200);
    assert.strictEqual(chatRes.body.response, 'The answer is 4.');
  });

  await test('GET /api/nodes/poll marks job as processing (skips it on next poll)', async () => {
    const nodeAuth = { ...AUTH, 'X-Node-Id': registeredNodeId };

    // Fire a chat request
    const chatPromise = request('POST', '/api/chat', { message: 'Test processing' });
    await new Promise(r => setTimeout(r, 100));

    // First poll picks up the job
    const poll1 = await request('GET', '/api/nodes/poll', null, nodeAuth);
    assert.strictEqual(poll1.status, 200);

    // Second poll should find no pending jobs
    const poll2 = await request('GET', '/api/nodes/poll', null, nodeAuth);
    assert.strictEqual(poll2.status, 204);

    // Clean up: post result so the chat resolves
    await request('POST', `/api/nodes/result/${poll1.body.jobId}`, {
      response: 'Done',
    }, nodeAuth);
    await chatPromise;
  });

  // ── Node Result Validation ──

  await test('POST /api/nodes/result requires auth headers', async () => {
    const res = await request('POST', '/api/nodes/result/fake-job-id', {
      response: 'test',
    });
    assert.strictEqual(res.status, 401);
  });

  await test('POST /api/nodes/result returns 404 for unknown jobId', async () => {
    const nodeAuth = { ...AUTH, 'X-Node-Id': registeredNodeId };
    const res = await request('POST', '/api/nodes/result/nonexistent-job', {
      response: 'test',
    }, nodeAuth);
    assert.strictEqual(res.status, 404);
  });

  await test('POST /api/nodes/result rejects empty response', async () => {
    const nodeAuth = { ...AUTH, 'X-Node-Id': registeredNodeId };

    // Create a job and poll it
    const chatPromise = request('POST', '/api/chat', { message: 'Empty response test' });
    await new Promise(r => setTimeout(r, 100));
    const pollRes = await request('GET', '/api/nodes/poll', null, nodeAuth);
    assert.strictEqual(pollRes.status, 200);

    // Post empty response — should be rejected
    const res = await request('POST', `/api/nodes/result/${pollRes.body.jobId}`, {
      response: '',
    }, nodeAuth);
    assert.strictEqual(res.status, 400);

    // Wait for the held chat request to timeout (JOB_TIMEOUT_MS=3000)
    const chatRes = await chatPromise;
    assert.strictEqual(chatRes.status, 504);
  });

  await test('POST /api/nodes/result updates node stats', async () => {
    const nodeAuth = { ...AUTH, 'X-Node-Id': registeredNodeId };

    // Do a full round-trip
    const chatPromise = request('POST', '/api/chat', { message: 'Stats test' });
    await new Promise(r => setTimeout(r, 100));
    const pollRes = await request('GET', '/api/nodes/poll', null, nodeAuth);
    await request('POST', `/api/nodes/result/${pollRes.body.jobId}`, {
      response: 'Stats verified.',
    }, nodeAuth);
    await chatPromise;

    // Check network endpoint for updated stats
    const netRes = await request('GET', '/api/network');
    const node = netRes.body.nodes.find(n => n.id === registeredNodeId);
    assert.ok(node);
    assert.ok(node.queriesServed >= 1, `Expected queriesServed >= 1, got ${node.queriesServed}`);
    assert.ok(node.averageResponseMs > 0, 'Expected averageResponseMs > 0');
  });

  // ── Job Timeout ──

  await test('POST /api/chat times out when no node picks up', async () => {
    const start = Date.now();
    const res = await request('POST', '/api/chat', { message: 'Timeout test' });
    const elapsed = Date.now() - start;
    assert.strictEqual(res.status, 504);
    assert.ok(res.body.error.includes('busy'));
    assert.ok(elapsed >= 2500, `Expected timeout >= 2500ms, got ${elapsed}ms`);
  });

  // ── Network Endpoint (with nodes registered) ──

  await test('GET /api/network returns node list', async () => {
    const res = await request('GET', '/api/network');
    assert.strictEqual(res.status, 200);
    assert.ok(Array.isArray(res.body.nodes));
    assert.ok(res.body.nodes.length >= 1);
    assert.ok('totalQueries' in res.body);
    assert.ok('deviceCount' in res.body);
    assert.ok('pendingJobs' in res.body);
    assert.ok('processingJobs' in res.body);
  });

  await test('/api/network includes lastSeen for nodes', async () => {
    const res = await request('GET', '/api/network');
    const node = res.body.nodes.find(n => n.id === registeredNodeId);
    assert.ok(node);
    assert.ok(node.lastSeen, 'Missing lastSeen field');
    assert.ok(node.queriesServed !== undefined, 'Missing queriesServed field');
  });

  await test('/api/network does not expose internal fields', async () => {
    const res = await request('GET', '/api/network');
    for (const node of res.body.nodes) {
      assert.strictEqual(node.ollamaUrl, undefined, 'ollamaUrl should not be exposed');
    }
  });

  await test('/health includes job queue stats', async () => {
    const res = await request('GET', '/health');
    assert.strictEqual(res.status, 200);
    assert.ok('inferenceNodes' in res.body);
    assert.ok('monitorNodes' in res.body);
    assert.ok('pendingJobs' in res.body);
    assert.ok('processingJobs' in res.body);
    assert.ok('totalQueries' in res.body);
  });

  // ── Auth Endpoints ──

  await test('POST /api/auth/google with missing credential returns 400', async () => {
    const res = await request('POST', '/api/auth/google', {});
    assert.strictEqual(res.status, 400);
    assert.ok(res.body.error);
  });

  await test('POST /api/auth/google with invalid JWT returns 401', async () => {
    const res = await request('POST', '/api/auth/google', { credential: 'not.a.valid.jwt' });
    assert.strictEqual(res.status, 401);
    assert.ok(res.body.error);
  });

  await test('GET /api/auth/me without Authorization returns 401', async () => {
    const res = await request('GET', '/api/auth/me');
    assert.strictEqual(res.status, 401);
    assert.ok(res.body.error);
  });

  await test('GET /api/auth/me with bad token returns 401', async () => {
    const res = await request('GET', '/api/auth/me', null, {
      'Authorization': 'Bearer wm_bad_token_1234567890abcdef',
    });
    assert.strictEqual(res.status, 401);
    assert.ok(res.body.error);
  });

  await test('GET /api/auth/tokens without admin secret returns 401', async () => {
    const res = await request('GET', '/api/auth/tokens');
    assert.strictEqual(res.status, 401);
    assert.ok(res.body.error);
  });

  // ── Setup Endpoint ──

  await test('GET /api/setup returns Mac steps for Mac UA', async () => {
    const res = await request('GET', '/api/setup', null, {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.os, 'mac');
    assert.strictEqual(res.body.supported, true);
    assert.ok(Array.isArray(res.body.steps));
    assert.ok(res.body.steps.length >= 2, 'Expected at least 2 steps');
    assert.ok(res.body.quickCommand, 'Expected quickCommand for Mac');
    assert.ok(res.body.quickCommand.includes('setup.sh'));
  });

  await test('GET /api/setup returns Android steps', async () => {
    const res = await request('GET', '/api/setup', null, {
      'User-Agent': 'Mozilla/5.0 (Linux; Android 13; SM-N960F) AppleWebKit/537.36',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.os, 'android');
    assert.ok(res.body.model.includes('qwen3'));
  });

  await test('GET /api/setup returns unsupported for iOS', async () => {
    const res = await request('GET', '/api/setup', null, {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.supported, false);
    assert.strictEqual(res.body.os, 'ios');
  });

  // ── Device Chooser & Monitor Node ──

  await test('GET /api/setup?device=iphone returns supported + monitor role', async () => {
    const res = await request('GET', '/api/setup?device=iphone', null, {
      'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.supported, true);
    assert.strictEqual(res.body.os, 'ios');
    assert.strictEqual(res.body.role, 'monitor');
    assert.strictEqual(res.body.model, null);
    assert.ok(res.body.message.includes('monitor'));
    assert.ok(Array.isArray(res.body.steps));
    assert.ok(res.body.steps.length >= 1);
  });

  await test('GET /api/setup?device=android overrides Mac UA detection', async () => {
    const res = await request('GET', '/api/setup?device=android', null, {
      'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
    });
    assert.strictEqual(res.status, 200);
    assert.strictEqual(res.body.os, 'android');
    assert.strictEqual(res.body.role, 'inference');
    assert.strictEqual(res.body.supported, true);
  });

  let monitorNodeId = null;

  await test('Monitor node poll returns 204 without stealing queued job', async () => {
    // Register a monitor node
    const regRes = await request('POST', '/api/nodes/register', {
      name: 'iPhone Monitor',
      role: 'monitor',
      type: 'iphone',
    }, AUTH);
    assert.strictEqual(regRes.status, 201);
    monitorNodeId = regRes.body.node.id;

    // Fire a chat request to create a pending job
    const chatPromise = request('POST', '/api/chat', { message: 'Monitor test' });
    await new Promise(r => setTimeout(r, 100));

    // Monitor node polls — should get 204 (no job), NOT 200
    const pollRes = await request('GET', '/api/nodes/poll', null, {
      ...AUTH, 'X-Node-Id': monitorNodeId,
    });
    assert.strictEqual(pollRes.status, 204);

    // Inference node should still be able to pick up the job
    const infPollRes = await request('GET', '/api/nodes/poll', null, {
      ...AUTH, 'X-Node-Id': registeredNodeId,
    });
    assert.strictEqual(infPollRes.status, 200);
    assert.ok(infPollRes.body.jobId);

    // Clean up
    await request('POST', `/api/nodes/result/${infPollRes.body.jobId}`, {
      response: 'Monitor test done.',
    }, { ...AUTH, 'X-Node-Id': registeredNodeId });
    await chatPromise;
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
  process.env.LOG_FILE = '/dev/null';
  process.env.NODE_SECRET = 'test-secret-123';
  process.env.JOB_TIMEOUT_MS = '3000';
  process.env.JOB_CLEANUP_INTERVAL_MS = '999999';
  process.env.MAX_QUEUE_SIZE = '100';
  process.env.NODE_STALE_MS = '999999';
  process.env.GOOGLE_CLIENT_ID = 'test-client-id.apps.googleusercontent.com';

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
