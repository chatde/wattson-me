# Wattson V3 — AI For the World

## Session Continuity Document

> Any Claude session can read this file and pick up exactly where the last session left off.

---

## Vision

A peer-to-peer AI network powered by donated devices — old phones, Raspberry Pis, laptops, desktops. Anyone can contribute a device. Anyone can use the AI. No accounts. No cost. No corporate servers.

**The tagline:** "Powered by the devices you forgot about."

**The URL:** wattson.me

The idea: millions of old phones sit in drawers. Old laptops gather dust. Raspberry Pis run nothing. What if all those devices collectively served free AI to the world? That's Wattson.

You visit wattson.me, ask a question, and the network routes it to the nearest available device running Ollama. The AI runs locally on that device. The answer comes back to you. Zero cloud. Zero accounts. Zero cost.

---

## Architecture

### Core Principles
- **Zero npm dependencies** — pure Node.js only. No Express, no Socket.io, nothing. This runs on a Raspberry Pi 1 if needed.
- **Ollama everywhere** — every contributing device runs Ollama with whatever model fits its hardware.
- **Cloudflare Tunnel** — free, DDoS-protected, no port forwarding needed. The tunnel connects Mac (gateway) to wattson.me.
- **Single HTML SPA** — no React, no build step, no framework. One HTML file with inline CSS and JS. Works on any browser, any device.
- **Privacy by design** — IPs are hashed before logging. No accounts. No tracking. No cookies. Conversation logs store hashed IPs + truncated Q&A for abuse detection only.

### Network Topology
```
[User Browser] --> [Cloudflare Tunnel] --> [Mac Gateway :8093]
                                              |
                                    [Node Registry]
                                       /    |    \
                              [Note 9]  [Pi]  [Future nodes...]
                              (Ollama)  (Ollama)  (Ollama)
```

The Mac runs the gateway server (server.js on port 8093). Cloudflare Tunnel exposes it as wattson.me. The gateway holds a registry of all contributing nodes and routes chat requests to them.

### Current Stack
- **Gateway:** Node.js server (server.js), port 8093, Mac Mini M1
- **Tunnel:** cloudflared, connects to Cloudflare (wattson.me domain)
- **Frontend:** Single HTML SPA (public/index.html) with 5 pages: Home, About, Get Started, Meet Wattson, Connect
- **AI Backend:** Ollama on Note 9 (192.168.5.48:11434), model: wattson:chat (qwen3:1.7b)
- **Node Registry:** registry.json — static file listing all contributing nodes
- **LaunchAgent:** com.wattson.me (auto-starts server on boot)

---

## Contributor Power Modes

When someone contributes a device, they choose a power mode:

| Mode | Description | Best For |
|------|-------------|----------|
| **Full Force** | 100% dedicated to network. Device does nothing else. | Old phones plugged in, dedicated Pis, spare laptops |
| **Half Force** | Shared resources. AI runs but with lower priority. | Phone you still use occasionally |
| **Eco Mode** | Only serves when device is idle + charging. | Daily driver phone, work laptop |

Power modes are set by the contributor and reported to the registry. The gateway uses this info for routing decisions (prefer Full Force nodes first).

---

## Fragment & Redundancy System (Future)

For when the network grows beyond a single gateway:

- **Fragment routing:** Large queries split across multiple devices, answers reassembled
- **Redundancy:** Same query sent to 2+ nodes, fastest response wins, others cancelled
- **Failover:** If a node goes offline mid-query, auto-retry on next available node
- **Geographic routing:** Route to nearest node by latency (not IP geolocation)

This is Phase 3+ work. Not needed until we have 10+ nodes.

---

## Phased Build Plan

### Phase 1: Foundation (MVP) — COMPLETE

Get the core infrastructure running: server, frontend, tunnel, one node.

| Task | Status | Notes |
|------|--------|-------|
| 1.1 Install cloudflared | DONE | v2026.2.0 |
| 1.2 Create tunnel | IN PROGRESS | Awaiting browser auth |
| 1.3 Build API server | DONE | 18/18 tests pass |
| 1.4 Build frontend | DONE | SPA with 5 pages |
| 1.5 Create node registry | DONE | registry.json with Note 9 |
| 1.6 Create .env config | DONE | All settings configurable |
| 1.7 Create LaunchAgents | DONE | Server running on 8093 |
| 1.8 Test end-to-end | DONE | All endpoints verified |
| 1.9 Push to GitHub | DONE | github.com/chatde/wattson-me |

### Phase 2: Go Live

Get wattson.me actually serving public traffic.

| Task | Status | Notes |
|------|--------|-------|
| 2.1 Complete Cloudflare tunnel auth | DONE | Tunnel running via cloudflared |
| 2.2 Configure DNS (wattson.me -> tunnel) | DONE | CNAME to tunnel UUID |
| 2.3 SSL/TLS via Cloudflare | DONE | Full Strict mode, automatic |
| 2.4 Test public access | DONE | Verified from cellular |
| 2.5 Add CORS for wattson.me origin | DONE | Locked to https://wattson.me |
| 2.6 Monitor first 24 hours | DONE | Logs + rate limits working |

### Phase 3: Multi-Node

Add more devices to the network.

| Task | Status | Notes |
|------|--------|-------|
| 3.1 Add Pi 1 Model B as node | TODO | ARMv6, 475MB RAM — tiny model only |
| 3.2 Build node health-check system | DONE | Stale detection via lastSeen, marks offline |
| 3.3 Build smart routing | TODO | Route by: node health > power mode > latency |
| 3.4 Build contributor onboarding | DONE | Google Sign-In + token generation |
| 3.5 Add node auto-registration API | DONE | POST /api/nodes/register (with auth) |
| 3.6 Build contributor dashboard | DONE | Dashboard page with node management |

### Phase 4: Scale

Prepare for real traffic and many contributors.

| Task | Status | Notes |
|------|--------|-------|
| 4.1 Fragment & redundancy system | TODO | Split queries, parallel execution |
| 4.2 Geographic routing | TODO | Latency-based, not IP-based |
| 4.3 Rate limiting per-route | TODO | Different limits for chat vs static |
| 4.4 Abuse detection | TODO | Pattern matching on inputs |
| 4.5 Analytics dashboard | TODO | Public page: queries/day, nodes, uptime |
| 4.6 Model recommendations by hardware | TODO | Auto-suggest best model for device specs |

### Phase 5: Community

Build the contributor community.

| Task | Status | Notes |
|------|--------|-------|
| 5.1 Contributor leaderboard | TODO | Queries served, uptime, etc. |
| 5.2 Social sharing | TODO | "I power Wattson" badges |
| 5.3 Blog/updates page | TODO | Network milestones, new features |
| 5.4 Mobile app for contributors | TODO | Monitor your node from your phone |
| 5.5 Documentation site | TODO | Full setup guides per device type |

---

## Key Technical Decisions

### Why Zero Dependencies?
- Runs on anything. A Raspberry Pi 1 with 475MB RAM can run this.
- No supply chain attacks. No left-pad incidents. No npm audit warnings.
- No build step. Clone, run, done.
- Forces clean code. You can't hide behind frameworks.

### Why Cloudflare Tunnel?
- Free tier is generous (unlimited bandwidth).
- Built-in DDoS protection.
- No port forwarding needed (critical for home networks).
- Auto-SSL.
- If Cloudflare goes down, the whole internet has problems anyway.

### Why Ollama?
- Runs on everything: phones (Termux), Pis, laptops, desktops.
- Simple HTTP API. No CUDA setup, no Python environments.
- Model management built in. Pull a model, run it.
- Active community, frequent updates.

### Why Single HTML SPA?
- One file. No build. No webpack. No React hydration.
- Works on any browser, including old phones.
- Instant load. No JavaScript framework overhead.
- Easy to contribute to — it's just HTML, CSS, and vanilla JS.

### Why Not WebRTC/P2P Direct?
- NAT traversal is unreliable. Cloudflare Tunnel is reliable.
- P2P exposes contributor IPs. Tunnel hides them.
- P2P needs STUN/TURN servers (cost money). Tunnel is free.
- Future option: WebRTC for contributor-to-contributor, tunnel for public access.

---

## API Reference

### POST /api/chat
Send a message to Wattson.

**Request:**
```json
{
  "message": "What is the meaning of life?",
  "history": [
    { "role": "user", "text": "Hi" },
    { "role": "assistant", "text": "Hello! How can I help?" }
  ]
}
```

**Response:**
```json
{
  "response": "That's a deep question! Many philosophers..."
}
```

**Errors:** 400 (bad input), 429 (rate limited), 502 (AI offline)

### GET /api/network
Get network status.

**Response:**
```json
{
  "nodes": [{ "id": "node-1", "name": "Note 9", "type": "phone", ... }],
  "totalQueries": 42,
  "deviceCount": 1,
  "onlineCount": 1,
  "networkVersion": "0.1.0"
}
```

### GET /api/state
Proxy to Mind Bridge for Wattson's internal state.

### GET /health
Health check.

**Response:**
```json
{
  "status": "healthy",
  "ollamaAlive": true,
  "mindBridgeAlive": true,
  "uptime": 3600
}
```

---

## Security Model

- **IPs hashed** with SHA-256 + salt before any logging
- **Rate limiting:** 20/min, 100/hour per IP
- **Input validation:** Max 500 chars, HTML stripped, no null bytes
- **Output sanitization:** Strip `<think>` tags (qwen3 leaks these), strip HTML, strip markdown bold, truncate to 2000 chars
- **Directory traversal protection** on static file serving
- **Security headers** on all responses: X-Content-Type-Options, X-Frame-Options, Referrer-Policy, X-XSS-Protection, Permissions-Policy
- **CORS** locked to wattson.me origin (+ localhost for dev)
- **Body size limit:** 10KB max request body
- **No cookies, no sessions, no accounts** — nothing to steal

---

## File Structure

```
/Volumes/AI-Models/wattson-me/
  server.js          — Gateway server (zero dependencies)
  test.js            — Test suite (18 tests)
  registry.json      — Node registry (contributing devices)
  .env               — Configuration (not in git)
  .env.example       — Example config (in git)
  GAMEPLAN.md        — This file (session continuity)
  README.md          — Public README for GitHub
  public/
    index.html       — Single-page app (all 5 pages)
```

---

## Environment Variables

```bash
PORT=8093                           # Server port
HOST=0.0.0.0                       # Bind address
OLLAMA_URL=http://192.168.5.48:11434  # Primary Ollama node
CHAT_MODEL=wattson:chat             # Ollama model name
MIND_BRIDGE_URL=http://localhost:8081  # Wattson Mind Bridge
RATE_LIMIT_PER_MIN=20               # Per-IP per-minute limit
RATE_LIMIT_PER_HOUR=100             # Per-IP per-hour limit
MAX_INPUT_LENGTH=500                # Max message length
IP_SALT=<random-string>             # Salt for IP hashing
CORS_ORIGIN=https://wattson.me      # Allowed CORS origin
LOG_FILE=./conversations.jsonl      # Conversation log path
```

---

## LaunchAgents

### com.wattson.me.plist
- **Path:** ~/Library/LaunchAgents/com.wattson.me.plist
- **WorkingDirectory:** /Volumes/AI-Models/wattson-me
- **Program:** /opt/homebrew/bin/node server.js
- **Port:** 8093
- **KeepAlive:** true
- **RunAtLoad:** true

---

## Domain & DNS

- **Domain:** wattson.me (needs to be registered/configured)
- **DNS:** Cloudflare (free plan)
- **Tunnel:** cloudflared tunnel pointing to localhost:8093
- **SSL:** Automatic via Cloudflare (Full Strict)

---

## Current State (as of 2026-02-27)

- **wattson.me is LIVE** — publicly accessible via Cloudflare Tunnel
- Server running on port 8093 (Mac Mini M1 gateway)
- 54+ tests passing (pull-based architecture, auth, contributor endpoints)
- Frontend SPA complete with 5 pages + contributor dashboard
- Note 9 is first inference node (wattson:chat / qwen3:1.7b) via LaunchAgent
- Registry persistence saves node stats + totalQueries across restarts
- Conversation log rotation at 5MB (keeps 1 backup)
- Google Sign-In for contributor authentication
- LaunchAgents: com.wattson.me (server), com.wattson.node-note9 (inference client)
- Code pushed to github.com/chatde/wattson-me

### Next Immediate Steps
1. Add Pi 1 Model B as second inference node
2. Build smart routing (prefer healthier / faster nodes)
3. Add contributor onboarding flow (auto-token generation)
4. Public analytics dashboard

---

## Contributing

The project is open source at github.com/chatde/wattson-me. MIT license.

To contribute a device:
1. Install Ollama on your device
2. Pull a model that fits your hardware (e.g., `ollama pull qwen3:0.6b` for low-RAM devices)
3. Run Ollama (`ollama serve`)
4. Contact the project to get your node added to the registry

Future: auto-registration API (Phase 3.5) will make this self-service.

---

## Session Handoff Notes

When picking up this project in a new Claude session:

1. **Read this file first** — it has everything you need.
2. **Check server status:** `curl http://localhost:8093/health`
3. **Check tunnel status:** `cloudflared tunnel list`
4. **Run tests:** `cd /Volumes/AI-Models/wattson-me && node test.js`
5. **Key constraint:** Zero npm dependencies. Do not add any. Ever.
6. **Key constraint:** Single HTML file for frontend. No build step. No frameworks.
7. **Key constraint:** Privacy first. Hash IPs, no accounts, no tracking.
8. **Node path on Mac:** /opt/homebrew/bin/node (NOT /usr/local/bin/node)
9. **Phone Ollama:** 192.168.5.48:11434 (Note 9, may be offline — check first)
10. **qwen3 quirk:** Must send `think: false` in API calls or output goes to thinking field instead of content.
