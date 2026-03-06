# CLAUDE.md — Wattson.me

## What This Is

Peer-to-peer distributed AI network powered by donated devices (old phones, Raspberry Pis, laptops). Anyone visits wattson.me, asks a question, and the network routes it to the nearest available device running Ollama. Zero cloud, zero accounts, zero cost.

## Tech Stack

- **Runtime**: Node.js (zero npm dependencies — pure Node.js only, no Express, no Socket.io)
- **Frontend**: Single HTML SPA (`public/`) — no React, no build step, no framework
- **Entry point**: `server.js` (gateway)
- **Client lib**: `wattson-client.js`
- **Registry**: `registry.json` + `registry-state.json` + `tokens.json`
- **LLM runtime**: Ollama on each contributing device
- **Hosting**: Mac Mini :8093 via Cloudflare Tunnel → wattson.me (NOT Vercel)
- **GitHub**: chatde/wattson-me (SSH protocol)
- **Node**: /opt/homebrew/bin/node

## Key Paths

```
server.js               # Main gateway server (pure Node.js)
wattson-client.js       # Client library
public/                 # Static frontend (single HTML SPA)
registry.json           # Device registry definition
registry-state.json     # Live device state
tokens.json             # Auth tokens
test.js                 # Tests
GAMEPLAN.md             # Full architecture spec and current status — read before working
```

## Development Workflow

```bash
/opt/homebrew/bin/node server.js    # Start gateway server
/opt/homebrew/bin/node test.js      # Run tests

# Deploy: runs on Mac Mini at port 8093 via Cloudflare Tunnel
# NO Vercel — this is self-hosted
```

## Project-Specific Rules

- **No console.log in production code.**
- **Zero npm dependencies**: This is a hard architectural constraint — the server must run on a Raspberry Pi 1. Never add external packages to server.js or wattson-client.js.
- **No framework**: No Express, no Socket.io, no React. Pure Node.js + vanilla HTML/CSS/JS only.
- **No build step**: The frontend is a single HTML file. No bundler, no transpiler.
- **Privacy by design**: IPs are hashed before logging. No accounts, no tracking, no cookies. Do not add any user identification.
- **Hosting is NOT Vercel**: Wattson runs on Mac Mini :8093 via Cloudflare Tunnel. Do not add Vercel config.
- **GAMEPLAN.md**: Read before starting any work — it has full architecture and current build status.
- **Git**: SSH protocol (chatde on GitHub). Deployment is manual to Mac Mini — no CI/CD auto-deploy.
