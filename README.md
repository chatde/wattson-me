# Wattson — AI For the World

> Powered by the devices you forgot about.

**[wattson.me](https://wattson.me)**

A peer-to-peer AI network powered by any device people contribute — old phones, Raspberry Pis, laptops, desktops. Collectively they serve free AI to the world.

## How It Works

1. You ask a question at wattson.me
2. The network routes it to the nearest available device
3. AI runs locally on that device (no cloud)
4. The answer comes back to you

Zero accounts. Zero cost. Zero corporate servers.

## Architecture

- **Zero npm dependencies** — pure Node.js
- **Ollama** for local AI inference on any device
- **Cloudflare Tunnel** for secure, DDoS-protected access
- **Single HTML SPA** — no build step, works everywhere

## Quick Start

```bash
# Clone
git clone https://github.com/chatde/wattson-me.git
cd wattson-me

# Configure
cp .env.example .env
# Edit .env with your settings

# Run
node server.js

# Test
node test.js
```

## Contributing a Device

See the [Get Started](https://wattson.me/start) page for setup guides.

**Supported devices:**
- Android phones (Termux + Ollama)
- Raspberry Pi (1GB+ RAM)
- Linux/Mac/Windows laptops & desktops
- Anything that runs Ollama

## Power Modes

| Mode | Description | Best For |
|------|-------------|----------|
| Full Force | 100% dedicated to network | Plugged-in phones, old laptops |
| Half Force | Shared resources | Phone you still use |
| Eco Mode | Only when idle | Daily driver phone |

## License

MIT

## Links

- Website: [wattson.me](https://wattson.me)
- Open source: [github.com/chatde/wattson-me](https://github.com/chatde/wattson-me)

A project by GHB Ventures.
