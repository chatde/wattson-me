#!/bin/bash
# Wattson.me Auto-Setup
# Usage: curl -fsSL https://wattson.me/setup.sh | bash
#
# Detects your platform, installs Ollama, picks the best model
# for your hardware, and downloads the contributor client.

set -e

echo ""
echo "  Wattson.me Auto-Setup"
echo "  ====================="
echo ""

# ── Platform Detection ────────────────────────────────────────────────────────

PLATFORM="linux"
if [ -d "/data/data/com.termux" ]; then
  PLATFORM="termux"
elif [ "$(uname 2>/dev/null)" = "Darwin" ]; then
  PLATFORM="mac"
fi

echo "  Platform: $PLATFORM"

# ── RAM Detection & Model Selection ───────────────────────────────────────────

RAM_MB=0
if [ "$PLATFORM" = "mac" ]; then
  RAM_MB=$(( $(sysctl -n hw.memsize 2>/dev/null || echo 0) / 1048576 ))
elif [ -f /proc/meminfo ]; then
  RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
  RAM_MB=$(( RAM_KB / 1024 ))
fi

echo "  RAM: ${RAM_MB}MB"

MODEL="qwen3:0.6b"
if [ "$RAM_MB" -ge 8000 ]; then
  MODEL="llama3.1:8b-q4"
elif [ "$RAM_MB" -ge 2000 ]; then
  MODEL="qwen3:1.7b"
fi

echo "  Model: $MODEL"
echo ""

# ── Install Ollama ────────────────────────────────────────────────────────────

if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
  echo "  [ok] Ollama already running"
elif [ "$PLATFORM" = "termux" ]; then
  # On Termux, Ollama runs inside proot-distro (debian)
  if command -v proot-distro >/dev/null 2>&1; then
    echo "  Starting Ollama via proot-distro..."
    proot-distro login debian -- bash -c "export OLLAMA_HOST=127.0.0.1:11434; ollama serve" >/dev/null 2>&1 &
    echo "  Waiting for Ollama to start..."
    for i in $(seq 1 30); do
      curl -sf http://localhost:11434/api/tags >/dev/null 2>&1 && break
      sleep 2
    done
    if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
      echo "  [ok] Ollama started"
    else
      echo "  ERROR: Ollama failed to start."
      echo "  Try manually: proot-distro login debian -- bash -c 'OLLAMA_HOST=127.0.0.1:11434 ollama serve'"
      exit 1
    fi
  else
    echo "  ERROR: proot-distro not found. Install it:"
    echo "    pkg install proot-distro && proot-distro install debian"
    exit 1
  fi
elif command -v ollama >/dev/null 2>&1; then
  echo "  Starting Ollama..."
  ollama serve >/dev/null 2>&1 &
  sleep 3
  if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
    echo "  [ok] Ollama started"
  else
    echo "  Warning: Ollama may not have started. Try 'ollama serve &' manually."
  fi
else
  echo "  Installing Ollama..."
  if [ "$PLATFORM" = "mac" ]; then
    if command -v brew >/dev/null 2>&1; then
      brew install ollama
    else
      echo ""
      echo "  Homebrew not found. Install it first:"
      echo "    /bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\""
      echo ""
      echo "  Then re-run this script."
      exit 1
    fi
  else
    curl -fsSL https://ollama.ai/install.sh | sh
  fi
  echo "  [ok] Ollama installed"
  ollama serve >/dev/null 2>&1 &
  sleep 3
fi

# ── Pull Model (via API — works on all platforms including proot) ────────────

echo ""
echo "  Pulling model: $MODEL"
echo "  (This may take a few minutes on first run)"
echo ""

# Check if model already exists
EXISTING=$(curl -sf http://localhost:11434/api/tags 2>/dev/null)
if echo "$EXISTING" | grep -q "\"$MODEL\""; then
  echo "  [ok] Model already downloaded"
else
  # Pull via API (works regardless of how Ollama is installed)
  curl -sf http://localhost:11434/api/pull -d "{\"name\":\"$MODEL\"}" | while IFS= read -r line; do
    STATUS=$(echo "$line" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$STATUS" ]; then
      printf "\r  %s                    " "$STATUS"
    fi
  done
  echo ""
  echo "  [ok] Model ready"
fi

# ── Download Client ───────────────────────────────────────────────────────────

echo "  Downloading wattson-client.js..."
curl -fsSO https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js
echo "  [ok] Client downloaded"

# ── Done ──────────────────────────────────────────────────────────────────────

echo ""
echo "  ====================="
echo "  Setup complete!"
echo "  ====================="
echo ""
echo "  To start contributing, run:"
echo ""
echo "    WATTSON_SERVER=https://wattson.me \\"
echo "    NODE_SECRET=YOUR_TOKEN \\"
echo "    MODEL=$MODEL \\"
echo "    node wattson-client.js"
echo ""
echo "  Replace YOUR_TOKEN with your contributor token."
echo ""
echo "  Get your token at: https://wattson.me/start"
echo "  Sign in with Google → copy your token → use it above"
echo ""
