#!/bin/bash
# Wattson.me — One-Command Termux Setup
# Usage: curl -fsSL https://wattson.me/setup-termux.sh | bash -s -- YOUR_TOKEN
#
# Installs Ollama, picks the best model for your phone,
# downloads the client, and starts contributing immediately.

set -e

TOKEN="${1:-}"
if [ -z "$TOKEN" ]; then
  echo ""
  echo "  Usage: curl -fsSL https://wattson.me/setup-termux.sh | bash -s -- YOUR_TOKEN"
  echo ""
  echo "  Get your token at: https://wattson.me/start"
  exit 1
fi

echo ""
echo "  Wattson.me — Termux Setup"
echo "  ========================="
echo ""

# ── Install dependencies ──────────────────────────────────────────────────────

echo "  Updating packages..."
pkg update -y > /dev/null 2>&1
echo "  Installing Ollama + Node.js..."
pkg install -y ollama nodejs-lts > /dev/null 2>&1
echo "  [ok] Dependencies installed"

# ── Detect RAM & pick model ───────────────────────────────────────────────────

RAM_MB=0
if [ -f /proc/meminfo ]; then
  RAM_KB=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
  RAM_MB=$(( RAM_KB / 1024 ))
fi

MODEL="qwen3:0.6b"
if [ "$RAM_MB" -ge 2000 ]; then
  MODEL="qwen3:1.7b"
fi

echo "  RAM: ${RAM_MB}MB → Model: $MODEL"

# ── Start Ollama ──────────────────────────────────────────────────────────────

echo "  Starting Ollama..."
ollama serve > /dev/null 2>&1 &
OLLAMA_PID=$!

# Wait for Ollama to be ready
for i in $(seq 1 30); do
  curl -sf http://localhost:11434/api/tags > /dev/null 2>&1 && break
  sleep 2
done

if ! curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
  echo "  ERROR: Ollama failed to start"
  exit 1
fi
echo "  [ok] Ollama running"

# ── Pull model ────────────────────────────────────────────────────────────────

echo ""
echo "  Pulling $MODEL (this may take a few minutes)..."

EXISTING=$(curl -sf http://localhost:11434/api/tags 2>/dev/null)
if echo "$EXISTING" | grep -q "\"$MODEL\""; then
  echo "  [ok] Model already downloaded"
else
  curl -sf http://localhost:11434/api/pull -d "{\"name\":\"$MODEL\"}" | while IFS= read -r line; do
    STATUS=$(echo "$line" | grep -o '"status":"[^"]*"' | head -1 | cut -d'"' -f4)
    if [ -n "$STATUS" ]; then
      printf "\r  %s                    " "$STATUS"
    fi
  done
  echo ""
  echo "  [ok] Model ready"
fi

# ── Download & run client ─────────────────────────────────────────────────────

echo "  Downloading client..."
curl -fsSO https://raw.githubusercontent.com/chatde/wattson-me/main/wattson-client.js
echo "  [ok] Client downloaded"

echo ""
echo "  ========================="
echo "  Starting Wattson client..."
echo "  ========================="
echo ""

WATTSON_SERVER=https://wattson.me \
NODE_SECRET="$TOKEN" \
MODEL="$MODEL" \
node wattson-client.js
