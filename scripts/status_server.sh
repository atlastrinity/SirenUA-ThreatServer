#!/usr/bin/env bash
# SirenUA Threat Server - Status Check Script

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PID_FILE="$DIR/server.pid"
PORT="${PORT:-8085}"

RUNNING_PID=$(lsof -t -i :"$PORT" 2>/dev/null || true)

if [ -n "$RUNNING_PID" ]; then
    echo "🟢 Status: RUNNING (PID: $RUNNING_PID on port $PORT)"
    
    # Check Health
    HEALTH=$(curl -s -m 3 "http://127.0.0.1:$PORT/health" 2>/dev/null || echo "UNRESPONSIVE")
    echo "📊 Health: $HEALTH"
    
    # Check Gemini Status
    GEMINI_STATUS=$(curl -s -m 3 "http://127.0.0.1:$PORT/api/gemini/status" 2>/dev/null || echo "UNRESPONSIVE")
    echo "🧠 Gemini: $GEMINI_STATUS"
    
    # Check Ngrok URL from log if available
    NGROK_URL=$(grep -o 'https://[^ ]*\.ngrok-free\.dev' "$DIR/server.log" | tail -n 1 || true)
    if [ -n "$NGROK_URL" ]; then
        echo "🌍 Ngrok Public URL: $NGROK_URL"
    fi
else
    echo "🔴 Status: STOPPED (Port $PORT is not in use)"
    if [ -f "$PID_FILE" ]; then
        echo "⚠️ Stale PID file found ($PID_FILE), cleaning up..."
        rm -f "$PID_FILE"
    fi
fi
