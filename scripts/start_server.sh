#!/usr/bin/env bash
# SirenUA Threat Server - Resilient Background Daemon Start Script

set -e

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PID_FILE="$DIR/server.pid"
LOG_FILE="$DIR/server.log"
PORT="${PORT:-8085}"

# Check if already running on port
RUNNING_PID=$(lsof -t -i :"$PORT" 2>/dev/null || true)
if [ -n "$RUNNING_PID" ]; then
    echo "🟢 SirenUA Threat Server is already running (PID: $RUNNING_PID) on port $PORT"
    exit 0
fi

if [ -f "$PID_FILE" ]; then
    OLD_PID=$(cat "$PID_FILE")
    if ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "🟢 SirenUA Threat Server is already running (PID: $OLD_PID)"
        exit 0
    else
        rm -f "$PID_FILE"
    fi
fi

# Find Python 3
PYTHON_BIN="$(which python3)"
if [ -x "/Users/dev/.pyenv/versions/3.11.13/bin/python3" ]; then
    PYTHON_BIN="/Users/dev/.pyenv/versions/3.11.13/bin/python3"
fi

echo "🚀 Starting SirenUA Threat Server in background (LIVE mode)..."
echo "📂 Working directory: $DIR"
echo "🐍 Python interpreter: $PYTHON_BIN"
echo "📝 Log file: $LOG_FILE"

# Launch in background with nohup, fully detached from terminal
nohup "$PYTHON_BIN" server.py --live > "$LOG_FILE" 2>&1 &
SERVER_PID=$!
echo "$SERVER_PID" > "$PID_FILE"
disown "$SERVER_PID" 2>/dev/null || true

echo "⏳ Waiting for server startup (PID: $SERVER_PID)..."
STARTED=false
for i in {1..15}; do
    if curl -s -m 2 "http://127.0.0.1:$PORT/health" > /dev/null 2>&1; then
        STARTED=true
        break
    fi
    sleep 1
done

if [ "$STARTED" = true ]; then
    echo "✅ SirenUA Threat Server is ACTIVE and HEALTHY!"
    echo "🌐 Local API: http://localhost:$PORT"
    echo "📋 API Docs: http://localhost:$PORT/docs"
    HEALTH_JSON=$(curl -s "http://127.0.0.1:$PORT/health" || echo "{}")
    echo "📊 Status: $HEALTH_JSON"
else
    echo "⚠️ Server started (PID $SERVER_PID), but health check is not responding yet. Check $LOG_FILE:"
    tail -n 20 "$LOG_FILE"
fi
