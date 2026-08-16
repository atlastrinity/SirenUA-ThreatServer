#!/usr/bin/env bash
# SirenUA Threat Server - Stop Daemon Script

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

PID_FILE="$DIR/server.pid"
PORT="${PORT:-8085}"

STOPPED=false

if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "🛑 Stopping SirenUA Threat Server (PID: $PID)..."
        kill -15 "$PID" 2>/dev/null || true
        for i in {1..5}; do
            if ! ps -p "$PID" > /dev/null 2>&1; then
                STOPPED=true
                break
            fi
            sleep 1
        done
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "⚠️ Process didn't stop gracefully, forcing kill..."
            kill -9 "$PID" 2>/dev/null || true
            STOPPED=true
        fi
    fi
    rm -f "$PID_FILE"
fi

RUNNING_PORT_PID=$(lsof -t -i :"$PORT" 2>/dev/null || true)
if [ -n "$RUNNING_PORT_PID" ]; then
    echo "🛑 Freeing port $PORT (PID: $RUNNING_PORT_PID)..."
    kill -15 "$RUNNING_PORT_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$RUNNING_PORT_PID" 2>/dev/null || true
    STOPPED=true
fi

echo "✅ SirenUA Threat Server has been stopped."
