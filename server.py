"""
Threat Monitoring Server — FastAPI сервер моніторингу загроз.

Запуск:
    python server.py          # мок-режим (для тестування)
    python server.py --live   # живий режим з Telegram (потрібні ключі)

API:
    GET  /api/threats           — поточний стан загроз для всіх областей
    POST /api/threats/mock      — встановити загрозу вручну (мок-режим)
    POST /api/threats/scenario  — запустити тестовий сценарій
    POST /api/threats/clear     — очистити всі загрози
"""

import os
import sys
import asyncio
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

from mock_mode import MockThreatManager

# Глобальний менеджер загроз (in-memory)
threat_manager = MockThreatManager()
telegram_monitor = None
is_live_mode = "--live" in sys.argv or os.environ.get("LIVE_MODE", "false").lower() == "true"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка Telegram моніторингу."""
    global telegram_monitor
    
    if is_live_mode:
        from telegram_monitor import TelegramThreatMonitor
        telegram_monitor = TelegramThreatMonitor(threat_manager)
        await telegram_monitor.start()
        print("🟢 Сервер запущено в LIVE режимі (Telegram)")
    else:
        print("🟡 Сервер запущено в MOCK режимі (тестування)")
    
    yield
    
    if telegram_monitor:
        await telegram_monitor.stop()


app = FastAPI(
    title="SirenUA Threat Monitor",
    description="API моніторингу рівня загрози для областей України",
    version="1.0.0",
    lifespan=lifespan,
)

# Дозвіл CORS для iOS додатку
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic моделі ---

class ThreatSetRequest(BaseModel):
    region: str
    level: str  # none, low, medium, high, critical
    threat_type: Optional[str] = None
    detail: Optional[str] = None


class ScenarioRequest(BaseModel):
    scenario: str  # mig_takeoff, shaheds_south, cruise_missiles_west, massive_attack, ballistic_kharkiv


# --- API Endpoints ---

@app.get("/")
async def root():
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.0.0",
        "status": "running",
        "mode": "live" if is_live_mode else "mock",
        "telegram_connected": telegram_monitor is not None and telegram_monitor.is_running,
    }


@app.get("/api/threats")
async def get_threats():
    """Повертає поточний стан загроз для всіх областей."""
    return {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if is_live_mode else "mock",
        "threats": threat_manager.get_all_threats(),
    }


@app.post("/api/threats/mock")
async def set_mock_threat(request: ThreatSetRequest):
    """Встановити загрозу вручну для тестування."""
    valid_levels = {"none", "low", "medium", "high", "critical"}
    if request.level not in valid_levels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid level '{request.level}'. Valid: {valid_levels}"
        )

    success = threat_manager.set_threat(
        region=request.region,
        level=request.level,
        threat_type=request.threat_type,
        detail=request.detail,
    )

    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Region '{request.region}' not found"
        )

    return {"status": "ok", "region": request.region, "level": request.level}


@app.post("/api/threats/scenario")
async def set_scenario(request: ScenarioRequest):
    """Запустити тестовий сценарій."""
    valid_scenarios = {
        "mig_takeoff", "shaheds_south", "cruise_missiles_west",
        "massive_attack", "ballistic_kharkiv", "clear"
    }
    if request.scenario not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{request.scenario}'. Valid: {valid_scenarios}"
        )

    if request.scenario == "clear":
        threat_manager.clear_all()
    else:
        threat_manager.set_scenario(request.scenario)

    return {"status": "ok", "scenario": request.scenario}


@app.post("/api/threats/clear")
async def clear_all_threats():
    """Очистити всі загрози."""
    threat_manager.clear_all()
    return {"status": "ok", "message": "All threats cleared"}


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8085))
    mode = "LIVE (Telegram)" if is_live_mode else "MOCK (тестування)"
    
    print(f"🚀 SirenUA Threat Monitor Server")
    print(f"📡 Mode: {mode}")
    print(f"🌐 URL: http://localhost:{port}")
    print(f"📋 API Docs: http://localhost:{port}/docs")
    print()

    if not is_live_mode:
        print("Тестові сценарії:")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"mig_takeoff\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"shaheds_south\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"massive_attack\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/clear")
        print()
    else:
        print("⚡ Підключення до Telegram каналів...")
        print("   При першому запуску потрібно ввести номер телефону та код.")
        print()

    uvicorn.run(app, host="0.0.0.0", port=port)
