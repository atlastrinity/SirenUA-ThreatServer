"""
SirenUA Threat Monitoring Server — Entry Point.
Assembles the FastAPI app from core modules, registers middleware, routers, and health checks.
"""

import os
import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import IS_LIVE_MODE
from core.globals import threat_manager, shelter_manager
import core.globals
from core.lifespan import lifespan
from core.middleware import register_middleware, register_exception_handlers
from database.analytics_db import on_threat_changed

# API Routers
from api.threats import router as threats_router
from api.analytics import router as analytics_router
from api.shelters import router as shelters_router
from api.admin import router as admin_router

# Wire up the change callback
threat_manager.on_change = on_threat_changed

# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

app = FastAPI(
    title="SirenUA Threat Monitor",
    description="API моніторингу рівня загрози для областей України",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Middleware & exception handlers
register_middleware(app)
register_exception_handlers(app)

# Routers
app.include_router(threats_router)
app.include_router(analytics_router)
app.include_router(shelters_router)
app.include_router(admin_router)


# ---------------------------------------------------------------------------
# Health-checks
# ---------------------------------------------------------------------------

@app.get("/")
async def root():
    """Health-check для Render / моніторингу."""
    telegram_connected = core.globals.telegram_monitor is not None and core.globals.telegram_monitor.is_running
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.2.0",
        "status": "running",
        "mode": "live" if IS_LIVE_MODE else "mock",
        "telegram_connected": telegram_connected,
        "shelters_loaded": shelter_manager.total_count,
    }


@app.head("/")
async def root_health():
    """Health-check для Render / моніторингу."""
    telegram_connected = core.globals.telegram_monitor is not None and core.globals.telegram_monitor.is_running
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.2.0",
        "status": "running",
        "mode": "live" if IS_LIVE_MODE else "mock",
        "telegram_connected": telegram_connected,
        "shelters_loaded": shelter_manager.total_count,
    }


# ---------------------------------------------------------------------------
# Dev runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8085))
    mode = "LIVE (Telegram)" if IS_LIVE_MODE else "MOCK (тестування)"

    print("🚀 SirenUA Threat Monitor Server")
    print(f"📡 Mode: {mode}")
    print(f"🌐 URL: http://localhost:{port}")
    print(f"📋 API Docs: http://localhost:{port}/docs")
    print()

    if not IS_LIVE_MODE:
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

    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
