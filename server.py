"""
SirenUA Threat Monitoring Server.
Modularized entrypoint for the FastAPI threat server.
"""

import os
import sys
import asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import aiohttp

# Core and Config
from core.config import IS_LIVE_MODE, DB_PATH, logger
from core.globals import threat_manager, shelter_manager
import core.globals
import time

# Database and Helpers
from database.db_helpers import HAS_FIREBASE, get_db
from database.analytics_db import (
    init_analytics_db,
    log_error_to_db,
    log_rule_audit_to_db,
    last_logged_states,
    on_threat_changed,
    safe_run_task,
)

# API Routers
from api.threats import router as threats_router
from api.analytics import router as analytics_router
from api.shelters import router as shelters_router
from api.admin import router as admin_router

# Setup manager callback
threat_manager.on_change = on_threat_changed

# Initialize Firebase helper
try:
    import firebase_admin
    from firebase_admin import credentials
except ImportError:
    pass

def init_firebase():
    if not HAS_FIREBASE:
        logger.warning("Бібліотека firebase-admin не встановлена. Сповіщення не надсилатимуться.")
        return
    
    cred_env = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if cred_env:
        if cred_env.strip().startswith("{"):
            try:
                import json
                cred_dict = json.loads(cred_env)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                logger.info("Firebase Admin SDK ініціалізовано за допомогою JSON-рядка з змінної оточення.")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за JSON-рядком: {e}")
        
        if os.path.exists(cred_env):
            try:
                cred = credentials.Certificate(cred_env)
                firebase_admin.initialize_app(cred)
                logger.info(f"Firebase Admin SDK ініціалізовано за допомогою файлу: {cred_env}")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за файлом ключів: {e}")

    default_paths = ["threat_server/firebase-credentials.json", "firebase-credentials.json"]
    for path in default_paths:
        if os.path.exists(path):
            try:
                cred = credentials.Certificate(path)
                firebase_admin.initialize_app(cred)
                logger.info(f"Firebase Admin SDK ініціалізовано за допомогою дефолтного файлу: {path}")
                return
            except Exception as e:
                logger.error(f"Помилка ініціалізації Firebase за дефолтним файлом {path}: {e}")

    try:
        firebase_admin.initialize_app()
        logger.info("Firebase Admin SDK ініціалізовано (Default Credentials / Env).")
    except Exception as e:
        logger.warning("Не знайдено credentials. Сповіщення у фоні не працюватимуть.")

aerial_alerts_task = None

async def poll_aerial_alerts():
    """Фонова задача для опитування офіційного API тривог (alerts.in.ua або ubilling)."""
    token = os.environ.get("ALERTS_TOKEN")
    
    if token:
        logger.info("Запуск фонового опитування офіційних тривог з alerts.in.ua...")
        url = "https://api.alerts.in.ua/v1/alerts/active.json"
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "SirenUA-ThreatServer/1.0"
        }
    else:
        logger.info("Запуск фонового опитування офіційних тривог з ubilling (резервний режим, ALERTS_TOKEN не знайдено)...")
        url = "https://ubilling.net.ua/aerialalerts/"
        headers = {"User-Agent": "SirenUA-ThreatServer/1.0"}

    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=8.0) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if token:
                            active_alerts = data.get("alerts", [])
                            active_regions = set()
                            
                            for alert in active_alerts:
                                loc_type = alert.get("location_type")
                                loc_title = alert.get("location_title")
                                if loc_title:
                                    if loc_type == "oblast" or loc_title == "м. Київ":
                                        active_regions.add(loc_title)
                            
                            from core.regions import ALL_REGIONS
                            for region_name in ALL_REGIONS.keys():
                                is_active = region_name in active_regions
                                threat_manager.set_alarm_active(region_name, is_active)
                        else:
                            states = data.get("states", {})
                            for region_name, state_data in states.items():
                                is_active = state_data.get("alertnow", False)
                                threat_manager.set_alarm_active(region_name, is_active)
                    else:
                        logger.warning(f"Помилка опитування тривог (URL: {url}): HTTP статус {response.status}")
        except Exception as e:
            logger.error(f"Помилка під час опитування тривог (URL: {url}): {e}")
            log_error_to_db("server", str(e), endpoint="poll_aerial_alerts", context=f"url={url}")
        
        sleep_interval = 15.0 if token else 30.0
        await asyncio.sleep(sleep_interval)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка Telegram моніторингу."""
    global aerial_alerts_task
    import database.analytics_db
    database.analytics_db.main_loop = asyncio.get_running_loop()
    
    # Ініціалізація Firebase
    init_firebase()
    
    # Запуск FCM воркера
    try:
        from database.db_helpers import start_fcm_worker
        await start_fcm_worker()
    except Exception as e:
        logger.error(f"Помилка запуску FCM воркера: {e}")
    
    # Ініціалізація БД аналітики
    init_analytics_db()

    # Відновлення БД SQLite з Firestore (якщо локальна БД порожня)
    try:
        from database.db_helpers import restore_sqlite_from_firestore
        await asyncio.to_thread(restore_sqlite_from_firestore)
    except Exception as e:
        logger.error(f"Помилка автоматичного відновлення SQLite: {e}")

    # Завантаження збереженого стану загроз
    try:
        await asyncio.to_thread(threat_manager.load_from_db)
        for r, s in threat_manager.threats.items():
            last_logged_states[r] = {
                "active_threats": {
                    t.threat_id: {
                        "level": t.level,
                        "threat_type": t.threat_type,
                        "detail": t.detail,
                        "confidence": t.confidence,
                        "is_predictive": getattr(t, "is_predictive", False),
                        "is_test": t.is_test
                    }
                    for t in s.active_threats
                    if t.threat_type and t.threat_type != "official_alarm"
                },
                "is_active": s.is_active,
                "level": s.level
            }
    except Exception as e:
        logger.error(f"Помилка асинхронного завантаження стану загроз: {e}")

    # Завантаження бази укриттів
    async def load_shelters_background():
        try:
            await shelter_manager.load()
            await shelter_manager.start_refresh_loop()
        except Exception as e:
            logger.error(f"Помилка завантаження укриттів: {e}")
            
    asyncio.create_task(load_shelters_background())
    
    # Запуск фонового опитування офіційного API
    aerial_alerts_task = asyncio.create_task(poll_aerial_alerts())

    if IS_LIVE_MODE:
        from monitor.telegram_monitor import TelegramThreatMonitor
        core.globals.telegram_monitor = TelegramThreatMonitor(threat_manager)
        await core.globals.telegram_monitor.start()
        logger.info("🟢 Сервер запущено в LIVE режимі (Telegram)")
    else:
        logger.info("🟡 Сервер запущено в MOCK режимі (тестування)")
    
    yield
    
    # Зупинка фонового опитування
    if aerial_alerts_task:
        aerial_alerts_task.cancel()
        try:
            await aerial_alerts_task
        except asyncio.CancelledError:
            pass
            
    await shelter_manager.stop()
    if core.globals.telegram_monitor:
        await core.globals.telegram_monitor.stop()

    # Фінальний бекап SQLite
    try:
        from database.db_helpers import backup_sqlite_to_firestore
        await asyncio.to_thread(backup_sqlite_to_firestore)
        logger.info("💾 [Lifespan Shutdown] Фінальний бекап SQLite успішно створено.")
    except Exception as e:
        logger.error(f"⚠️ [Lifespan Shutdown] Помилка створення фінального бекапу: {e}")

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

# HTTP Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    client_host = request.client.host if request.client else "unknown"
    logger.info(f"⬇️ Incoming request: {request.method} {request.url.path} from {client_host}")
    try:
        response = await call_next(request)
        duration = time.time() - start_time
        logger.info(
            f"⬆️ Response: {request.method} {request.url.path} - Status: {response.status_code} - Duration: {duration:.3f}s"
        )
        return response
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"❌ Request Failed: {request.method} {request.url.path} - Error: {e} - Duration: {duration:.3f}s"
        )
        raise e

# Exceptions handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code >= 400:
        safe_run_task(asyncio.to_thread(
            log_error_to_db,
            "server",
            str(exc.detail),
            str(request.url.path),
            f"method={request.method}, status={exc.status_code}",
            "auth" if exc.status_code in [401, 403] else ("500_server" if exc.status_code >= 500 else "general")
        ))
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_msg = str(exc.errors())
    safe_run_task(asyncio.to_thread(
        log_error_to_db,
        "server",
        error_msg,
        str(request.url.path),
        f"method={request.method}",
        "general"
    ))
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

@app.exception_handler(Exception)
async def custom_global_exception_handler(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    error_str = f"{str(exc)}\n{tb}"
    safe_run_task(asyncio.to_thread(
        log_error_to_db,
        "server",
        error_str,
        str(request.url.path),
        f"method={request.method}",
        "systemic"
    ))
    try:
        from database.db_helpers import backup_sqlite_to_firestore
        safe_run_task(asyncio.to_thread(backup_sqlite_to_firestore))
    except Exception:
        pass
    return JSONResponse(
        status_code=500,
        content={"detail": "Внутрішня помилка сервера. Помилку записано в системний лог."},
    )

# Include API Routers
app.include_router(threats_router)
app.include_router(analytics_router)
app.include_router(shelters_router)
app.include_router(admin_router)

# Health-checks
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

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8085))
    mode = "LIVE (Telegram)" if IS_LIVE_MODE else "MOCK (тестування)"
    
    print(f"🚀 SirenUA Threat Monitor Server")
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
