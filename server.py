"""
SirenUA Threat Monitoring Server.
Modularized entrypoint for the FastAPI threat server.
"""

import os
import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import aiohttp

# Core and Config
from core.config import IS_LIVE_MODE, logger
import core.globals
from core.globals import threat_manager, shelter_manager
import time

# Database and Helpers
from database.db_helpers import HAS_FIREBASE
from database.analytics_db import (
    init_analytics_db,
    log_error_to_db,
    last_logged_states,
    on_threat_changed,
    safe_run_task,
    reconcile_active_threats_with_db,
)

# API Routers
from api.threats import router as threats_router
from api.analytics import router as analytics_router
from api.shelters import router as shelters_router
from api.admin import router as admin_router

# Setup manager callback
threat_manager.on_change = on_threat_changed

from core.firebase_init import init_firebase

aerial_alerts_task = None

async def poll_aerial_alerts():
    """
    Фонова задача для опитування офіційного API тривог із каскадним резервуванням (Fallback):
    - Tier 1 (Основне першоджерело): ubilling.net.ua/aerialalerts/ (2-3 повторні спроби при збоях)
    - Tier 2 (Резерв 1): api.ukrainealarm.com (якщо налаштовано токен)
    - Tier 3 (Резерв 2): api.alerts.in.ua (якщо налаштовано ALERTS_TOKEN)
    """
    ukraine_alarm_token = os.environ.get("UKRAINE_ALARM_API_KEY") or os.environ.get("UKRAINE_ALARM_TOKEN")
    alerts_in_ua_token = os.environ.get("ALERTS_TOKEN")

    logger.info(f"Запуск фонового каскадного опитування офіційних тривог. "
                f"Пріоритет 1 (Основне): UBilling (дзеркало), "
                f"Пріоритет 2 (Резерв 1): UkraineAlarm ({'налаштовано' if ukraine_alarm_token else 'очікує ключ'}), "
                f"Пріоритет 3 (Резерв 2): Alerts.in.ua ({'налаштовано' if alerts_in_ua_token else 'без токена'}).")

    while True:
        from core.regions import ALL_REGIONS, normalize_region_name
        success = False
        official_dict = {}
        alert_types_dict = {}
        active_source = "none"

        async with aiohttp.ClientSession() as session:
            # -------------------------------------------------------------
            # Tier 1 (Основне першоджерело): UBilling Дзеркало (ubilling.net.ua)
            # 3 спроби із короткою паузою перед перемиканням на резервні джерела
            # -------------------------------------------------------------
            for attempt in range(1, 4):
                if success:
                    break
                try:
                    url = "https://ubilling.net.ua/aerialalerts/"
                    headers = {
                        "User-Agent": "SirenUA-ThreatServer/1.0",
                        "Accept": "application/json"
                    }
                    async with session.get(url, headers=headers, timeout=5.0) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if isinstance(data, dict):
                                states = data.get("states", {})
                                if isinstance(states, dict) and states:
                                    for r_raw, state_data in states.items():
                                        canon_r = normalize_region_name(r_raw)
                                        if isinstance(state_data, dict):
                                            is_act = state_data.get("alertnow", False)
                                            official_dict[canon_r] = is_act
                                            alert_types_dict[canon_r] = "air" if is_act else None
                                    for region_name in ALL_REGIONS.keys():
                                        if region_name not in official_dict:
                                            official_dict[region_name] = False
                                            alert_types_dict[region_name] = None
                                    success = True
                                    active_source = "ubilling.net.ua"
                                    break
                        else:
                            logger.warning(f"Tier 1 (UBilling) спроба {attempt}/3 HTTP {resp.status}")
                except Exception as e:
                    logger.warning(f"Tier 1 (UBilling) спроба {attempt}/3 недоступний: {e}")

                if not success and attempt < 3:
                    await asyncio.sleep(0.8)

            # -------------------------------------------------------------
            # Tier 2 (Резерв 1): UkraineAlarm API (api.ukrainealarm.com)
            # -------------------------------------------------------------
            if not success and ukraine_alarm_token:
                try:
                    url = "https://api.ukrainealarm.com/api/v3/alerts"
                    headers = {
                        "Authorization": ukraine_alarm_token,
                        "Accept": "application/json",
                        "User-Agent": "SirenUA-ThreatServer/1.0"
                    }
                    async with session.get(url, headers=headers, timeout=6.0) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if isinstance(data, list):
                                active_regions_map = {}
                                for item in data:
                                    if isinstance(item, dict):
                                        raw_name = item.get("regionName") or item.get("location_title")
                                        if raw_name:
                                            canon_name = normalize_region_name(raw_name)
                                            active_alerts = item.get("activeAlerts", [])
                                            # Find primary alert type
                                            alert_type = "air"
                                            if active_alerts and isinstance(active_alerts, list):
                                                for a in active_alerts:
                                                    if isinstance(a, dict):
                                                        raw_t = (a.get("type") or "AIR").upper()
                                                        if raw_t in ("ARTILLERY", "URBAN_FIGHTS", "CHEMICAL", "NUCLEAR"):
                                                            alert_type = raw_t.lower()
                                                            break
                                            active_regions_map[canon_name] = alert_type

                                for region_name in ALL_REGIONS.keys():
                                    is_active = region_name in active_regions_map
                                    a_type = active_regions_map.get(region_name)
                                    official_dict[region_name] = is_active
                                    alert_types_dict[region_name] = a_type
                                success = True
                                active_source = "ukrainealarm.com"
                        else:
                            logger.warning(f"Tier 2 (UkraineAlarm) HTTP статус {resp.status}, перемикання на резерв...")
                except Exception as e:
                    logger.warning(f"Tier 2 (UkraineAlarm) недоступний: {e}, перемикання на резерв...")

            # -------------------------------------------------------------
            # Tier 3 (Резерв 2): Alerts.in.ua (api.alerts.in.ua)
            # -------------------------------------------------------------
            if not success and alerts_in_ua_token:
                try:
                    url = "https://api.alerts.in.ua/v1/alerts/active.json"
                    headers = {
                        "Authorization": f"Bearer {alerts_in_ua_token}",
                        "User-Agent": "SirenUA-ThreatServer/1.0"
                    }
                    async with session.get(url, headers=headers, timeout=6.0) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            if isinstance(data, dict):
                                active_alerts = data.get("alerts", [])
                                active_set = set()
                                for alert in active_alerts:
                                    if isinstance(alert, dict):
                                        loc_type = alert.get("location_type")
                                        loc_title = alert.get("location_title")
                                        if loc_title and (loc_type == "oblast" or loc_title == "м. Київ"):
                                            active_set.add(normalize_region_name(loc_title))

                                for region_name in ALL_REGIONS.keys():
                                    is_act = region_name in active_set
                                    official_dict[region_name] = is_act
                                    alert_types_dict[region_name] = "air" if is_act else None
                                success = True
                                active_source = "alerts.in.ua"
                        else:
                            logger.warning(f"Tier 3 (Alerts.in.ua) HTTP статус {resp.status}")
                except Exception as e:
                    logger.warning(f"Tier 3 (Alerts.in.ua) помилка: {e}")

        # -----------------------------------------------------------------
        # Оновлення статусу джерел та ThreatManager
        # -----------------------------------------------------------------
        if not hasattr(core.globals, "sources_status"):
            core.globals.sources_status = {}
        core.globals.sources_status["active_source"] = active_source
        core.globals.sources_status["last_polled_at"] = time.time()

        if success:
            for region_name, is_act in official_dict.items():
                a_type = alert_types_dict.get(region_name)
                threat_manager.set_alarm_active(region_name, is_act, alert_type=a_type)

            # Автоматично знімаємо протерміновані загрози та загрози у знятих тривогах (у фоновому потоці)
            try:
                from services.missile_lifecycle_service import prune_expired_missile_threats
                await asyncio.to_thread(prune_expired_missile_threats, threat_manager, official_dict)
            except Exception as prune_err:
                logger.error(f"Помилка під час prune_expired_missile_threats: {prune_err}")
            
            await asyncio.sleep(15.0)
        else:
            logger.warning("⚠️ Всі 3 джерела офіційних тривог (UBilling -> UkraineAlarm -> Alerts.in.ua) тимчасово недоступні. Зберігаємо попередній стан.")
            # При недоступності повторюємо швидше (5с) для оперативного відновлення
            await asyncio.sleep(5.0)

async def periodic_sqlite_backup():
    """Фонова задача регулярного стиснутого бекапу SQLite в Firestore кожні 15 хвилин."""
    while True:
        try:
            await asyncio.sleep(900)  # 15 хвилин
            from database.db_helpers import backup_sqlite_to_firestore
            await asyncio.to_thread(backup_sqlite_to_firestore)
            logger.info("⏰ [Periodic Backup] Автоматичний бекап SQLite успішно збережено в Firestore.")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"⚠️ [Periodic Backup] Помилка періодичного бекапу: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка Telegram моніторингу."""
    global aerial_alerts_task
    import sys
    import database.analytics_db
    database.analytics_db.main_loop = asyncio.get_running_loop()
    
    # Автоматичне блокування режиму сну macOS під час роботи сервера (24/7 Live Protection)
    caffeinate_proc = None
    if sys.platform == "darwin":
        try:
            import subprocess
            caffeinate_proc = subprocess.Popen(
                ["caffeinate", "-dimsu"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            logger.info("☕ [Caffeinate] Активовано системний захист від сну macOS (Sleep Prevention Active).")
        except Exception as e:
            logger.warning(f"Не вдалося активувати caffeinate: {e}")

    # Підключення автоматичного збору всіх помилок та логів у таблицю error_log
    try:
        from database.error_logger import attach_database_logging_handler
        attach_database_logging_handler()
    except Exception as e:
        logger.warning(f"Error attaching db logging handler: {e}")
    
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

    # Завантаження збереженого стану загроз та звірка з базою SQLite
    try:
        await asyncio.to_thread(threat_manager.load_from_db)
        await asyncio.to_thread(reconcile_active_threats_with_db, threat_manager)
    except Exception as e:
        logger.error(f"Помилка асинхронного завантаження та звірки стану загроз: {e}")

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

    # Запуск періодичного бекапу SQLite в Firestore кожні 15 хвилин
    periodic_backup_task = asyncio.create_task(periodic_sqlite_backup())

    # Запуск періодичного розумного локального бекапу з дозаписом кожні 5 хвилин
    from database.smart_backup import periodic_smart_backup_loop, smart_local_incremental_backup
    smart_backup_task = asyncio.create_task(periodic_smart_backup_loop())
    asyncio.create_task(asyncio.to_thread(smart_local_incremental_backup))

    # Запуск / перевірка Ngrok тунелю та фонового вотчдога
    from services.ngrok_service import ensure_ngrok_running, ngrok_watchdog_loop
    asyncio.create_task(ensure_ngrok_running())
    ngrok_watchdog_task = asyncio.create_task(ngrok_watchdog_loop())

    if IS_LIVE_MODE:
        from monitor.telegram_monitor import TelegramThreatMonitor
        core.globals.telegram_monitor = TelegramThreatMonitor(threat_manager)
        asyncio.create_task(core.globals.telegram_monitor.start())
        logger.info("🟢 Сервер запущено в LIVE режимі (Telegram)")
    else:
        logger.info("🟡 Сервер запущено в MOCK режимі (тестування)")
    
    yield
    
    # Зупинка фонового бекапу, вотчдога та опитування
    periodic_backup_task.cancel()
    smart_backup_task.cancel()
    ngrok_watchdog_task.cancel()
    if aerial_alerts_task:
        aerial_alerts_task.cancel()
        try:
            await aerial_alerts_task
        except asyncio.CancelledError:
            pass
            
    # Фінальний локальний смарт-бекап перед зупинкою
    try:
        smart_local_incremental_backup()
    except Exception as e:
        logger.error(f"⚠️ [Lifespan Shutdown] Помилка фінального смарт-бекапу: {e}")

    await shelter_manager.stop()
    if core.globals.telegram_monitor:
        await core.globals.telegram_monitor.stop()

    # Фінальний скид черги історії та бекап SQLite
    try:
        from database.threat_logger import flush_history_batch
        flush_history_batch()
    except Exception as e:
        logger.error(f"⚠️ [Lifespan Shutdown] Помилка скиду черги історії: {e}")

    try:
        from database.db_helpers import backup_sqlite_to_firestore
        await asyncio.to_thread(backup_sqlite_to_firestore)
        logger.info("💾 [Lifespan Shutdown] Фінальний бекап SQLite успішно створено.")
    except Exception as e:
        logger.error(f"⚠️ [Lifespan Shutdown] Помилка створення фінального бекапу: {e}")

    if caffeinate_proc:
        try:
            caffeinate_proc.terminate()
        except Exception:
            pass

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

# High-frequency routine polling paths that should not spam stdout unless slow or error
ROUTINE_PATHS = {"/api/threats", "/health", "/favicon.ico"}

# HTTP Request Logging Middleware
@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    path = request.url.path
    client_host = request.client.host if request.client else "unknown"
    ua = request.headers.get("user-agent", "unknown")
    is_routine = path in ROUTINE_PATHS and request.method == "GET"

    if not is_routine:
        logger.info(f"⬇️ Incoming request: {request.method} {path} from {client_host} ({ua})")
    try:
        response = await call_next(request)
        duration = time.time() - start_time
        if not is_routine or response.status_code >= 400 or duration > 1.0:
            logger.info(
                f"⬆️ Response: {request.method} {path} - Status: {response.status_code} - Duration: {duration:.3f}s"
            )
        return response
    except Exception as e:
        duration = time.time() - start_time
        logger.error(
            f"❌ Request Failed: {request.method} {path} - Error: {e} - Duration: {duration:.3f}s"
        )
        raise e

# Exceptions handlers
@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Do not log 404 Not Found to error_log as normal missing routes are expected HTTP behavior
    if exc.status_code >= 400 and exc.status_code != 404:
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
@app.get("/health")
@app.get("/api/health")
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
@app.head("/health")
@app.head("/api/health")
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

@app.get("/ws")
async def websocket_http_fallback():
    """Fallback handler for HTTP GET on /ws."""
    return {"status": "ok", "message": "WebSocket endpoint is active. Use ws:// protocol for real-time connection."}

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

    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False, access_log=False)
