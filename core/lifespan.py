"""
Application Lifespan Manager.
Handles startup/shutdown sequence: Firebase, FCM, DB, shelter loading, Telegram monitor,
and background aerial-alerts polling.
"""

import asyncio
import os
from contextlib import asynccontextmanager

import aiohttp
from fastapi import FastAPI

from core.config import IS_LIVE_MODE, logger
from core.globals import threat_manager, shelter_manager
import core.globals
from core.firebase_init import init_firebase
from database.analytics_db import init_analytics_db, last_logged_states, log_error_to_db

# Background task handle
aerial_alerts_task = None


async def poll_aerial_alerts():
    """Фонова задача для опитування офіційного API тривог (alerts.in.ua або ubilling)."""
    token = os.environ.get("ALERTS_TOKEN")

    if token:
        logger.info("Запуск фонового опитування офіційних тривог з alerts.in.ua...")
        url = "https://api.alerts.in.ua/v1/alerts/active.json"
        headers = {"Authorization": f"Bearer {token}", "User-Agent": "SirenUA-ThreatServer/1.0"}
    else:
        logger.info("Запуск фонового опитування офіційних тривог з ubilling (резервний режим)...")
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
                                if loc_title and (loc_type == "oblast" or loc_title == "м. Київ"):
                                    active_regions.add(loc_title)
                            from core.regions import ALL_REGIONS
                            for region_name in ALL_REGIONS.keys():
                                threat_manager.set_alarm_active(region_name, region_name in active_regions)
                        else:
                            states = data.get("states", {})
                            for region_name, state_data in states.items():
                                threat_manager.set_alarm_active(region_name, state_data.get("alertnow", False))
                    else:
                        logger.warning(f"Помилка опитування тривог (URL: {url}): HTTP статус {response.status}")
        except Exception as e:
            err_msg = str(e) or repr(e) or type(e).__name__
            logger.error(f"Помилка під час опитування тривог (URL: {url}): {err_msg}")
            log_error_to_db("server", err_msg, endpoint="poll_aerial_alerts", context=f"url={url}")

        await asyncio.sleep(15.0 if token else 30.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка всіх фонових задач."""
    global aerial_alerts_task

    import database.analytics_db
    database.analytics_db.main_loop = asyncio.get_running_loop()

    # Firebase
    init_firebase()

    # FCM worker
    try:
        from database.db_helpers import start_fcm_worker
        await start_fcm_worker()
    except Exception as e:
        logger.error(f"Помилка запуску FCM воркера: {e}")

    # Analytics DB
    init_analytics_db()

    # Restore SQLite from Firestore
    try:
        from database.db_helpers import restore_sqlite_from_firestore
        await asyncio.to_thread(restore_sqlite_from_firestore)
    except Exception as e:
        logger.error(f"Помилка автоматичного відновлення SQLite: {e}")

    # Load saved threat state
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

    # Shelters
    async def load_shelters_background():
        try:
            await shelter_manager.load()
            await shelter_manager.start_refresh_loop()
        except Exception as e:
            logger.error(f"Помилка завантаження укриттів: {e}")

    asyncio.create_task(load_shelters_background())

    # Aerial alerts polling
    aerial_alerts_task = asyncio.create_task(poll_aerial_alerts())

    # Telegram monitor
    if IS_LIVE_MODE:
        from monitor.telegram_monitor import TelegramThreatMonitor
        core.globals.telegram_monitor = TelegramThreatMonitor(threat_manager)
        await core.globals.telegram_monitor.start()
        logger.info("🟢 Сервер запущено в LIVE режимі (Telegram)")
    else:
        logger.info("🟡 Сервер запущено в MOCK режимі (тестування)")

    yield

    # Shutdown
    if aerial_alerts_task:
        aerial_alerts_task.cancel()
        try:
            await aerial_alerts_task
        except asyncio.CancelledError:
            pass

    await shelter_manager.stop()
    if core.globals.telegram_monitor:
        await core.globals.telegram_monitor.stop()

    try:
        from database.db_helpers import backup_sqlite_to_firestore
        await asyncio.to_thread(backup_sqlite_to_firestore)
        logger.info("💾 [Lifespan Shutdown] Фінальний бекап SQLite успішно створено.")
    except Exception as e:
        logger.error(f"⚠️ [Lifespan Shutdown] Помилка створення фінального бекапу: {e}")
