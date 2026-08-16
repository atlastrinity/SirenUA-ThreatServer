"""
Admin System Control API Router.
FastAPI routes for server restart, memory status, and runtime maintenance.
"""

import os
import sys
import asyncio
import psutil
from datetime import datetime, timezone
from fastapi import APIRouter, BackgroundTasks

from core.config import IS_LIVE_MODE, logger

router = APIRouter()


@router.post("/api/admin/restart")
@router.post("/api/admin/system/restart")
async def restart_server(background_tasks: BackgroundTasks):
    """Gracefully initiates a server restart in the background."""
    logger.info("🔄 [Admin Control] Отримано запит на перезавантаження сервера...")

    async def schedule_restart():
        await asyncio.sleep(0.6)
        logger.info("💾 [Admin Control] Збереження стану та скид черг перед перезапуском...")
        try:
            from database.threat_logger import flush_history_batch
            flush_history_batch()
        except Exception as e:
            logger.warning(f"Flush error during restart: {e}")

        try:
            from database.db_helpers import backup_sqlite_to_firestore
            backup_sqlite_to_firestore()
        except Exception as e:
            logger.warning(f"Backup error during restart: {e}")

        logger.info("🚀 [Admin Control] Перезапуск процесу сервера...")
        os.execv(sys.executable, [sys.executable] + sys.argv)

    background_tasks.add_task(schedule_restart)
    return {
        "status": "restarting",
        "message": "Сервер перезавантажується... Зв'язок відновиться через 2-3 секунди."
    }


@router.get("/api/admin/system/info")
async def get_system_info():
    """Повертає системну інформацію про поточний процес сервера."""
    try:
        proc = psutil.Process()
        mem_info = proc.memory_info()
        uptime_seconds = int(datetime.now().timestamp() - proc.create_time())
        return {
            "status": "online",
            "pid": proc.pid,
            "memory_mb": round(mem_info.rss / (1024 * 1024), 2),
            "cpu_percent": proc.cpu_percent(interval=0.1),
            "uptime_seconds": uptime_seconds,
            "mode": "live" if IS_LIVE_MODE else "mock",
            "python_version": sys.version.split()[0],
        }
    except Exception as e:
        return {
            "status": "online",
            "pid": os.getpid(),
            "mode": "live" if IS_LIVE_MODE else "mock",
            "error": str(e)
        }


@router.get("/api/admin/sources/status")
@router.get("/api/sources/status")
async def get_sources_status():
    """Повертає статус доступності всіх джерел тривог (Tier 1-3) та аналізатора Gemini."""
    import core.globals
    ukraine_alarm_token = os.environ.get("UKRAINE_ALARM_API_KEY") or os.environ.get("UKRAINE_ALARM_TOKEN")
    alerts_in_ua_token = os.environ.get("ALERTS_TOKEN")
    gemini_key = os.environ.get("GEMINI_API_KEY")
    telegram_monitor = getattr(core.globals, "telegram_monitor", None)
    sources_info = getattr(core.globals, "sources_status", {})

    return {
        "status": "ok",
        "mode": "live" if IS_LIVE_MODE else "mock",
        "active_source": sources_info.get("active_source", "none"),
        "sources": {
            "ubilling": {
                "name": "UBilling Дзеркало (Tier 1 - Основне)",
                "url": "https://ubilling.net.ua/aerialalerts/",
                "configured": True,
                "status": "ONLINE"
            },
            "ukraine_alarm": {
                "name": "UkraineAlarm API v3 (Tier 2 - Резерв 1)",
                "url": "https://api.ukrainealarm.com/api/v3/alerts",
                "configured": bool(ukraine_alarm_token),
                "status": "ONLINE" if ukraine_alarm_token else "NEED_KEY"
            },
            "alerts_in_ua": {
                "name": "Alerts.in.ua API (Tier 3 - Резерв 2)",
                "url": "https://api.alerts.in.ua/v1/alerts/active.json",
                "configured": bool(alerts_in_ua_token),
                "status": "ONLINE" if alerts_in_ua_token else "NEED_TOKEN"
            },
            "threat_server": {
                "name": "SirenUA ThreatServer Backend",
                "status": "ONLINE"
            },
            "gemini": {
                "name": "Аналізатор Gemini AI",
                "configured": bool(gemini_key),
                "status": "ONLINE" if (gemini_key and telegram_monitor and telegram_monitor.analyzer.is_configured) else ("MOCK" if not IS_LIVE_MODE else "OFFLINE")
            }
        }
    }

