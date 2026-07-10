"""
SirenUA Threat Management API Router.
FastAPI routes for current threat status feed, scenarios, and overrides.
"""

import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from core.config import IS_LIVE_MODE
from core.globals import threat_manager
from api.schemas import ThreatSetRequest, ScenarioRequest, TelegramTestRequest

router = APIRouter()

@router.get("/api/threats")
async def get_threats():
    """Повертає поточний стан загроз для всіх областей."""
    return {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if IS_LIVE_MODE else "mock",
        "threats": threat_manager.get_all_threats(),
    }

@router.get("/api/gemini/status")
async def get_gemini_status():
    """Повертає поточний статус ШІ-аналізатора Gemini."""
    import core.globals
    telegram_monitor = core.globals.telegram_monitor
    
    if not IS_LIVE_MODE:
        return {"status": "mock", "error": "Сервер працює в тестовому (MOCK) режимі"}
        
    if telegram_monitor is None or telegram_monitor.analyzer is None:
        return {"status": "offline", "error": "Моніторинг не запущено"}
        
    analyzer = telegram_monitor.analyzer
    if not analyzer.is_configured:
        return {"status": "offline", "error": "API-ключ GEMINI_API_KEY не налаштовано"}
        
    if analyzer.last_error:
        return {"status": "error", "error": analyzer.last_error}
        
    return {"status": "ok", "error": None}

@router.post("/api/threats/mock")
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
        is_test=True,
    )

    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Region '{request.region}' not found"
        )

    return {"status": "ok", "region": request.region, "level": request.level}

@router.post("/api/threats/scenario")
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
        await asyncio.to_thread(threat_manager.clear_all, only_test=True)
    else:
        await asyncio.to_thread(threat_manager.set_scenario, request.scenario)

    return {"status": "ok", "scenario": request.scenario}

@router.post("/api/threats/clear")
async def clear_all_threats():
    """Очистити всі загрози."""
    await asyncio.to_thread(threat_manager.clear_all, only_test=True)
    return {"status": "ok", "message": "All threats cleared"}

@router.post("/api/telegram/test")
async def test_telegram_message(request: TelegramTestRequest):
    """Сімулювати отримання повідомлення з Telegram та обробити його негайно."""
    import core.globals
    telegram_monitor = core.globals.telegram_monitor
    
    if telegram_monitor is None:
        raise HTTPException(
            status_code=503,
            detail="Telegram monitor not initialized or running in mock-only mode"
        )
    
    if telegram_monitor.analyzer.is_configured:
        print(f"🧪 [Test Endpoint] Analyzing message: {request.text[:80]}...")
        results = await telegram_monitor.analyzer.analyze_batch([{"channel": request.channel, "text": request.text}])
        if results:
            await telegram_monitor._apply_gemini_analysis(results, is_test=True)
            return {
                "status": "ok",
                "message": "Message analyzed via Gemini immediately",
                "results": results
            }
        else:
            return {"status": "ok", "message": "Analyzed via Gemini, but no targets identified"}
    else:
        await telegram_monitor._process_message_regex(request.text, request.channel)
        return {"status": "ok", "message": "Analyzed via Regex fallback immediately"}
