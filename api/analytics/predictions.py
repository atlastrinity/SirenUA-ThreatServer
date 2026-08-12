"""
Analytics Predictions & Rules API.
Endpoints: ML predictions, Gemini rules management, region history.
"""

from fastapi import APIRouter, HTTPException
from datetime import timezone

from database.db_helpers import get_db
from database.query_builder import build_and_execute_query

router = APIRouter()


@router.get("/api/analytics/predictions")
async def get_predictions(region: str = None, days: int = 3, limit: int = 50):
    """Активні та завершені AI-прогнози загроз."""
    base_query = '''
        SELECT th.*, td.attack_vector, td.speed_kmh, td.altitude_category,
               td.launch_origin, td.weapon_subtype, td.source_reliability,
               td.message_context_tags, td.civilian_risk_level,
               td.air_defense_active, td.engagement_status,
               pe.prediction_accuracy, pe.lifecycle_status, pe.was_predictive
        FROM threat_history th
        LEFT JOIN telemetry_data td ON th.id = td.threat_event_id
        LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
    '''
    filters = {}
    if region:
        from urllib.parse import unquote
        filters["th.region"] = unquote(region)

    events = build_and_execute_query(
        base_query=base_query,
        date_column="th.timestamp",
        days=days,
        filters=filters,
        order_by="th.timestamp DESC",
        limit=limit,
        json_fields=["message_context_tags"]
    )
    return {"total": len(events), "days": days, "events": events}


@router.get("/api/analytics/rules")
async def get_rules(active_only: bool = False):
    """Список ML-правил (правила класифікації Gemini)."""
    filters = {"is_active": 1} if active_only else None
    order_by = "evidence_count DESC, accuracy_score DESC" if active_only else "is_active DESC, evidence_count DESC, accuracy_score DESC"

    rules = build_and_execute_query(
        base_query="SELECT * FROM gemini_rules",
        filters=filters,
        order_by=order_by,
        json_fields=["trigger_conditions", "override_conditions", "applicable_regions", "applicable_types"]
    )
    return {"total": len(rules), "rules": rules}


@router.post("/api/analytics/rules/rebuild")
async def rebuild_rules():
    """Перебудовує правила класифікації з поточної бази даних (Gemini)."""
    try:
        from analyzer.gemini_analyzer import GeminiThreatAnalyzer
        from database.error_logger import log_error_to_db, log_rule_audit_to_db
        import asyncio

        analyzer = GeminiThreatAnalyzer(error_callback=log_error_to_db, rule_audit_callback=log_rule_audit_to_db)
        
        loop = asyncio.get_event_loop()
        rules_updated = await loop.run_in_executor(None, analyzer.run_rules_learner)
        
        return {"status": "ok", "rules_updated": rules_updated}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


from typing import Optional
import sqlite3
import asyncio

@router.get("/api/history/{region}")
async def get_region_history(
    region: str,
    date: Optional[str] = None,
    limit: int = 200
):
    """
    Повертає хронологію загроз для області за вказаний календарний день.
    
    Час фільтрується суворо за Київською добою (00:00:00 — 23:59:59 Europe/Kiev).
    
    Дані джерел:
      - SQLite (threat_history) — основне джерело. Миттєва локальна вибірка без
        обмежень квот та мережевих затримок. Містить і загрози, і відбої
        (clearing_logger записує відбій як threat_level="none" прямо сюди).
      - Firestore (sirenua_history) — резервне джерело (фолбек), використовується лише
        якщо SQLite повернув 0 подій (наприклад, новий контейнер до відновлення бекапу).
    
    Args:
        region: Назва області (URL-encoded)
        date: Дата у форматі YYYY-MM-DD. Без параметра — сьогодні за Києвом.
        limit: Максимальна кількість подій (до 200)
    """
    from urllib.parse import unquote
    from datetime import datetime as dt, timedelta, time as dt_time, timezone
    from database.db_helpers import DB_PATH
    region = unquote(region)
    
    # --- Часова зона Києва ---
    try:
        import zoneinfo
        kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
    except ImportError:
        from backports import zoneinfo
        kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
    
    now_kyiv = dt.now(kyiv_tz)

    # --- Визначення календарного дня ---
    if date:
        try:
            target_date = dt.strptime(date, "%Y-%m-%d").date()
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірний формат дати. Використовуйте YYYY-MM-DD")
    else:
        target_date = now_kyiv.date()
    
    # Суворі межі календарної доби за Києвом → конвертація в UTC
    day_start_kyiv = dt.combine(target_date, dt_time.min).replace(tzinfo=kyiv_tz)
    day_end_kyiv = dt.combine(target_date, dt_time.max).replace(tzinfo=kyiv_tz)
    
    utc_start = day_start_kyiv.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    utc_end = day_end_kyiv.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # --- Отримання подій ---
    events = []
    
    # 1. SQLite (основне джерело) — миттєва локальна вибірка без обмежень квот та мережевих затримок
    try:
        def _fetch_sqlite():
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, region, threat_level, threat_type, detail, confidence
                FROM threat_history
                WHERE region = ? AND timestamp >= ? AND timestamp <= ? AND is_test = 0
                ORDER BY timestamp DESC
                LIMIT ?
            """, (region, utc_start, utc_end, min(limit, 200)))
            rows = cursor.fetchall()
            conn.close()
            return [{
                "id": str(row["id"]),
                "timestamp": row["timestamp"],
                "region": row["region"],
                "threat_level": row["threat_level"],
                "threat_type": row["threat_type"],
                "detail": row["detail"],
                "confidence": row["confidence"]
            } for row in rows]

        events = await asyncio.to_thread(_fetch_sqlite)
    except Exception as e:
        print(f"⚠️ [History API] SQLite fetch failed: {e}")

    # 2. Firestore фолбек — лише якщо SQLite порожній (наприклад, новий контейнер до відновлення)
    if not events:
        db = get_db()
        if db:
            try:
                docs = await asyncio.to_thread(
                    lambda: db.collection('sirenua_history')
                              .where('region', '==', region)
                              .limit(min(limit, 200))
                              .get()
                )
                for doc in docs:
                    d = doc.to_dict()
                    ts = d.get('timestamp', '')
                    if utc_start <= ts <= utc_end:
                        events.append(d)
            except Exception as e:
                print(f"⚠️ [History API] Firestore fallback fetch failed: {e}")

    # --- Сортування та дедуплікація ---
    events.sort(key=lambda x: str(x.get('timestamp', '')), reverse=True)
    
    seen = set()
    unique = []
    for ev in events:
        key = f"{ev.get('timestamp')}|{ev.get('threat_level')}|{ev.get('threat_type')}"
        if key not in seen:
            seen.add(key)
            unique.append(ev)
    
    unique = unique[:min(limit, 200)]
    
    return {
        "region": region,
        "date": str(target_date),
        "count": len(unique),
        "events": unique,
        "history": unique
    }

