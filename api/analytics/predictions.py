"""
Analytics Predictions & Rules API.
Endpoints: ML predictions, Gemini rules management, region history.
"""

import json
from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone

from database.db_helpers import get_db, execute_query_as_dicts
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


@router.get("/api/history/{region}")
async def get_region_history(region: str, limit: int = 50):
    """Публічна хронологія загроз для регіону (для клієнтського додатку)."""
    from urllib.parse import unquote
    region = unquote(region)

    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firestore недоступний")

    try:
        docs = (
            db.collection("sirenua_history")
            .where("region", "==", region)
            .stream()
        )

        history = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            history.append(data)

        # Sort in memory by timestamp descending
        history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        history = history[:limit]

        return {"region": region, "count": len(history), "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
