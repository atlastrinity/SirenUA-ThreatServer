"""
Analytics Predictions & Rules API.
Endpoints: ML predictions, Gemini rules management, region history.
"""

import json
from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone

from database.db_helpers import get_db, execute_query_as_dicts

router = APIRouter()


@router.get("/api/analytics/predictions")
async def get_predictions(region: str = None, days: int = 3, limit: int = 50):
    """Активні та завершені AI-прогнози загроз."""
    try:
        query = '''
            SELECT th.*, td.attack_vector, td.speed_kmh, td.altitude_category,
                   td.launch_origin, td.weapon_subtype, td.source_reliability,
                   td.message_context_tags, td.civilian_risk_level,
                   td.air_defense_active, td.engagement_status,
                   pe.prediction_accuracy, pe.lifecycle_status, pe.was_predictive
            FROM threat_history th
            LEFT JOIN telemetry_data td ON th.id = td.threat_event_id
            LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
            WHERE th.timestamp >= datetime('now', ?)
        '''
        params = [f'-{days} days']

        if region:
            from urllib.parse import unquote
            query += " AND th.region = ?"
            params.append(unquote(region))

        query += " ORDER BY th.timestamp DESC LIMIT ?"
        params.append(min(limit, 200))

        events = execute_query_as_dicts(query, tuple(params), json_fields=["message_context_tags"])
        return {"total": len(events), "days": days, "events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/rules")
async def get_rules(active_only: bool = False):
    """Список ML-правил (правила класифікації Gemini)."""
    try:
        if active_only:
            query = "SELECT * FROM gemini_rules WHERE is_active = 1 ORDER BY evidence_count DESC, accuracy_score DESC"
        else:
            query = "SELECT * FROM gemini_rules ORDER BY is_active DESC, evidence_count DESC, accuracy_score DESC"

        rules = execute_query_as_dicts(
            query,
            json_fields=["trigger_conditions", "override_conditions", "applicable_regions", "applicable_types"]
        )
        return {"total": len(rules), "rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
            .order_by("timestamp", direction="DESCENDING")
            .limit(limit)
            .stream()
        )

        history = []
        for doc in docs:
            data = doc.to_dict()
            data["id"] = doc.id
            history.append(data)

        return {"region": region, "count": len(history), "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
