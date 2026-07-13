"""
Analytics Predictions & Rules API.
Endpoints: ML predictions, Gemini rules management, region history.
"""

import sqlite3
import json
from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone

from core.config import DB_PATH
from database.db_helpers import get_db

router = APIRouter()


@router.get("/api/analytics/predictions")
async def get_predictions(region: str = None, days: int = 3, limit: int = 50):
    """Активні та завершені AI-прогнози загроз."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

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

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        events = []
        for row in rows:
            event = dict(row)
            if event.get("message_context_tags"):
                try:
                    event["message_context_tags"] = json.loads(event["message_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    event["message_context_tags"] = []
            events.append(event)

        return {"total": len(events), "days": days, "events": events}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/rules")
async def get_rules(active_only: bool = False):
    """Список ML-правил (правила класифікації Gemini)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if active_only:
            cursor.execute("SELECT * FROM gemini_rules WHERE is_active = 1 ORDER BY evidence_count DESC, accuracy_score DESC")
        else:
            cursor.execute("SELECT * FROM gemini_rules ORDER BY is_active DESC, evidence_count DESC, accuracy_score DESC")

        rows = cursor.fetchall()
        conn.close()

        rules = []
        for row in rows:
            rule = dict(row)
            for field in ["trigger_conditions", "override_conditions", "applicable_regions", "applicable_types"]:
                if rule.get(field):
                    try:
                        rule[field] = json.loads(rule[field])
                    except (json.JSONDecodeError, TypeError):
                        pass
            rules.append(rule)

        return {"total": len(rules), "rules": rules}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analytics/rules/rebuild")
async def rebuild_rules():
    """Перебудовує правила класифікації з поточної бази даних (Gemini)."""
    try:
        from core.globals import threat_manager
        if threat_manager is None:
            raise HTTPException(status_code=503, detail="ThreatManager не ініціалізовано")
        if not hasattr(threat_manager, 'rebuild_rules'):
            raise HTTPException(status_code=501, detail="ThreatManager не підтримує rebuild_rules")
        result = await threat_manager.rebuild_rules()
        return {"status": "ok", "result": result}
    except HTTPException:
        raise
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
