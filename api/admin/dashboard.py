"""
Admin Dashboard API.
Aggregated statistics for the admin dashboard.
"""

from fastapi import APIRouter, HTTPException, Request
from core.config import get_kyiv_tz_offset
from database.db_helpers import execute_query_as_dicts

router = APIRouter()


@router.get("/api/admin/dashboard/stats")
async def get_admin_dashboard_stats():
    """Агреговані статистичні дані для дашборду."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        # Total events (7d) excluding official alarms to match accuracy breakdown
        total_query = """
            SELECT COUNT(*) as c 
            FROM threat_history th
            WHERE th.timestamp >= datetime('now', '-7 days') AND th.threat_type != 'official_alarm'
        """
        total_rows = execute_query_as_dicts(total_query)
        total_7d = total_rows[0]["c"] if total_rows else 0

        # Accuracy breakdown (7d)
        accuracy_query = """
            SELECT
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END), 0) as confirmed,
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END), 0) as mitigated,
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END), 0) as overestimated,
                COALESCE(SUM(CASE WHEN pe.lifecycle_status = 'active' AND pe.prediction_accuracy IS NULL THEN 1 ELSE 0 END), 0) as active,
                COUNT(*) as total
            FROM threat_history th
            LEFT JOIN paired_events pe ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND th.threat_type != 'official_alarm'
        """
        accuracy_rows = execute_query_as_dicts(accuracy_query)
        acc = accuracy_rows[0] if accuracy_rows else {"confirmed": 0, "mitigated": 0, "overestimated": 0, "active": 0, "total": 0}

        # AI accuracy percentage
        evaluated = (acc["confirmed"] or 0) + (acc["mitigated"] or 0) + (acc["overestimated"] or 0)
        if evaluated > 0:
            accuracy_pct = round(((acc["confirmed"] or 0) + (acc["mitigated"] or 0) * 0.8) / evaluated * 100, 1)
        else:
            accuracy_pct = 0

        # Active threats right now
        active_query = "SELECT COUNT(*) as c FROM threat_history WHERE threat_level IN ('high', 'medium') AND threat_type != 'official_alarm' AND timestamp >= datetime('now', '-2 hours')"
        active_rows = execute_query_as_dicts(active_query)
        active_now = active_rows[0]["c"] if active_rows else 0

        # Average response time (how early AI detected before alarm)
        avg_query = """
            SELECT AVG(
                strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)
            ) as avg_delta
            FROM threat_history th_ai
            LEFT JOIN paired_events pe ON pe.threat_event_id = th_ai.id
            JOIN threat_history th_alarm ON th_alarm.region = th_ai.region
                AND th_alarm.threat_type = 'official_alarm'
                AND th_alarm.threat_level = 'high'
                AND ABS(strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)) < 1800
                AND strftime('%s', th_alarm.timestamp) >= strftime('%s', th_ai.timestamp)
            WHERE th_ai.timestamp >= datetime('now', '-7 days')
                AND th_ai.threat_type != 'official_alarm'
        """
        avg_rows = execute_query_as_dicts(avg_query)
        avg_row = avg_rows[0] if avg_rows else None
        avg_early_seconds = round(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] is not None else None

        # Threats by type (7d)
        type_query = """
            SELECT th.threat_type, COUNT(*) as count
            FROM threat_history th
            WHERE th.timestamp >= datetime('now', '-7 days') AND th.threat_type != 'official_alarm'
            GROUP BY th.threat_type ORDER BY count DESC
        """
        by_type = execute_query_as_dicts(type_query)

        # Top regions (7d)
        regions_query = """
            SELECT th.region, COUNT(*) as count
            FROM threat_history th
            WHERE th.timestamp >= datetime('now', '-7 days') AND th.threat_type != 'official_alarm'
            GROUP BY th.region ORDER BY count DESC LIMIT 10
        """
        top_regions = execute_query_as_dicts(regions_query)

        # Hourly distribution (7d) — UTC to Kyiv
        hourly_query = f"""
            SELECT CAST(strftime('%H', datetime(th.timestamp, {tz_modifier})) AS INTEGER) as hour,
                   COUNT(*) as count
            FROM threat_history th
            WHERE th.timestamp >= datetime('now', '-7 days') AND th.threat_type != 'official_alarm'
            GROUP BY hour ORDER BY hour
        """
        hourly = execute_query_as_dicts(hourly_query)

        # Errors count (24h)
        errors_query = "SELECT COUNT(*) as c FROM error_log WHERE timestamp >= datetime('now', '-1 day')"
        errors_rows = execute_query_as_dicts(errors_query)
        errors_24h = errors_rows[0]["c"] if errors_rows else 0

        return {
            "total_events_7d": total_7d,
            "accuracy": acc,
            "accuracy_pct": accuracy_pct,
            "active_now": active_now,
            "avg_early_seconds": avg_early_seconds,
            "by_type": by_type,
            "top_regions": top_regions,
            "hourly": hourly,
            "errors_24h": errors_24h
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


async def _run_db_operation(fn, success_msg: str, fail_msg: str, err_prefix: str, *args):
    try:
        import asyncio
        result = await asyncio.to_thread(fn, *args)
        if result:
            return {"status": "ok", "message": success_msg}
        return {"status": "warning", "message": fail_msg}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"{err_prefix}: {str(e)}")


@router.post("/api/admin/backup")
async def trigger_backup():
    """Примусовий бекап SQLite у Firebase Firestore."""
    from database.db_helpers import backup_sqlite_to_firestore
    return await _run_db_operation(
        backup_sqlite_to_firestore,
        "Бекап SQLite успішно збережено у Firebase.",
        "Бекап не вдався (Firebase не ініціалізовано або БД порожня).",
        "Помилка бекапу"
    )


@router.post("/api/admin/restore")
async def trigger_restore():
    """Примусове відновлення SQLite з Firebase Firestore."""
    from database.db_helpers import restore_sqlite_from_firestore
    return await _run_db_operation(
        restore_sqlite_from_firestore,
        "SQLite успішно відновлено з Firebase бекапу.",
        "Відновлення не вдалося (бекап відсутній або Firebase не ініціалізовано).",
        "Помилка відновлення",
        True
    )


@router.post("/api/admin/restore_upload")
async def trigger_restore_upload(request: Request):
    """Відновлення SQLite з HTTP-завантаженого gzip+base64 бекапу (обхід Firestore)."""
    try:
        from database.db_helpers import _restore_from_payload
        import asyncio
        body = await request.json()
        encoded = body.get("data")
        if not encoded:
            raise HTTPException(status_code=400, detail="Missing 'data' field with base64+gzip payload")
        result = await asyncio.to_thread(_restore_from_payload, encoded)
        if result:
            return {"status": "ok", "message": "SQLite успішно відновлено з завантаженого бекапу."}
        return {"status": "warning", "message": "Відновлення не вдалося."}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка відновлення: {str(e)}")

