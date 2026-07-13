"""
Admin Dashboard API.
Aggregated statistics for the admin dashboard.
"""

import sqlite3
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH, get_kyiv_tz_offset
from database.analytics_db import get_sqlite_connection

router = APIRouter()


@router.get("/api/admin/dashboard/stats")
async def get_admin_dashboard_stats():
    """Агреговані статистичні дані для дашборду."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = get_sqlite_connection(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total events (7d) excluding official alarms to match accuracy breakdown
        cursor.execute("""
            SELECT COUNT(*) as c 
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
        """)
        total_7d = cursor.fetchone()["c"]

        # Accuracy breakdown (7d)
        cursor.execute("""
            SELECT
                SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                SUM(CASE WHEN pe.lifecycle_status = 'active' AND pe.prediction_accuracy IS NULL THEN 1 ELSE 0 END) as active,
                COUNT(*) as total
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
        """)
        acc = dict(cursor.fetchone())

        # AI accuracy percentage
        evaluated = (acc["confirmed"] or 0) + (acc["mitigated"] or 0) + (acc["overestimated"] or 0)
        if evaluated > 0:
            accuracy_pct = round(((acc["confirmed"] or 0) + (acc["mitigated"] or 0) * 0.8) / evaluated * 100, 1)
        else:
            accuracy_pct = 0

        # Active threats right now
        cursor.execute("SELECT COUNT(*) as c FROM paired_events WHERE lifecycle_status = 'active'")
        active_now = cursor.fetchone()["c"]

        # Average response time (how early AI detected before alarm)
        cursor.execute("""
            SELECT AVG(
                strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)
            ) as avg_delta
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            JOIN threat_history th_alarm ON th_alarm.region = pe.region
                AND th_alarm.threat_type = 'official_alarm'
                AND th_alarm.threat_level = 'high'
                AND ABS(strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)) < 1800
                AND strftime('%s', th_alarm.timestamp) >= strftime('%s', th_ai.timestamp)
            WHERE th_ai.timestamp >= datetime('now', '-7 days')
                AND pe.was_predictive = 1
                AND pe.threat_type != 'official_alarm'
        """)
        avg_row = cursor.fetchone()
        avg_early_seconds = round(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] else None

        # Threats by type (7d)
        cursor.execute("""
            SELECT pe.threat_type, COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
            GROUP BY pe.threat_type ORDER BY count DESC
        """)
        by_type = [dict(r) for r in cursor.fetchall()]

        # Top regions (7d)
        cursor.execute("""
            SELECT pe.region, COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
            GROUP BY pe.region ORDER BY count DESC LIMIT 10
        """)
        top_regions = [dict(r) for r in cursor.fetchall()]

        # Hourly distribution (7d) — UTC to Kyiv
        cursor.execute(f"""
            SELECT CAST(strftime('%H', datetime(th.timestamp, {tz_modifier})) AS INTEGER) as hour,
                   COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
            GROUP BY hour ORDER BY hour
        """)
        hourly = [dict(r) for r in cursor.fetchall()]

        # Errors count (24h)
        cursor.execute("SELECT COUNT(*) as c FROM error_log WHERE timestamp >= datetime('now', '-1 day')")
        errors_24h = cursor.fetchone()["c"]

        conn.close()

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
