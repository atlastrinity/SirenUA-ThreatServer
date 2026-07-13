"""
Admin Errors API.
Endpoints for error log listing and aggregated error statistics.
"""

import sqlite3
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH

router = APIRouter()


def _get_kyiv_tz_offset() -> int:
    """Returns the current UTC offset for Europe/Kiev (handles DST)."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        return int(dt.strftime('%z')[:3])
    except Exception:
        return 3  # Fallback to Kyiv default (UTC+3)


@router.get("/api/admin/errors")
async def get_admin_errors(source: str = None, error_type: str = None, days: int = 7, limit: int = 100):
    """Список помилок з фільтрами."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM error_log WHERE timestamp >= datetime('now', ?)"
        params = [f'-{days} days']

        if source:
            query += " AND source = ?"
            params.append(source)
        if error_type:
            query += " AND error_type = ?"
            params.append(error_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return {
            "total": len(rows),
            "errors": [dict(r) for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/errors/stats")
async def get_admin_errors_stats(days: int = 7):
    """Агреговані лічильники помилок."""
    offset_hours = _get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'

        # By source
        cursor.execute('''
            SELECT source, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY source ORDER BY count DESC
        ''', (day_filter,))
        by_source = [dict(r) for r in cursor.fetchall()]

        # By type
        cursor.execute('''
            SELECT error_type, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY error_type ORDER BY count DESC
        ''', (day_filter,))
        by_type = [dict(r) for r in cursor.fetchall()]

        # Hourly (last 48h)
        cursor.execute(f'''
            SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, {tz_modifier})) as hour, COUNT(*) as count
            FROM error_log
            WHERE timestamp >= datetime('now', '-2 days')
            GROUP BY hour ORDER BY hour
        ''')
        hourly = [dict(r) for r in cursor.fetchall()]

        # Total
        cursor.execute("SELECT COUNT(*) as total FROM error_log WHERE timestamp >= datetime('now', ?)", (day_filter,))
        total = cursor.fetchone()["total"]

        conn.close()
        return {"total": total, "by_source": by_source, "by_type": by_type, "hourly": hourly}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
