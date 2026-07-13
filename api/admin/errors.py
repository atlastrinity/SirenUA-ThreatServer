"""
Admin Errors API.
Endpoints for error log listing and aggregated error statistics.
"""

import sqlite3
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH, get_kyiv_tz_offset
from database.db_helpers import get_sqlite_connection, execute_query_as_dicts

router = APIRouter()


@router.get("/api/admin/errors")
async def get_admin_errors(source: str = None, error_type: str = None, days: int = 7, limit: int = 100):
    """Список помилок з фільтрами."""
    try:
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

        errors = execute_query_as_dicts(query, tuple(params))
        return {
            "total": len(errors),
            "errors": errors
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/errors/stats")
async def get_admin_errors_stats(days: int = 7):
    """Агреговані лічильники помилок."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        day_filter = f'-{days} days'

        # By source
        by_source = execute_query_as_dicts('''
            SELECT source, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY source ORDER BY count DESC
        ''', (day_filter,))

        # By type
        by_type = execute_query_as_dicts('''
            SELECT error_type, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY error_type ORDER BY count DESC
        ''', (day_filter,))

        # Hourly (last 48h)
        hourly = execute_query_as_dicts(f'''
            SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, {tz_modifier})) as hour, COUNT(*) as count
            FROM error_log
            WHERE timestamp >= datetime('now', '-2 days')
            GROUP BY hour ORDER BY hour
        ''')

        # Total
        total_rows = execute_query_as_dicts("SELECT COUNT(*) as total FROM error_log WHERE timestamp >= datetime('now', ?)", (day_filter,))
        total = total_rows[0]["total"] if total_rows else 0

        return {"total": total, "by_source": by_source, "by_type": by_type, "hourly": hourly}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
