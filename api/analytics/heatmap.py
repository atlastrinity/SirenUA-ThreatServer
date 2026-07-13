"""
Analytics Heatmap & Stats API.
Endpoints: heatmap data, aggregated statistics, attack patterns.
"""

from fastapi import APIRouter, HTTPException
from database.db_helpers import execute_query_as_dicts

router = APIRouter()


@router.get("/api/analytics/heatmap")
async def get_heatmap_data(days: int = 7):
    """Повертає історичні дані загроз для побудови теплової карти."""
    try:
        query = '''
            SELECT region, COUNT(*) as threat_count, MAX(timestamp) as last_threat 
            FROM threat_history 
            WHERE timestamp >= datetime('now', ?) 
            GROUP BY region
            ORDER BY threat_count DESC
        '''
        data = execute_query_as_dicts(query, (f'-{days} days',))
        return {"days": days, "data": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/stats")
async def get_analytics_stats(days: int = 7):
    """Агреговані показники за останні N днів."""
    try:
        day_filter = f'-{days} days'

        speed_query = '''
            SELECT th.threat_type, 
                   AVG(td.speed_kmh) as avg_speed,
                   COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.speed_kmh IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY th.threat_type
        '''
        speed_by_type = [
            {"type": r["threat_type"], "avg_speed": round(r["avg_speed"], 1), "count": r["count"]} 
            for r in execute_query_as_dicts(speed_query, (day_filter,))
        ]

        vector_query = '''
            SELECT td.attack_vector, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.attack_vector != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.attack_vector
            ORDER BY count DESC LIMIT 10
        '''
        top_vectors = execute_query_as_dicts(vector_query, (day_filter,))

        confidence_query = '''
            SELECT threat_type, AVG(confidence) as avg_confidence, COUNT(*) as count
            FROM threat_history
            WHERE confidence IS NOT NULL AND timestamp >= datetime('now', ?)
            GROUP BY threat_type
        '''
        confidence_by_type = [
            {"type": r["threat_type"], "avg_confidence": round(r["avg_confidence"], 1), "count": r["count"]} 
            for r in execute_query_as_dicts(confidence_query, (day_filter,))
        ]

        hourly_query = '''
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
        '''
        hourly_histogram = execute_query_as_dicts(hourly_query, (day_filter,))

        regions_query = '''
            SELECT region, COUNT(*) as count, 
                   AVG(confidence) as avg_confidence
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY region
            ORDER BY count DESC LIMIT 10
        '''
        top_regions = [
            {"region": r["region"], "count": r["count"], "avg_confidence": round(r["avg_confidence"], 1) if r["avg_confidence"] else None} 
            for r in execute_query_as_dicts(regions_query, (day_filter,))
        ]

        engagement_query = '''
            SELECT td.engagement_status, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.engagement_status != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.engagement_status
            ORDER BY count DESC
        '''
        engagement_stats = execute_query_as_dicts(engagement_query, (day_filter,))

        wave_query = '''
            SELECT COUNT(DISTINCT td.group_id) as total_waves,
                   AVG(td.wave_number) as avg_waves_per_attack
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.group_id IS NOT NULL AND th.timestamp >= datetime('now', ?)
        '''
        wave_rows = execute_query_as_dicts(wave_query, (day_filter,))
        wave_row = wave_rows[0] if wave_rows else None
        wave_stats = {
            "total_waves": wave_row["total_waves"] if wave_row else 0,
            "avg_waves_per_attack": round(wave_row["avg_waves_per_attack"], 1) if wave_row and wave_row["avg_waves_per_attack"] else 0
        }

        total_query = '''SELECT COUNT(*) as total FROM threat_history WHERE timestamp >= datetime('now', ?)'''
        total_rows = execute_query_as_dicts(total_query, (day_filter,))
        total = total_rows[0]["total"] if total_rows else 0

        return {
            "days": days,
            "total_events": total,
            "avg_speed_by_type": speed_by_type,
            "top_attack_vectors": top_vectors,
            "avg_confidence_by_type": confidence_by_type,
            "hourly_histogram": hourly_histogram,
            "top_targeted_regions": top_regions,
            "engagement_stats": engagement_stats,
            "wave_stats": wave_stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/patterns")
async def get_patterns(days: int = 14):
    """Виявлені патерни атак (час доби, напрямки, типи)."""
    try:
        day_filter = f'-{days} days'

        time_query = '''
            SELECT td.time_of_day_category, th.threat_type, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.time_of_day_category != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.time_of_day_category, th.threat_type
            ORDER BY count DESC
        '''
        time_patterns = execute_query_as_dicts(time_query, (day_filter,))

        origin_query = '''
            SELECT td.launch_origin, COUNT(*) as count, 
                   GROUP_CONCAT(DISTINCT th.threat_type) as threat_types
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.launch_origin IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.launch_origin
            ORDER BY count DESC LIMIT 10
        '''
        origin_patterns = []
        for r in execute_query_as_dicts(origin_query, (day_filter,)):
            d = dict(r)
            d["threat_types"] = d["threat_types"].split(",") if d["threat_types"] else []
            origin_patterns.append(d)

        priority_query = '''
            SELECT td.strategic_priority, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT th.region) as regions
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.strategic_priority IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.strategic_priority
            ORDER BY count DESC
        '''
        priority_patterns = []
        for r in execute_query_as_dicts(priority_query, (day_filter,)):
            d = dict(r)
            d["regions"] = d["regions"].split(",") if d["regions"] else []
            priority_patterns.append(d)

        dow_query = '''
            SELECT CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY day_of_week
            ORDER BY day_of_week
        '''
        day_names = ['Неділя', 'Понеділок', 'Вівторок', 'Середа', 'Четвер', "П'ятниця", 'Субота']
        dow_dist = [
            {"day": day_names[r["day_of_week"]], "day_number": r["day_of_week"], "count": r["count"]} 
            for r in execute_query_as_dicts(dow_query, (day_filter,))
        ]

        risk_query = '''
            SELECT td.civilian_risk_level, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.civilian_risk_level IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.civilian_risk_level
            ORDER BY count DESC
        '''
        risk_dist = execute_query_as_dicts(risk_query, (day_filter,))

        return {
            "days": days,
            "time_of_day_patterns": time_patterns,
            "launch_origin_patterns": origin_patterns,
            "strategic_priority_patterns": priority_patterns,
            "day_of_week_distribution": dow_dist,
            "civilian_risk_distribution": risk_dist
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
