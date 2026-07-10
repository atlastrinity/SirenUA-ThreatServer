"""
SirenUA Analytics API Router.
FastAPI routes for heatmap data, telemetry, wave group analysis, pattern mapping, predictions, and rules.
"""

import sqlite3
import json
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH
from database.db_helpers import get_db
from database.analytics_db import log_error_to_db, log_rule_audit_to_db

router = APIRouter()

@router.get("/api/analytics/heatmap")
async def get_heatmap_data(days: int = 7):
    """Повертає історичні дані загроз для побудови теплової карти."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Запит рахує кількість тривог по регіонах за останні `days` днів
        cursor.execute('''
            SELECT region, COUNT(*) as threat_count, MAX(timestamp) as last_threat 
            FROM threat_history 
            WHERE timestamp >= datetime('now', ?) 
            GROUP BY region
            ORDER BY threat_count DESC
        ''', (f'-{days} days',))
        
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "days": days,
            "data": [dict(row) for row in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/telemetry/{region}")
async def get_region_telemetry(region: str, limit: int = 50, days: int = 30):
    """Повна телеметрія для регіону з групуванням."""
    from urllib.parse import unquote
    region = unquote(region)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT th.id, th.timestamp, th.region, th.threat_level, th.threat_type,
                   th.detail, th.confidence,
                   td.group_id, td.attack_vector, td.target_count, td.speed_kmh,
                   td.altitude_category, td.heading_degrees, td.distance_to_target_km,
                   td.launch_origin, td.weapon_subtype, td.engagement_status,
                   td.air_defense_active, td.multiple_waves, td.wave_number,
                   td.time_of_day_category, td.weather_factor, td.source_reliability,
                   td.message_context_tags, td.strategic_priority, td.civilian_risk_level,
                   td.event_phase, td.correlation_group
            FROM threat_history th
            LEFT JOIN telemetry_data td ON th.id = td.threat_event_id
            WHERE th.region = ? AND th.timestamp >= datetime('now', ?)
            ORDER BY th.timestamp DESC
            LIMIT ?
        ''', (region, f'-{days} days', min(limit, 200)))
        
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
        
        return {
            "region": region,
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/groups")
async def get_attack_groups(days: int = 7, limit: int = 50):
    """Список атакових хвиль/груп за останні N днів."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                td.group_id,
                td.correlation_group,
                td.attack_vector,
                COUNT(DISTINCT th.id) as event_count,
                COUNT(DISTINCT th.region) as region_count,
                GROUP_CONCAT(DISTINCT th.region) as regions,
                MIN(th.timestamp) as first_seen,
                MAX(th.timestamp) as last_seen,
                AVG(th.confidence) as avg_confidence,
                AVG(td.speed_kmh) as avg_speed,
                SUM(td.target_count) as total_targets,
                MAX(td.wave_number) as max_wave,
                GROUP_CONCAT(DISTINCT th.threat_type) as threat_types
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.group_id IS NOT NULL
              AND th.timestamp >= datetime('now', ?)
            GROUP BY td.group_id
            ORDER BY MAX(th.timestamp) DESC
            LIMIT ?
        ''', (f'-{days} days', min(limit, 100)))
        
        rows = cursor.fetchall()
        conn.close()
        
        groups = []
        for row in rows:
            group = dict(row)
            group["regions"] = group["regions"].split(",") if group["regions"] else []
            group["threat_types"] = group["threat_types"].split(",") if group["threat_types"] else []
            if group["avg_confidence"]:
                group["avg_confidence"] = round(group["avg_confidence"], 1)
            if group["avg_speed"]:
                group["avg_speed"] = round(group["avg_speed"], 1)
            groups.append(group)
        
        return {
            "days": days,
            "total_groups": len(groups),
            "groups": groups
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/stats")
async def get_analytics_stats(days: int = 7):
    """Агреговані показники за останні N днів."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Average speed by threat type
        cursor.execute('''
            SELECT th.threat_type, 
                   AVG(td.speed_kmh) as avg_speed,
                   COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.speed_kmh IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY th.threat_type
        ''', (day_filter,))
        speed_by_type = [{"type": r["threat_type"], "avg_speed": round(r["avg_speed"], 1), "count": r["count"]} for r in cursor.fetchall()]
        
        # 2. Top attack vectors
        cursor.execute('''
            SELECT td.attack_vector, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.attack_vector != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.attack_vector
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        top_vectors = [dict(r) for r in cursor.fetchall()]
        
        # 3. Average confidence by threat type
        cursor.execute('''
            SELECT threat_type, AVG(confidence) as avg_confidence, COUNT(*) as count
            FROM threat_history
            WHERE confidence IS NOT NULL AND timestamp >= datetime('now', ?)
            GROUP BY threat_type
        ''', (day_filter,))
        confidence_by_type = [{"type": r["threat_type"], "avg_confidence": round(r["avg_confidence"], 1), "count": r["count"]} for r in cursor.fetchall()]
        
        # 4. Hourly distribution
        cursor.execute('''
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
        ''', (day_filter,))
        hourly_histogram = [dict(r) for r in cursor.fetchall()]
        
        # 5. Top targeted regions
        cursor.execute('''
            SELECT region, COUNT(*) as count, 
                   AVG(confidence) as avg_confidence
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY region
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        top_regions = [{"region": r["region"], "count": r["count"], "avg_confidence": round(r["avg_confidence"], 1) if r["avg_confidence"] else None} for r in cursor.fetchall()]
        
        # 6. Engagement status distribution (interception rate)
        cursor.execute('''
            SELECT td.engagement_status, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.engagement_status != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.engagement_status
            ORDER BY count DESC
        ''', (day_filter,))
        engagement_stats = [dict(r) for r in cursor.fetchall()]
        
        # 7. Wave frequency
        cursor.execute('''
            SELECT COUNT(DISTINCT td.group_id) as total_waves,
                   AVG(td.wave_number) as avg_waves_per_attack
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.group_id IS NOT NULL AND th.timestamp >= datetime('now', ?)
        ''', (day_filter,))
        wave_row = cursor.fetchone()
        wave_stats = {
            "total_waves": wave_row["total_waves"] if wave_row else 0,
            "avg_waves_per_attack": round(wave_row["avg_waves_per_attack"], 1) if wave_row and wave_row["avg_waves_per_attack"] else 0
        }
        
        # 8. Total events
        cursor.execute('''
            SELECT COUNT(*) as total FROM threat_history WHERE timestamp >= datetime('now', ?)
        ''', (day_filter,))
        total = cursor.fetchone()["total"]
        
        conn.close()
        
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
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Time-of-day pattern
        cursor.execute('''
            SELECT td.time_of_day_category, th.threat_type, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.time_of_day_category != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.time_of_day_category, th.threat_type
            ORDER BY count DESC
        ''', (day_filter,))
        time_patterns = [dict(r) for r in cursor.fetchall()]
        
        # 2. Launch origin frequency
        cursor.execute('''
            SELECT td.launch_origin, COUNT(*) as count, 
                   GROUP_CONCAT(DISTINCT th.threat_type) as threat_types
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.launch_origin IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.launch_origin
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        origin_patterns = []
        for r in cursor.fetchall():
            d = dict(r)
            d["threat_types"] = d["threat_types"].split(",") if d["threat_types"] else []
            origin_patterns.append(d)
        
        # 3. Strategic priority targets
        cursor.execute('''
            SELECT td.strategic_priority, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT th.region) as regions
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.strategic_priority IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.strategic_priority
            ORDER BY count DESC
        ''', (day_filter,))
        priority_patterns = []
        for r in cursor.fetchall():
            d = dict(r)
            d["regions"] = d["regions"].split(",") if d["regions"] else []
            priority_patterns.append(d)
        
        # 4. Day-of-week distribution
        cursor.execute('''
            SELECT CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY day_of_week
            ORDER BY day_of_week
        ''', (day_filter,))
        day_names = ['Неділя', 'Понеділок', 'Вівторок', 'Середа', 'Четвер', "П'ятниця", 'Субота']
        dow_dist = [{"day": day_names[r["day_of_week"]], "day_number": r["day_of_week"], "count": r["count"]} for r in cursor.fetchall()]
        
        # 5. Civilian risk level distribution
        cursor.execute('''
            SELECT td.civilian_risk_level, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.civilian_risk_level IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.civilian_risk_level
            ORDER BY count DESC
        ''', (day_filter,))
        risk_dist = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
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


@router.get("/api/analytics/lifecycle/{region}")
async def get_lifecycle_data(region: str, days: int = 30, limit: int = 50):
    """Повний lifecycle загроз для регіону: встановлення → зняття з телеметрією обох подій."""
    from urllib.parse import unquote
    region = unquote(region)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                tc.id as clearing_id,
                tc.timestamp as clearing_timestamp,
                tc.region,
                tc.original_threat_event_id,
                tc.linked_group_id,
                tc.linked_correlation_group,
                tc.resolution_type,
                tc.intercepted_count,
                tc.total_targets_in_wave,
                tc.impact_confirmed,
                tc.damage_assessment,
                tc.civilian_casualties_reported,
                tc.infrastructure_hit,
                tc.air_defense_effectiveness,
                tc.threat_duration_assessment,
                tc.prediction_accuracy_hint,
                tc.was_predictive,
                tc.original_threat_level,
                tc.original_threat_type,
                tc.original_confidence,
                tc.clearing_confidence,
                tc.clearing_context_tags,
                tc.source_reliability,
                tc.time_of_day_category,
                tc.clearing_source_channel,
                tc.threat_set_timestamp,
                tc.threat_duration_seconds
            FROM threat_clearings tc
            WHERE tc.region = ? AND tc.timestamp >= datetime('now', ?)
            ORDER BY tc.timestamp DESC
            LIMIT ?
        ''', (region, f'-{days} days', min(limit, 200)))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            if event.get("clearing_context_tags"):
                try:
                    event["clearing_context_tags"] = json.loads(event["clearing_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    event["clearing_context_tags"] = []
            events.append(event)
        
        return {
            "region": region,
            "count": len(events),
            "lifecycle_events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/predictions")
async def get_prediction_accuracy(days: int = 30):
    """Валідація точності предиктивних (жовтих) регіонів — ключова аналітика для покращення моделі."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Overall prediction accuracy
        cursor.execute('''
            SELECT 
                prediction_accuracy_hint,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY prediction_accuracy_hint
            ORDER BY count DESC
        ''', (day_filter,))
        accuracy_dist = [dict(r) for r in cursor.fetchall()]
        
        # 2. Prediction accuracy by region
        cursor.execute('''
            SELECT 
                region,
                prediction_accuracy_hint,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY region, prediction_accuracy_hint
            ORDER BY region, count DESC
        ''', (day_filter,))
        by_region_raw = cursor.fetchall()
        
        region_accuracy = {}
        for r in by_region_raw:
            rn = r["region"]
            if rn not in region_accuracy:
                region_accuracy[rn] = {"region": rn, "predictions": [], "total": 0}
            region_accuracy[rn]["predictions"].append({
                "hint": r["prediction_accuracy_hint"],
                "count": r["count"]
            })
            region_accuracy[rn]["total"] += r["count"]
        
        # 3. Resolution type distribution for predictive regions
        cursor.execute('''
            SELECT 
                resolution_type,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY resolution_type
            ORDER BY count DESC
        ''', (day_filter,))
        pred_resolution_dist = [dict(r) for r in cursor.fetchall()]
        
        # 4. Air defense effectiveness for predictive regions
        cursor.execute('''
            SELECT 
                air_defense_effectiveness,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND air_defense_effectiveness != 'unknown'
              AND timestamp >= datetime('now', ?)
            GROUP BY air_defense_effectiveness
            ORDER BY count DESC
        ''', (day_filter,))
        pred_ad_eff = [dict(r) for r in cursor.fetchall()]
        
        # 5. Average threat duration for confirmed vs overestimated predictions
        cursor.execute('''
            SELECT 
                prediction_accuracy_hint,
                AVG(threat_duration_seconds) as avg_duration_sec,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND threat_duration_seconds IS NOT NULL
              AND timestamp >= datetime('now', ?)
            GROUP BY prediction_accuracy_hint
        ''', (day_filter,))
        duration_by_accuracy = [dict(r) for r in cursor.fetchall()]
        
        # 6. Total stats
        cursor.execute('''
            SELECT 
                COUNT(*) as total_clearings,
                SUM(CASE WHEN was_predictive = 1 THEN 1 ELSE 0 END) as predictive_clearings,
                SUM(CASE WHEN was_predictive = 0 THEN 1 ELSE 0 END) as direct_clearings,
                SUM(CASE WHEN impact_confirmed = 1 THEN 1 ELSE 0 END) as total_impacts,
                SUM(CASE WHEN civilian_casualties_reported = 1 THEN 1 ELSE 0 END) as civilian_incidents,
                AVG(threat_duration_seconds) as avg_duration_sec
            FROM threat_clearings
            WHERE timestamp >= datetime('now', ?)
        ''', (day_filter,))
        totals = dict(cursor.fetchone())
        if totals.get("avg_duration_sec"):
            totals["avg_duration_sec"] = round(totals["avg_duration_sec"], 1)
        
        conn.close()
        
        return {
            "days": days,
            "totals": totals,
            "prediction_accuracy_distribution": accuracy_dist,
            "prediction_accuracy_by_region": list(region_accuracy.values()),
            "predictive_resolution_types": pred_resolution_dist,
            "predictive_air_defense_effectiveness": pred_ad_eff,
            "avg_duration_by_accuracy": duration_by_accuracy
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/rules")
async def get_rules(active_only: bool = True, rule_type: str = None, limit: int = 50, threat_type: str = None):
    """Список правил самонавчання Gemini."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM gemini_rules WHERE 1=1"
        params = []
        
        if active_only:
            query += " AND is_active = 1"
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
        
        query += " ORDER BY evidence_count DESC, accuracy_score DESC LIMIT ?"
        params.append(min(limit, 200))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        rules = []
        for row in rows:
            rule = dict(row)
            if rule.get("rule_json"):
                try:
                    rule["rule_json"] = json.loads(rule["rule_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
            rules.append(rule)
        
        return {
            "total": len(rules),
            "active_only": active_only,
            "rules": rules
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/analytics/paired-events")
async def get_paired_events(region: str = None, status: str = None, days: int = 7, limit: int = 50):
    """Спарені події (lifecycle): загроза → телеметрія → clearing."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT pe.*, 
                   th.timestamp as threat_timestamp,
                   th.detail as threat_detail,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type,
                   tc.air_defense_effectiveness,
                   tc.clearing_context_tags
            FROM paired_events pe
            LEFT JOIN threat_history th ON pe.threat_event_id = th.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.created_at >= datetime('now', ?)
        """
        params = [f'-{days} days']
        
        if region:
            from urllib.parse import unquote
            query += " AND pe.region = ?"
            params.append(unquote(region))
        if status:
            query += " AND pe.lifecycle_status = ?"
            params.append(status)
        
        query += " ORDER BY pe.created_at DESC LIMIT ?"
        params.append(min(limit, 200))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            if event.get("clearing_context_tags"):
                try:
                    event["clearing_context_tags"] = json.loads(event["clearing_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    pass
            if event.get("rules_applied"):
                try:
                    event["rules_applied"] = json.loads(event["rules_applied"])
                except (json.JSONDecodeError, TypeError):
                    pass
            events.append(event)
        
        return {
            "total": len(events),
            "days": days,
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/analytics/rules/rebuild")
async def rebuild_rules():
    """Примусовий перерахунок правил самонавчання на основі paired_events."""
    import core.globals
    telegram_monitor = core.globals.telegram_monitor
    
    try:
        # Try through active telegram_monitor if running
        if telegram_monitor and hasattr(telegram_monitor, 'analyzer') and telegram_monitor.analyzer:
            count = await asyncio.to_thread(telegram_monitor.analyzer.run_rules_learner)
            return {"status": "ok", "rules_updated": count}
        
        # Fallback: create analyzer on the fly
        from analyzer.gemini_analyzer import GeminiThreatAnalyzer
        analyzer = GeminiThreatAnalyzer(error_callback=log_error_to_db, rule_audit_callback=log_rule_audit_to_db)
        count = await asyncio.to_thread(analyzer.run_rules_learner)
        return {"status": "ok", "rules_updated": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/history/{region}")
async def get_region_history(region: str, limit: int = 200, date: str = None):
    """Повертає хронологію загроз для конкретної області з Firebase Firestore.
    
    Args:
        region: Назва області
        limit: Максимальна кількість подій (default 200)
        date: Дата у форматі YYYY-MM-DD. Якщо не вказано, повертає за сьогодні.
    """
    from urllib.parse import unquote
    from datetime import datetime as dt, timedelta
    region = unquote(region)
    
    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firebase Firestore недоступний")
    
    # Determine date range in Europe/Kiev timezone, then convert to UTC for Firestore query comparison
    try:
        import zoneinfo
    except ImportError:
        from backports import zoneinfo
    
    kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
    
    if date:
        try:
            # Parse target date as local date (midnight start) in Kiev timezone
            parsed_date = dt.strptime(date, "%Y-%m-%d")
            local_start = parsed_date.replace(tzinfo=kyiv_tz)
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірний формат дати. Використовуйте YYYY-MM-DD")
    else:
        # If no date provided, get current time in Kiev timezone
        current_local = dt.now(kyiv_tz)
        local_start = current_local.replace(hour=0, minute=0, second=0, microsecond=0)
    
    local_end = local_start + timedelta(days=1)
    
    # Convert local start and end of the day in Kiev to UTC
    utc_start = local_start.astimezone(timezone.utc)
    utc_end = local_end.astimezone(timezone.utc)
    
    date_start = utc_start.strftime("%Y-%m-%d %H:%M:%S")
    date_end = utc_end.strftime("%Y-%m-%d %H:%M:%S")
        
    try:
        # Fetch by region only (avoids composite index requirement), then filter by date in Python
        docs = await asyncio.to_thread(
            lambda: db.collection('sirenua_history')
                      .where('region', '==', region)
                      .get()
        )
        
        events = []
        for doc in docs:
            d = doc.to_dict()
            ts = d.get('timestamp', '')
            # Filter by date range in Python
            if date_start <= ts < date_end:
                events.append(d)
        
        # Sort by timestamp descending
        events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Limit results
        events = events[:min(limit, 200)]
        
        return {
            "region": region,
            "date": local_start.strftime("%Y-%m-%d"),
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
