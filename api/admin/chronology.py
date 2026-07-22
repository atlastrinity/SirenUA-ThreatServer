"""
Admin Chronology API.
Endpoints for threat chronology (v1 and v2 with AI correlation).
"""

from datetime import datetime as dt_cls
from typing import Tuple
from urllib.parse import unquote
from fastapi import APIRouter, HTTPException

from core.config import get_kyiv_tz_offset
from database.db_helpers import execute_query_as_dicts

router = APIRouter()


def _apply_prediction_accuracy_filter(query: str, prediction_accuracy: str) -> str:
    """Appends a SQL WHERE clause for prediction_accuracy filter."""
    if prediction_accuracy == "match":
        return query + " AND pe.prediction_accuracy = 'confirmed'"
    elif prediction_accuracy == "mismatch":
        return query + " AND pe.prediction_accuracy = 'overestimated'"
    elif prediction_accuracy == "mitigated":
        return query + " AND pe.prediction_accuracy = 'mitigated'"
    elif prediction_accuracy == "active":
        return query + " AND (pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL))"
    elif prediction_accuracy == "cleared":
        return query + " AND (pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL))"
    return query


@router.get("/api/admin/chronology")
async def get_admin_chronology(
    region: str = None,
    days: int = 7,
    threat_type: str = None,
    was_predictive: int = None,
    prediction_accuracy: str = None
):
    """Хронологія загроз: встановлення → зняття, з match_type."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        day_filter = f'-{days} days'

        query = '''
            SELECT th.id, th.region, th.threat_level, th.threat_type,
                   th.timestamp as threat_timestamp,
                   th.detail as threat_detail,
                   pe.confidence_at_set, pe.confidence_at_clear,
                   pe.was_predictive, pe.prediction_accuracy,
                   pe.lifecycle_status, pe.duration_seconds,
                   pe.gemini_group_id,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE th.timestamp >= datetime('now', ?) AND pe.threat_type != 'official_alarm'
        '''
        params = [day_filter]

        decoded_region = None
        if region:
            decoded_region = unquote(region)
            query += " AND th.region = ?"
            params.append(decoded_region)
        if threat_type:
            query += " AND th.threat_type = ?"
            params.append(threat_type)
        if was_predictive is not None:
            query += " AND pe.was_predictive = ?"
            params.append(was_predictive)
        if prediction_accuracy:
            query = _apply_prediction_accuracy_filter(query, prediction_accuracy)

        query += " ORDER BY th.timestamp DESC LIMIT 500"
        rows = execute_query_as_dicts(query, params)

        # Daily aggregation
        daily_agg_query = f'''
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.lifecycle_status = 'active' THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE th.timestamp >= datetime('now', ?) AND pe.threat_type != 'official_alarm'
        '''
        agg_params = [day_filter]
        if decoded_region:
            daily_agg_query += " AND th.region = ?"
            agg_params.append(decoded_region)
        if threat_type:
            daily_agg_query += " AND th.threat_type = ?"
            agg_params.append(threat_type)
        if was_predictive is not None:
            daily_agg_query += " AND pe.was_predictive = ?"
            agg_params.append(was_predictive)
        if prediction_accuracy:
            daily_agg_query = _apply_prediction_accuracy_filter(daily_agg_query, prediction_accuracy)

        daily_agg_query += " GROUP BY day ORDER BY day"
        daily_stats = execute_query_as_dicts(daily_agg_query, agg_params)

        events = []
        for row in rows:
            event = dict(row)
            if event.get("threat_type") == "official_alarm":
                event["match_type"] = "cleared" if event.get("clearing_timestamp") else "official"
            elif event.get("prediction_accuracy") == "confirmed":
                event["match_type"] = "confirmed"
            elif event.get("prediction_accuracy") == "mitigated":
                event["match_type"] = "mitigated"
            elif event.get("prediction_accuracy") == "overestimated":
                event["match_type"] = "overestimated"
            elif event.get("lifecycle_status") == "active":
                event["match_type"] = "active"
            else:
                event["match_type"] = "cleared"
            events.append(event)

        return {"total": len(events), "days": days, "events": events, "daily_stats": daily_stats}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


def _build_alarm_lookup(alarm_rows: list) -> dict:
    """Helper to build alarm lookup: region -> [(epoch, ts)]"""
    alarm_by_region = {}
    for ar in alarm_rows:
        r = ar["region"]
        if r not in alarm_by_region:
            alarm_by_region[r] = []
        ts_str = ar["timestamp"]
        try:
            ts_epoch = dt_cls.fromisoformat(ts_str.replace('Z', '+00:00') if ts_str else "").timestamp()
        except Exception:
            try:
                ts_epoch = dt_cls.strptime(ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
            except Exception:
                continue
        alarm_by_region[r].append({"epoch": ts_epoch, "ts": ts_str})
    return alarm_by_region


def _correlate_single_event(ev: dict, alarm_by_region: dict) -> dict:
    """Correlates a single AI threat event with nearest official alarm and formats results."""
    ai_ts_str = ev.get("ai_timestamp", "")
    try:
        ai_epoch = dt_cls.fromisoformat(ai_ts_str.replace('Z', '+00:00') if ai_ts_str else "").timestamp()
    except Exception:
        try:
            ai_epoch = dt_cls.strptime(ai_ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
        except Exception:
            ai_epoch = None

    # Find nearest alarm within ±30min window
    best_alarm = None
    best_delta = None
    region_alarms = alarm_by_region.get(ev["region"], [])
    if ai_epoch:
        for alarm in region_alarms:
            delta = alarm["epoch"] - ai_epoch  # positive = AI was first
            if abs(delta) <= 1800:  # 30 min window
                if best_delta is None or abs(delta) < abs(best_delta):
                    best_delta = delta
                    best_alarm = alarm

    ev["alarm_timestamp"] = best_alarm["ts"] if best_alarm else None
    ev["time_delta_seconds"] = round(best_delta) if best_delta is not None else None

    # Determine match_type and match_reason
    pred_acc = ev.get("prediction_accuracy")
    lifecycle = ev.get("lifecycle_status")

    if pred_acc == "confirmed" or (best_alarm and best_delta is not None and abs(best_delta) <= 1800):
        ev["match_type"] = "confirmed"
        if best_delta is not None:
            if best_delta > 0:
                mins = round(best_delta / 60)
                ev["match_reason"] = f"AI визначив загрозу за {mins} хв до офіційної тривоги"
            elif best_delta < 0:
                mins = round(abs(best_delta) / 60)
                ev["match_reason"] = f"Офіційна тривога була за {mins} хв до AI-детекції"
            else:
                ev["match_reason"] = "AI та офіційна тривога одночасно"
        else:
            ev["match_reason"] = "Підтверджено через lifecycle"
    elif pred_acc == "mitigated":
        ev["match_type"] = "mitigated"
        ev["match_reason"] = "Загрозу нейтралізовано (ППО/РЕБ)"
    elif pred_acc == "overestimated":
        ev["match_type"] = "overestimated"
        ev["match_reason"] = "Тривога не підтверджена — AI переоцінив загрозу"
    elif lifecycle == "active":
        ev["match_type"] = "active"
        ev["match_reason"] = "Загроза ще активна, очікуємо результат"
    else:
        ev["match_type"] = "cleared"
        ev["match_reason"] = "Знято без кореляції з офіційною тривогою"

    # Telemetry summary
    telem_parts = []
    if ev.get("attack_vector") and ev["attack_vector"] != "unknown":
        telem_parts.append(ev["attack_vector"])
    if ev.get("weapon_subtype"):
        telem_parts.append(ev["weapon_subtype"])
    if ev.get("target_count") and ev["target_count"] > 0:
        telem_parts.append(f"{ev['target_count']} цілей")
    if ev.get("speed_kmh") and ev["speed_kmh"] > 0:
        telem_parts.append(f"{ev['speed_kmh']} км/г")
    if ev.get("launch_origin"):
        telem_parts.append(f"з {ev['launch_origin']}")
    ev["telemetry_summary"] = " | ".join(telem_parts) if telem_parts else None

    return ev


def _build_chronology_stats_and_buckets(correlated_events: list, limit: int) -> Tuple[dict, list, dict]:
    """Helper to aggregate stats and compute delta distribution."""
    stats = {
        "confirmed": sum(1 for e in correlated_events if e["match_type"] == "confirmed"),
        "mitigated": sum(1 for e in correlated_events if e["match_type"] == "mitigated"),
        "overestimated": sum(1 for e in correlated_events if e["match_type"] == "overestimated"),
        "active": sum(1 for e in correlated_events if e["match_type"] == "active"),
        "cleared": sum(1 for e in correlated_events if e["match_type"] == "cleared"),
    }

    # Slice to requested limit
    sliced_events = correlated_events[:limit]

    # Time delta distribution (for histogram)
    deltas = [e["time_delta_seconds"] for e in sliced_events if e["time_delta_seconds"] is not None]
    delta_buckets = {}
    for d in deltas:
        bucket = (d // 60) * 60
        bucket_label = f"{int(bucket // 60)} хв"
        delta_buckets[bucket_label] = delta_buckets.get(bucket_label, 0) + 1

    return stats, sliced_events, delta_buckets


@router.get("/api/admin/chronology/v2")
async def get_admin_chronology_v2(
    region: str = None,
    date_from: str = None,
    date_to: str = None,
    days: int = 7,
    threat_type: str = None,
    match_result: str = None,
    confidence_min: int = None,
    confidence_max: int = None,
    limit: int = 300
):
    """Хронологія з кореляцією AI-детекцій та офіційних тривог.

    Для кожної AI-події шукає найближчу офіційну тривогу в ±30хв вікні
    та обчислює time_delta, match_reason, та включає telemetry summary.
    """
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        # Date filter
        if date_from and date_to:
            date_clause = "AND th_ai.timestamp BETWEEN ? AND ?"
            date_params = [date_from, date_to + " 23:59:59"]
        else:
            date_clause = "AND th_ai.timestamp >= datetime('now', ?)"
            date_params = [f'-{days} days']

        # Build WHERE conditions
        where_extra = ""
        extra_params = []
        decoded_region = None
        if region:
            decoded_region = unquote(region)
            where_extra += " AND pe.region = ?"
            extra_params.append(decoded_region)
        if threat_type:
            where_extra += " AND pe.threat_type = ?"
            extra_params.append(threat_type)
        if confidence_min is not None:
            where_extra += " AND pe.confidence_at_set >= ?"
            extra_params.append(confidence_min)
        if confidence_max is not None:
            where_extra += " AND pe.confidence_at_set <= ?"
            extra_params.append(confidence_max)

        match_filter = match_result

        # Main query: AI threat events with telemetry
        query = f"""
            SELECT pe.id, pe.region, pe.threat_level, pe.threat_type,
                   pe.confidence_at_set, pe.confidence_at_clear,
                   pe.was_predictive, pe.prediction_accuracy,
                   pe.lifecycle_status, pe.duration_seconds,
                   pe.gemini_group_id,
                   th_ai.timestamp as ai_timestamp,
                   th_ai.detail as threat_detail,
                   td.attack_vector, td.target_count, td.speed_kmh,
                   td.weapon_subtype, td.launch_origin, td.altitude_category,
                   td.distance_to_target_km, td.event_phase,
                   td.source_reliability, td.civilian_risk_level,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            LEFT JOIN telemetry_data td ON td.threat_event_id = th_ai.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause}
            {where_extra}
            ORDER BY th_ai.timestamp DESC
        """
        params = date_params + extra_params
        ai_events = execute_query_as_dicts(query, params)

        # Get all official alarm timestamps for correlation
        alarm_query = f"""
            SELECT region, timestamp, threat_level, id
            FROM threat_history
            WHERE threat_type = 'official_alarm'
            AND threat_level = 'high'
            {date_clause.replace('th_ai.timestamp', 'timestamp')}
            ORDER BY timestamp
        """
        alarm_rows = execute_query_as_dicts(alarm_query, date_params)

        # Build alarm lookup: region -> [(timestamp_epoch, ts_str)]
        alarm_by_region = _build_alarm_lookup(alarm_rows)

        # Correlate each AI event with nearest official alarm
        correlated_events = []
        for ev in ai_events:
            corr_ev = _correlate_single_event(ev, alarm_by_region)
            correlated_events.append(corr_ev)

        # Aggregate stats (unfiltered for period)
        total_period = len(correlated_events)
        stats, sliced_events, delta_buckets = _build_chronology_stats_and_buckets(correlated_events, limit)

        # Apply match_filter
        if match_filter:
            if match_filter == "match":
                correlated_events = [e for e in correlated_events if e["match_type"] == "confirmed"]
            elif match_filter == "mitigated":
                correlated_events = [e for e in correlated_events if e["match_type"] == "mitigated"]
            elif match_filter == "mismatch":
                correlated_events = [e for e in correlated_events if e["match_type"] == "overestimated"]
            elif match_filter == "active":
                correlated_events = [e for e in correlated_events if e["match_type"] == "active"]

        # Daily aggregation for charts
        daily_agg_query = f"""
            SELECT date(datetime(th_ai.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause}
            {where_extra}
            GROUP BY day ORDER BY day
        """
        agg_params = date_params + extra_params
        daily_stats = execute_query_as_dicts(daily_agg_query, agg_params)

        # Threat type breakdown for charts
        type_breakdown_query = f"""
            SELECT pe.threat_type, pe.prediction_accuracy, COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause}
            {where_extra}
            GROUP BY pe.threat_type, pe.prediction_accuracy
        """
        type_breakdown = execute_query_as_dicts(type_breakdown_query, date_params + extra_params)

        return {
            "total": total_period,
            "stats": stats,
            "events": sliced_events,
            "daily_stats": daily_stats,
            "delta_distribution": delta_buckets,
            "type_breakdown": type_breakdown
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
