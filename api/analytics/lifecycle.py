"""
Analytics Lifecycle & Telemetry API.
Endpoints: per-region telemetry, attack groups, lifecycle data, paired events.
"""

import json
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH
from database.db_helpers import execute_query_as_dicts
from database.query_builder import build_and_execute_query

router = APIRouter()


@router.get("/api/analytics/telemetry/{region}")
async def get_region_telemetry(region: str, limit: int = 50, days: int = 30):
    """Повна телеметрія для регіону з групуванням."""
    from urllib.parse import unquote
    region = unquote(region)

    base_query = '''
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
    '''
    events = build_and_execute_query(
        base_query=base_query,
        date_column="th.timestamp",
        days=days,
        filters={"th.region": region},
        order_by="th.timestamp DESC",
        limit=limit,
        json_fields=["message_context_tags"]
    )
    return {"region": region, "count": len(events), "events": events}


@router.get("/api/analytics/groups")
async def get_attack_groups(days: int = 7, limit: int = 50):
    """Список атакових хвиль/груп за останні N днів."""
    try:
        query = '''
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
        '''
        rows = execute_query_as_dicts(query, (f'-{days} days', min(limit, 100)))

        groups = []
        for group in rows:
            group["regions"] = group["regions"].split(",") if group["regions"] else []
            group["threat_types"] = group["threat_types"].split(",") if group["threat_types"] else []
            if group["avg_confidence"]:
                group["avg_confidence"] = round(group["avg_confidence"], 1)
            if group["avg_speed"]:
                group["avg_speed"] = round(group["avg_speed"], 1)
            groups.append(group)

        return {"days": days, "total_groups": len(groups), "groups": groups}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@router.get("/api/analytics/lifecycle/{region}")
async def get_lifecycle_data(region: str, days: int = 30, limit: int = 50):
    """Повний lifecycle загроз для регіону: встановлення → зняття з телеметрією обох подій."""
    from urllib.parse import unquote
    region = unquote(region)

    base_query = '''
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
    '''
    events = build_and_execute_query(
        base_query=base_query,
        date_column="tc.timestamp",
        days=days,
        filters={"tc.region": region},
        order_by="tc.timestamp DESC",
        limit=limit,
        json_fields=["clearing_context_tags"]
    )
    return {"region": region, "count": len(events), "lifecycle_events": events}


@router.get("/api/analytics/paired-events")
async def get_paired_events(region: str = None, status: str = None, days: int = 7, limit: int = 50):
    """Спарені події (lifecycle): загроза → телеметрія → clearing."""
    base_query = """
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
    """
    filters = {}
    if region:
        from urllib.parse import unquote
        filters["pe.region"] = unquote(region)
    if status:
        filters["pe.lifecycle_status"] = status

    events = build_and_execute_query(
        base_query=base_query,
        date_column="pe.created_at",
        days=days,
        filters=filters,
        order_by="pe.created_at DESC",
        limit=limit,
        json_fields=["clearing_context_tags", "rules_applied"]
    )
    return {"total": len(events), "days": days, "events": events}
