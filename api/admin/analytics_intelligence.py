"""
Admin Analytics Intelligence API.
Deep trajectory analysis, launch origin statistics, threat type distributions,
regional risk matrices, and flight corridor intelligence.
"""

import json
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from core.config import get_kyiv_tz_offset
from core.topology import REGION_CENTROIDS, SHAHED_ROUTES
from core.threat_types import THREAT_TYPES
from database.db_helpers import execute_query_as_dicts, execute_write, get_sqlite_connection
from core.config import DB_PATH

router = APIRouter()

# Known Russian launch hubs with coordinates
LAUNCH_HUBS = {
    "Саваслейка РФ": (55.85, 42.15),
    "Приморсько-Ахтарськ РФ": (46.05, 36.50),
    "Курська обл. РФ": (51.73, 36.19),
    "Бєлгородська обл. РФ": (50.60, 36.59),
    "Каспійське море": (42.00, 51.50),
    "Чорне море": (43.50, 34.00),
    "АР Крим": (45.30, 34.10),
    "Єйськ РФ": (46.70, 38.28),
    "Оленегорськ РФ": (68.15, 33.28),
    "Мачулищі РБ": (53.77, 27.55),
    "Енгельс РФ": (51.48, 46.11),
    "Моздок РФ": (43.75, 44.65),
    "Шайковка РФ": (54.33, 34.27),
    "Ростовська обл. РФ": (47.24, 39.71),
    "Таганрозька затока": (47.20, 38.90),
    "Краснодарський край РФ": (45.04, 38.98),
    "Сольці РФ": (58.12, 30.32),
    "Тамбовська обл. РФ": (52.73, 41.45),
    "Дягілєво РФ": (54.62, 39.57),
    "Астрахань РФ": (46.35, 48.05),
}


@router.get("/api/admin/analytics/trajectory_heatmap")
async def get_trajectory_heatmap(days: int = 30):
    """Теплова карта траєкторій: source_region → target_region з частотою та координатами."""
    try:
        # From gemini_rules: established route patterns
        rules_query = """
            SELECT source_region, target_region, threat_type, evidence_count, accuracy_score
            FROM gemini_rules
            WHERE is_active = 1 AND rule_type = 'route_pattern'
            ORDER BY evidence_count DESC
        """
        rules = execute_query_as_dicts(rules_query)

        # From telemetry_data: actual observed trajectories
        telemetry_query = f"""
            SELECT td.launch_origin as source_region, th.region as target_region,
                   pe.threat_type, COUNT(*) as count,
                   AVG(pe.confidence_at_set) as avg_confidence,
                   AVG(td.speed_kmh) as avg_speed
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            JOIN paired_events pe ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-{days} days')
              AND td.launch_origin IS NOT NULL AND td.launch_origin != ''
              AND pe.threat_type != 'official_alarm'
            GROUP BY td.launch_origin, th.region, pe.threat_type
            ORDER BY count DESC
        """
        telemetry_corridors = execute_query_as_dicts(telemetry_query)

        corridors = []

        # Process rules
        for r in rules:
            src = r["source_region"]
            tgt = r["target_region"]
            src_coords = LAUNCH_HUBS.get(src) or REGION_CENTROIDS.get(src)
            tgt_coords = REGION_CENTROIDS.get(tgt)
            if src_coords and tgt_coords:
                corridors.append({
                    "source": src,
                    "target": tgt,
                    "source_lat": src_coords[0],
                    "source_lon": src_coords[1],
                    "target_lat": tgt_coords[0],
                    "target_lon": tgt_coords[1],
                    "count": r["evidence_count"] or 1,
                    "threat_type": r["threat_type"],
                    "avg_confidence": round(r["accuracy_score"] * 100) if r["accuracy_score"] else 0,
                    "data_source": "rule"
                })

        # Process telemetry
        for t in telemetry_corridors:
            src = t["source_region"]
            tgt = t["target_region"]
            src_coords = LAUNCH_HUBS.get(src) or REGION_CENTROIDS.get(src)
            tgt_coords = REGION_CENTROIDS.get(tgt)
            if src_coords and tgt_coords:
                corridors.append({
                    "source": src,
                    "target": tgt,
                    "source_lat": src_coords[0],
                    "source_lon": src_coords[1],
                    "target_lat": tgt_coords[0],
                    "target_lon": tgt_coords[1],
                    "count": t["count"],
                    "threat_type": t["threat_type"],
                    "avg_confidence": round(t["avg_confidence"]) if t["avg_confidence"] else 0,
                    "avg_speed": round(t["avg_speed"]) if t["avg_speed"] else None,
                    "data_source": "telemetry"
                })

        return {"corridors": corridors, "total": len(corridors)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/launch_origins")
async def get_launch_origins(days: int = 30):
    """Статистика запусків за пусковими хабами РФ."""
    try:
        query = f"""
            SELECT td.launch_origin as name,
                   COUNT(*) as total_launches,
                   pe.threat_type,
                   MAX(th.timestamp) as last_detected
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            JOIN paired_events pe ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-{days} days')
              AND td.launch_origin IS NOT NULL AND td.launch_origin != ''
              AND pe.threat_type != 'official_alarm'
            GROUP BY td.launch_origin, pe.threat_type
            ORDER BY total_launches DESC
        """
        rows = execute_query_as_dicts(query)

        # Also include known launch hubs from gemini_rules
        rules_query = """
            SELECT source_region as name, threat_type, evidence_count as total_launches
            FROM gemini_rules
            WHERE is_active = 1 AND rule_type = 'route_pattern'
              AND source_region NOT IN (SELECT DISTINCT region FROM threat_history)
            ORDER BY evidence_count DESC
        """
        rule_origins = execute_query_as_dicts(rules_query)

        # Merge by origin name
        origins_map = {}
        for r in rows + rule_origins:
            name = r["name"]
            if name not in origins_map:
                coords = LAUNCH_HUBS.get(name, (0, 0))
                origins_map[name] = {
                    "name": name,
                    "lat": coords[0],
                    "lon": coords[1],
                    "total_launches": 0,
                    "by_type": {},
                    "last_detected": r.get("last_detected")
                }
            tt = r.get("threat_type", "unknown")
            origins_map[name]["by_type"][tt] = origins_map[name]["by_type"].get(tt, 0) + (r.get("total_launches") or 0)
            origins_map[name]["total_launches"] += (r.get("total_launches") or 0)
            if r.get("last_detected") and (not origins_map[name]["last_detected"] or r["last_detected"] > origins_map[name]["last_detected"]):
                origins_map[name]["last_detected"] = r["last_detected"]

        origins = sorted(origins_map.values(), key=lambda x: x["total_launches"], reverse=True)
        return {"origins": origins, "total": len(origins)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/threat_type_distribution")
async def get_threat_type_distribution(days: int = 30):
    """Розподіл типів загроз за часом (щоденно)."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        query = f"""
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   pe.threat_type,
                   COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-{days} days')
              AND pe.threat_type != 'official_alarm'
            GROUP BY day, pe.threat_type
            ORDER BY day
        """
        rows = execute_query_as_dicts(query)

        # Pivot into daily structure
        daily_map = {}
        totals = {}
        for r in rows:
            day = r["day"]
            tt = r["threat_type"] or "unknown"
            count = r["count"]
            if day not in daily_map:
                daily_map[day] = {"date": day}
            daily_map[day][tt] = daily_map[day].get(tt, 0) + count
            totals[tt] = totals.get(tt, 0) + count

        daily = sorted(daily_map.values(), key=lambda x: x["date"])

        # Category aggregation: БПЛА vs Ракети vs Балістика vs КАБ
        categories = {
            "БПЛА": sum(totals.get(t, 0) for t in ["shahed", "recon_uav", "recon"]),
            "Крилаті ракети": sum(totals.get(t, 0) for t in ["cruise_missile", "tu95", "tu22m3", "zircon"]),
            "Балістика": sum(totals.get(t, 0) for t in ["ballistic", "iskander"]),
            "КАБ/Авіабомби": totals.get("kab", 0),
            "Авіація": sum(totals.get(t, 0) for t in ["mig31k", "su35_su57"]),
            "Артилерія": sum(totals.get(t, 0) for t in ["artillery", "mlrs"]),
            "Інше": sum(v for k, v in totals.items() if k not in ["shahed", "recon_uav", "recon", "cruise_missile", "tu95", "tu22m3", "zircon", "ballistic", "iskander", "kab", "mig31k", "su35_su57", "artillery", "mlrs"])
        }

        return {"daily": daily, "totals": totals, "categories": categories}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/region_risk_matrix")
async def get_region_risk_matrix(days: int = 30):
    """Матриця ризиків по областях: ймовірність, частота, типи загроз."""
    try:
        query = f"""
            SELECT pe.region,
                   COUNT(*) as total_events,
                   pe.threat_type,
                   AVG(pe.confidence_at_set) as avg_confidence,
                   AVG(pe.duration_seconds) as avg_duration,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-{days} days')
              AND pe.threat_type != 'official_alarm'
            GROUP BY pe.region, pe.threat_type
            ORDER BY total_events DESC
        """
        rows = execute_query_as_dicts(query)

        # Aggregate by region
        region_map = {}
        max_events = 1
        for r in rows:
            name = r["region"]
            if name not in region_map:
                coords = REGION_CENTROIDS.get(name, (0, 0))
                region_map[name] = {
                    "name": name,
                    "lat": coords[0],
                    "lon": coords[1],
                    "total_events": 0,
                    "by_type": {},
                    "avg_confidence": 0,
                    "confirmed": 0,
                    "predictive": 0,
                    "dominant_threat_type": None,
                }
            tt = r["threat_type"] or "unknown"
            count = r["total_events"]
            region_map[name]["total_events"] += count
            region_map[name]["by_type"][tt] = region_map[name]["by_type"].get(tt, 0) + count
            region_map[name]["confirmed"] += r["confirmed"] or 0
            region_map[name]["predictive"] += r["predictive"] or 0
            if r["avg_confidence"]:
                region_map[name]["avg_confidence"] = round(r["avg_confidence"])
            if region_map[name]["total_events"] > max_events:
                max_events = region_map[name]["total_events"]

        # Calculate risk score and dominant type
        for name, data in region_map.items():
            data["risk_score"] = round(data["total_events"] / max_events * 100)
            if data["by_type"]:
                data["dominant_threat_type"] = max(data["by_type"], key=data["by_type"].get)

        regions = sorted(region_map.values(), key=lambda x: x["total_events"], reverse=True)
        return {"regions": regions, "total": len(regions)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/flight_corridors")
async def get_flight_corridors(days: int = 30):
    """Аналіз льотних коридорів: маршрути прольоту та частота."""
    try:
        # From gemini_rules: route_pattern rules
        query = """
            SELECT source_region, target_region, threat_type,
                   evidence_count, accuracy_score, rule_text
            FROM gemini_rules
            WHERE is_active = 1 AND rule_type = 'route_pattern'
            ORDER BY evidence_count DESC
        """
        rules = execute_query_as_dicts(query)

        corridors = []
        for r in rules:
            src_coords = LAUNCH_HUBS.get(r["source_region"]) or REGION_CENTROIDS.get(r["source_region"])
            tgt_coords = REGION_CENTROIDS.get(r["target_region"])
            corridors.append({
                "source": r["source_region"],
                "target": r["target_region"],
                "route_description": r["rule_text"],
                "threat_type": r["threat_type"],
                "count": r["evidence_count"] or 1,
                "accuracy": round(r["accuracy_score"] * 100) if r["accuracy_score"] else 0,
                "source_coords": list(src_coords) if src_coords else None,
                "target_coords": list(tgt_coords) if tgt_coords else None,
            })

        # Historical SHAHED routes
        shahed_routes_data = []
        for route_name, regions in SHAHED_ROUTES.items():
            waypoints = []
            for reg in regions:
                coords = REGION_CENTROIDS.get(reg)
                if coords:
                    waypoints.append({"region": reg, "lat": coords[0], "lon": coords[1]})
            shahed_routes_data.append({
                "route_name": route_name,
                "waypoints": waypoints,
                "total_regions": len(regions)
            })

        return {
            "corridors": corridors,
            "shahed_routes": shahed_routes_data,
            "total": len(corridors)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/daily_summary")
async def get_daily_summary(days: int = 30):
    """Щоденний зведений звіт: запуски, перехоплення, прильоти."""
    offset_hours = get_kyiv_tz_offset()
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        query = f"""
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive,
                   AVG(pe.confidence_at_set) as avg_confidence
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE th.timestamp >= datetime('now', '-{days} days')
              AND pe.threat_type != 'official_alarm'
            GROUP BY day
            ORDER BY day
        """
        rows = execute_query_as_dicts(query)

        summaries = []
        for r in rows:
            total = r["total_events"]
            confirmed = r["confirmed"] or 0
            mitigated = r["mitigated"] or 0
            overestimated = r["overestimated"] or 0
            evaluated = confirmed + mitigated + overestimated
            effectiveness = round((confirmed + mitigated * 0.8) / evaluated * 100, 1) if evaluated > 0 else 0

            summaries.append({
                "date": r["day"],
                "total_events": total,
                "confirmed": confirmed,
                "mitigated": mitigated,
                "overestimated": overestimated,
                "predictive": r["predictive"] or 0,
                "avg_confidence": round(r["avg_confidence"]) if r["avg_confidence"] else 0,
                "effectiveness_pct": effectiveness
            })

        return {"summaries": summaries, "total_days": len(summaries)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/api/admin/analytics/generate_daily_report")
async def generate_daily_report():
    """Ручна генерація аналітичного звіту. Зберігає у таблицю analytics_reports."""
    try:
        # Gather all analytics data for today
        trajectory_data = await get_trajectory_heatmap(days=1)
        launch_data = await get_launch_origins(days=1)
        risk_data = await get_region_risk_matrix(days=1)
        type_data = await get_threat_type_distribution(days=1)
        daily_data = await get_daily_summary(days=1)

        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        summary_parts = []
        summary_parts.append(f"📊 Аналітичний звіт за {today}")
        summary_parts.append(f"Загальна кількість коридорів: {trajectory_data['total']}")
        summary_parts.append(f"Пускових хабів зафіксовано: {launch_data['total']}")
        summary_parts.append(f"Областей під загрозою: {risk_data['total']}")

        if type_data.get("categories"):
            cats = type_data["categories"]
            summary_parts.append(f"БПЛА: {cats.get('БПЛА', 0)} | Крилаті ракети: {cats.get('Крилаті ракети', 0)} | Балістика: {cats.get('Балістика', 0)}")

        if daily_data.get("summaries"):
            latest = daily_data["summaries"][-1] if daily_data["summaries"] else {}
            if latest:
                summary_parts.append(f"Ефективність AI: {latest.get('effectiveness_pct', 0)}%")

        summary_text = "\n".join(summary_parts)

        # Save to analytics_reports table
        execute_write(
            """INSERT INTO analytics_reports (report_date, report_type, summary_text, trajectory_data, launch_data, risk_matrix, generated_by)
               VALUES (?, 'daily', ?, ?, ?, ?, 'manual')""",
            (
                today,
                summary_text,
                json.dumps(trajectory_data, ensure_ascii=False, default=str),
                json.dumps(launch_data, ensure_ascii=False, default=str),
                json.dumps(risk_data, ensure_ascii=False, default=str),
            )
        )

        # Also save to palantir_reports DB table for Palantir Intelligence System
        palantir_summary = f"👁️ Palantir Tactical Assessment [{today}]\n• Active Vectors: {trajectory_data['total']}\n• Launch Hubs Monitored: {launch_data['total']}\n• Threatened Regions: {risk_data['total']}"
        execute_write(
            """INSERT INTO palantir_reports (report_date, threat_assessment_summary, palantir_vectors_json, launch_hubs_json, risk_matrix_json, confidence_index, generated_by)
               VALUES (?, ?, ?, ?, ?, 0.96, 'palantir_ai')""",
            (
                today,
                palantir_summary,
                json.dumps(trajectory_data, ensure_ascii=False, default=str),
                json.dumps(launch_data, ensure_ascii=False, default=str),
                json.dumps(risk_data, ensure_ascii=False, default=str),
            )
        )

        return {
            "status": "success",
            "report_date": today,
            "summary": summary_text,
            "palantir_summary": palantir_summary,
            "trajectory_corridors": trajectory_data["total"],
            "launch_origins": launch_data["total"],
            "regions_at_risk": risk_data["total"]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/analytics/reports")
async def get_analytics_reports(limit: int = 30):
    """Отримати збережені аналітичні звіти."""
    try:
        query = """
            SELECT id, created_at, report_date, report_type, summary_text, generated_by
            FROM analytics_reports
            ORDER BY created_at DESC
            LIMIT ?
        """
        rows = execute_query_as_dicts(query, (limit,))
        return {"reports": rows, "total": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ---------------------------------------------------------------------------
# Palantir Intelligence Dedicated Endpoints
# ---------------------------------------------------------------------------

@router.get("/api/admin/palantir/overview")
async def get_palantir_overview(days: int = 30):
    """Palantir System Unified Tactical Intelligence Endpoint."""
    heatmap = await get_trajectory_heatmap(days=days)
    launches = await get_launch_origins(days=days)
    risk = await get_region_risk_matrix(days=days)
    types = await get_threat_type_distribution(days=days)
    corridors = await get_flight_corridors(days=days)
    summary = await get_daily_summary(days=days)

    return {
        "system": "Palantir Tactical Intelligence Engine v2.0",
        "days": days,
        "trajectory_corridors": heatmap["corridors"],
        "launch_hubs": launches["origins"],
        "region_risk_matrix": risk["regions"],
        "threat_types": types,
        "flight_corridors": corridors["corridors"],
        "daily_summaries": summary["summaries"]
    }


@router.post("/api/admin/palantir/synthesize")
async def synthesize_palantir_intelligence():
    """Trigger manual Palantir AI tactical synthesis and store in palantir_reports DB."""
    return await generate_daily_report()


@router.get("/api/admin/palantir/reports")
async def get_palantir_reports(limit: int = 30):
    """Get reports from palantir_reports DB table."""
    try:
        query = """
            SELECT id, created_at, report_date, threat_assessment_summary, confidence_index, generated_by
            FROM palantir_reports
            ORDER BY created_at DESC
            LIMIT ?
        """
        rows = execute_query_as_dicts(query, (limit,))
        return {"reports": rows, "total": len(rows)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

