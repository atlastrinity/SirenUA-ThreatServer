"""
SirenUA Admin Panel API Router.
FastAPI routes for errors, dashboard aggregated stats, rules history, threat history seeding, and correlation.
"""

import sqlite3
import asyncio
from datetime import datetime, timezone
from fastapi import APIRouter, HTTPException

from core.config import DB_PATH
from database.db_helpers import get_db

router = APIRouter()

@router.post("/api/admin/seed_history")
async def seed_history():
    """Генерує початкову історію подій у Firestore для всіх областей."""
    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firebase Firestore недоступний")
        
    import random
    from datetime import datetime, timedelta, timezone
    
    regions = [
        "Вінницька область", "Волинська область", "Дніпропетровська область",
        "Донецька область", "Житомирська область", "Закарпатська область",
        "Запорізька область", "Івано-Франківська область", "Київська область",
        "Кіровоградська область", "Луганська область", "Львівська область",
        "Миколаївська область", "Одеська область", "Полтавська область",
        "Рівненська область", "Сумська область", "Тернопільська область",
        "Харківська область", "Херсонська область", "Хмельницька область",
        "Черкаська область", "Чернівецька область", "Чернігівська область",
        "м. Київ", "АР Крим"
    ]
    
    threat_templates = [
        {"threat_level": "high", "threat_type": "mig31k", "detail": "Зліт МіГ-31К з аеродрому Саваслейка. Ракетна небезпека!"},
        {"threat_level": "medium", "threat_type": "shahed", "detail": "Група ударних БпЛА типу 'Shahed' наближається з півдня."},
        {"threat_level": "high", "threat_type": "cruise_missile", "detail": "Запуск крилатих ракет Х-101/Х-555 з бортів Ту-95МС."},
        {"threat_level": "critical", "threat_type": "ballistic", "detail": "Загроза застосування балістичного озброєння з Криму!"},
    ]
    
    total_added = 0
    
    try:
        for region in regions:
            base_time = datetime.now(timezone.utc)
            
            for i in range(3):
                # 1. Початок тривоги
                alert_time = base_time - timedelta(days=i, hours=random.randint(2, 6))
                alert_timestamp = alert_time.strftime("%Y-%m-%d %H:%M:%S")
                
                # 2. Відбій тривоги
                clear_time = alert_time + timedelta(minutes=random.randint(45, 120))
                clear_timestamp = clear_time.strftime("%Y-%m-%d %H:%M:%S")
                
                alert_id = int(alert_time.timestamp() * 1000)
                clear_id = int(clear_time.timestamp() * 1000)
                
                is_tactical = random.choice([True, False])
                
                if is_tactical:
                    template = random.choice(threat_templates)
                    
                    alert_doc = {
                        "id": alert_id,
                        "region": region,
                        "timestamp": alert_timestamp,
                        "threat_level": template["threat_level"],
                        "threat_type": template["threat_type"],
                        "detail": template["detail"],
                        "confidence": random.randint(70, 95),
                        "telemetry": {
                            "source_reliability": "high",
                            "civilian_risk_level": "high" if template["threat_level"] == "high" else "moderate",
                            "message_context_tags": ["rocket", "alert"] if template["threat_type"] != "shahed" else ["shahed", "drone"]
                        }
                    }
                    
                    clear_doc = {
                        "id": clear_id,
                        "region": region,
                        "timestamp": clear_timestamp,
                        "threat_level": "none",
                        "threat_type": template["threat_type"],
                        "detail": "Відбій загрози",
                        "confidence": 100
                    }
                else:
                    alert_doc = {
                        "id": alert_id,
                        "region": region,
                        "timestamp": alert_timestamp,
                        "threat_level": "high",
                        "threat_type": "official_alarm",
                        "detail": "Повітряна тривога",
                        "confidence": 100
                    }
                    
                    clear_doc = {
                        "id": clear_id,
                        "region": region,
                        "timestamp": clear_timestamp,
                        "threat_level": "none",
                        "threat_type": "official_alarm",
                        "detail": "Відбій повітряної тривоги",
                        "confidence": 100
                    }
                
                db.collection('sirenua_history').add(alert_doc)
                db.collection('sirenua_history').add(clear_doc)
                total_added += 2
                
        return {"status": "success", "message": f"Додано {total_added} записів хронології у Firestore для всіх областей"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


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
    try:
        try:
            try:
                import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            except Exception:
                from backports import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
            from datetime import datetime
            dt = datetime.now(kiev_tz)
            offset_hours = int(dt.strftime('%z')[:3])
        except Exception:
            offset_hours = 3  # Fallback to Kyiv default (UTC+3)
            
        tz_modifier = f"'{offset_hours:+d} hours'"
        
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


@router.get("/api/admin/chronology")
async def get_admin_chronology(region: str = None, days: int = 7, threat_type: str = None, was_predictive: int = None, prediction_accuracy: str = None):
    """Хронологія загроз: встановлення → зняття, з match_type."""
    try:
        try:
            try:
                import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            except Exception:
                from backports import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
            from datetime import datetime
            dt = datetime.now(kiev_tz)
            offset_hours = int(dt.strftime('%z')[:3])
        except Exception:
            offset_hours = 3  # Fallback to Kyiv default (UTC+3)
            
        tz_modifier = f"'{offset_hours:+d} hours'"
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
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
            FROM threat_history th
            LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
            LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
            WHERE th.timestamp >= datetime('now', ?)
        '''
        params = [day_filter]
        
        if region:
            from urllib.parse import unquote
            query += " AND th.region = ?"
            params.append(unquote(region))
            
        if threat_type:
            query += " AND th.threat_type = ?"
            params.append(threat_type)
            
        if was_predictive is not None:
            query += " AND pe.was_predictive = ?"
            params.append(was_predictive)
            
        if prediction_accuracy:
            if prediction_accuracy == "match":
                query += " AND pe.prediction_accuracy = 'confirmed'"
            elif prediction_accuracy == "mismatch":
                query += " AND pe.prediction_accuracy = 'overestimated'"
            elif prediction_accuracy == "mitigated":
                query += " AND pe.prediction_accuracy = 'mitigated'"
            elif prediction_accuracy == "active":
                query += " AND (pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL))"
            elif prediction_accuracy == "cleared":
                query += " AND (pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL))"
        
        query += " ORDER BY th.timestamp DESC LIMIT 500"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Daily aggregation
        daily_agg_query = f'''
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   SUM(CASE WHEN th.threat_type != 'official_alarm' THEN 1 ELSE 0 END) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL) THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL) THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM threat_history th
            LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
            LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
            WHERE th.timestamp >= datetime('now', ?)
        '''
        agg_params = [day_filter]
        if region:
            daily_agg_query += " AND th.region = ?"
            agg_params.append(unquote(region))
            
        if threat_type:
            daily_agg_query += " AND th.threat_type = ?"
            agg_params.append(threat_type)
            
        if was_predictive is not None:
            daily_agg_query += " AND pe.was_predictive = ?"
            agg_params.append(was_predictive)
            
        if prediction_accuracy:
            if prediction_accuracy == "match":
                daily_agg_query += " AND pe.prediction_accuracy = 'confirmed'"
            elif prediction_accuracy == "mismatch":
                daily_agg_query += " AND pe.prediction_accuracy = 'overestimated'"
            elif prediction_accuracy == "mitigated":
                daily_agg_query += " AND pe.prediction_accuracy = 'mitigated'"
            elif prediction_accuracy == "active":
                daily_agg_query += " AND (pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL))"
            elif prediction_accuracy == "cleared":
                daily_agg_query += " AND (pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL))"
                
        daily_agg_query += " GROUP BY day ORDER BY day"
        
        cursor.execute(daily_agg_query, agg_params)
        daily_stats = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            # Determine match_type
            if event.get("threat_type") == "official_alarm":
                if event.get("clearing_timestamp"):
                    event["match_type"] = "cleared"
                else:
                    event["match_type"] = "official"
            elif event.get("prediction_accuracy") == "confirmed":
                event["match_type"] = "match"
            elif event.get("prediction_accuracy") == "mitigated":
                event["match_type"] = "mitigated"
            elif event.get("prediction_accuracy") == "overestimated":
                event["match_type"] = "mismatch"
            elif event.get("lifecycle_status") == "active":
                event["match_type"] = "active"
            else:
                event["match_type"] = "cleared"
            events.append(event)
        
        return {
            "total": len(events),
            "days": days,
            "events": events,
            "daily_stats": daily_stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/rules/history")
async def get_admin_rules_history(days: int = 30, limit: int = 200, rule_type: str = None, action: str = None, threat_type: str = None):
    """Аудит-лог змін правил Gemini."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM gemini_rules_audit WHERE timestamp >= datetime('now', ?)"
        params = [f'-{days} days']
        
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if action:
            query += " AND action = ?"
            params.append(action)
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "total": len(rows),
            "entries": [dict(r) for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/admin/dashboard/stats")
async def get_admin_dashboard_stats():
    """Агреговані статистичні дані для дашборду."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
    except Exception:
        offset_hours = 3
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total events (7d) excluding official alarms to match accuracy breakdown
        cursor.execute("SELECT COUNT(*) as c FROM paired_events WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'")
        total_7d = cursor.fetchone()["c"]

        # Accuracy breakdown (7d)
        cursor.execute("""
            SELECT
                SUM(CASE WHEN prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                SUM(CASE WHEN prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                SUM(CASE WHEN prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                SUM(CASE WHEN lifecycle_status = 'active' THEN 1 ELSE 0 END) as active,
                COUNT(*) as total
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
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
            WHERE pe.created_at >= datetime('now', '-7 days')
                AND pe.was_predictive = 1
                AND pe.threat_type != 'official_alarm'
        """)
        avg_row = cursor.fetchone()
        avg_early_seconds = round(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] else None

        # Threats by type (7d)
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
            GROUP BY threat_type ORDER BY count DESC
        """)
        by_type = [dict(r) for r in cursor.fetchall()]

        # Top regions (7d)
        cursor.execute("""
            SELECT region, COUNT(*) as count
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
            GROUP BY region ORDER BY count DESC LIMIT 10
        """)
        top_regions = [dict(r) for r in cursor.fetchall()]

        # Hourly distribution (7d) — UTC to Kyiv
        cursor.execute(f"""
            SELECT CAST(strftime('%H', datetime(th.timestamp, {tz_modifier})) AS INTEGER) as hour,
                   COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE pe.created_at >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
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
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
    except Exception:
        offset_hours = 3
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
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
        if region:
            from urllib.parse import unquote
            where_extra += " AND pe.region = ?"
            extra_params.append(unquote(region))
        if threat_type:
            where_extra += " AND pe.threat_type = ?"
            extra_params.append(threat_type)
        if confidence_min is not None:
            where_extra += " AND pe.confidence_at_set >= ?"
            extra_params.append(confidence_min)
        if confidence_max is not None:
            where_extra += " AND pe.confidence_at_set <= ?"
            extra_params.append(confidence_max)

        # Filter by match_result (applied in post-processing after correlation)
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
            LIMIT ?
        """
        params = date_params + extra_params + [min(limit, 500)]
        cursor.execute(query, params)
        ai_events = [dict(r) for r in cursor.fetchall()]

        # Get all official alarm timestamps for correlation
        alarm_query = f"""
            SELECT region, timestamp, threat_level, id
            FROM threat_history
            WHERE threat_type = 'official_alarm'
            AND threat_level = 'high'
            {date_clause.replace('th_ai.timestamp', 'timestamp')}
            ORDER BY timestamp
        """
        cursor.execute(alarm_query, date_params)
        alarm_rows = cursor.fetchall()

        # Build alarm lookup: region -> [(timestamp_epoch, ts_str)]
        from datetime import datetime as dt_cls
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

        # Correlate each AI event with nearest official alarm
        correlated_events = []
        for ev in ai_events:
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

            correlated_events.append(ev)

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

        # Aggregate stats
        stats = {
            "confirmed": sum(1 for e in correlated_events if e["match_type"] == "confirmed"),
            "mitigated": sum(1 for e in correlated_events if e["match_type"] == "mitigated"),
            "overestimated": sum(1 for e in correlated_events if e["match_type"] == "overestimated"),
            "active": sum(1 for e in correlated_events if e["match_type"] == "active"),
            "cleared": sum(1 for e in correlated_events if e["match_type"] == "cleared"),
        }

        # Time delta distribution (for histogram)
        deltas = [e["time_delta_seconds"] for e in correlated_events if e["time_delta_seconds"] is not None]
        delta_buckets = {}
        for d in deltas:
            bucket = (d // 60) * 60  # Round to nearest minute
            bucket_label = f"{int(bucket // 60)} хв"
            delta_buckets[bucket_label] = delta_buckets.get(bucket_label, 0) + 1

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
            {date_clause.replace('th_ai.timestamp', 'th_ai.timestamp')}
            {where_extra}
            GROUP BY day ORDER BY day
        """
        agg_params = date_params + extra_params
        cursor.execute(daily_agg_query, agg_params)
        daily_stats = [dict(r) for r in cursor.fetchall()]

        # Threat type breakdown for charts
        cursor.execute(f"""
            SELECT pe.threat_type, pe.prediction_accuracy, COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause.replace('th_ai.timestamp', 'th_ai.timestamp')}
            {where_extra}
            GROUP BY pe.threat_type, pe.prediction_accuracy
        """, date_params + extra_params)
        type_breakdown = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return {
            "total": len(correlated_events),
            "stats": stats,
            "events": correlated_events,
            "daily_stats": daily_stats,
            "delta_distribution": delta_buckets,
            "type_breakdown": type_breakdown
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
