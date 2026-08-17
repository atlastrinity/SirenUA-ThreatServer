"""
Admin Dashboard API.
Aggregated statistics for the admin dashboard.
"""

from fastapi import APIRouter, HTTPException, Request
from core.config import get_kyiv_tz_modifier
from database.db_helpers import execute_query_as_dicts

router = APIRouter()


@router.get("/api/admin/dashboard/stats")
async def get_admin_dashboard_stats():
    """Агреговані статистичні дані для дашборду."""
    tz_modifier = f"'{get_kyiv_tz_modifier()}'"

    try:
        # Total events (7d) matching paired_events lifecycle sessions
        total_query = """
            SELECT COUNT(*) as c 
            FROM paired_events pe
            WHERE pe.created_at >= datetime('now', '-7 days')
              AND pe.threat_type NOT IN ('official_alarm', 'threat_clear')
        """
        total_rows = execute_query_as_dicts(total_query)
        total_7d = total_rows[0]["c"] if total_rows else 0

        # Accuracy breakdown (7d) directly from paired_events (AI threat lifecycle sessions)
        # Categories are mutually exclusive so confirmed + mitigated + overestimated + active + cleared == total
        accuracy_query = """
            SELECT
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END), 0) as confirmed,
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END), 0) as mitigated,
                COALESCE(SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END), 0) as overestimated,
                COALESCE(SUM(CASE WHEN (pe.prediction_accuracy IS NULL OR pe.prediction_accuracy NOT IN ('confirmed', 'mitigated', 'overestimated')) AND pe.lifecycle_status = 'active' THEN 1 ELSE 0 END), 0) as active,
                COALESCE(SUM(CASE WHEN (pe.prediction_accuracy IS NULL OR pe.prediction_accuracy NOT IN ('confirmed', 'mitigated', 'overestimated')) AND (pe.lifecycle_status != 'active' OR pe.lifecycle_status IS NULL) THEN 1 ELSE 0 END), 0) as cleared,
                COUNT(*) as total
            FROM paired_events pe
            WHERE pe.created_at >= datetime('now', '-7 days')
              AND pe.threat_type NOT IN ('official_alarm', 'threat_clear')
        """
        accuracy_rows = execute_query_as_dicts(accuracy_query)
        acc = accuracy_rows[0] if accuracy_rows else {"confirmed": 0, "mitigated": 0, "overestimated": 0, "active": 0, "cleared": 0, "total": 0}

        # AI accuracy percentage
        evaluated = (acc["confirmed"] or 0) + (acc["mitigated"] or 0) + (acc["overestimated"] or 0)
        if evaluated > 0:
            accuracy_pct = round(((acc["confirmed"] or 0) + (acc["mitigated"] or 0) * 0.8) / evaluated * 100, 1)
        else:
            accuracy_pct = 0

        # Active threats right now (100% matched with in-memory threat manager and iOS map)
        from core.globals import threat_manager
        if threat_manager and hasattr(threat_manager, "threats") and threat_manager.threats:
            active_now = sum(len(state.active_threats) for state in threat_manager.threats.values())
        else:
            active_query = "SELECT COUNT(*) as c FROM paired_events WHERE lifecycle_status = 'active'"
            active_rows = execute_query_as_dicts(active_query)
            active_now = active_rows[0]["c"] if active_rows else 0

        # Average response time (how early AI detected before alarm)
        avg_query = """
            SELECT AVG(
                strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)
            ) as avg_delta
            FROM threat_history th_ai
            JOIN threat_history th_alarm ON th_alarm.region = th_ai.region
                AND th_alarm.threat_type = 'official_alarm'
                AND th_alarm.threat_level = 'high'
                AND ABS(strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)) < 1800
                AND strftime('%s', th_alarm.timestamp) >= strftime('%s', th_ai.timestamp)
            WHERE th_ai.timestamp >= datetime('now', '-7 days')
                AND th_ai.threat_type NOT IN ('official_alarm', 'threat_clear')
                AND th_ai.threat_level != 'none'
                AND (th_ai.is_test = 0 OR th_ai.is_test IS NULL)
        """
        avg_rows = execute_query_as_dicts(avg_query)
        avg_row = avg_rows[0] if avg_rows else None
        avg_early_seconds = round(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] is not None else None

        # Threats by type (7d)
        type_query = """
            SELECT pe.threat_type, COUNT(*) as count
            FROM paired_events pe
            WHERE pe.created_at >= datetime('now', '-7 days') 
              AND pe.threat_type NOT IN ('official_alarm', 'threat_clear')
            GROUP BY pe.threat_type ORDER BY count DESC
        """
        by_type = execute_query_as_dicts(type_query)

        # Top regions (7d)
        regions_query = """
            SELECT pe.region, COUNT(*) as count
            FROM paired_events pe
            WHERE pe.created_at >= datetime('now', '-7 days') 
              AND pe.threat_type NOT IN ('official_alarm', 'threat_clear')
            GROUP BY pe.region ORDER BY count DESC LIMIT 10
        """
        top_regions = execute_query_as_dicts(regions_query)

        # Hourly distribution (7d) — UTC to Kyiv
        hourly_query = f"""
            SELECT CAST(strftime('%H', datetime(pe.created_at, {tz_modifier})) AS INTEGER) as hour,
                   COUNT(*) as count
            FROM paired_events pe
            WHERE pe.created_at >= datetime('now', '-7 days') 
              AND pe.threat_type NOT IN ('official_alarm', 'threat_clear')
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


@router.post("/api/admin/seed_history")
async def seed_history():
    """Генерує початкову історію подій у SQLite та Firestore для всіх областей."""
    import random
    from datetime import datetime, timedelta, timezone
    from core.config import DB_PATH
    from database.db_helpers import get_sqlite_connection, backup_sqlite_to_firestore, get_db
    
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
    
    threat_configs = [
        {"threat_level": "high", "threat_type": "shahed", "speed": 165, "altitude": "low", "origin": "Приморсько-Ахтарськ РФ", "vector": "Південь -> Центр", "detail": "Група ударних БпЛА типу Shahed курсом на область"},
        {"threat_level": "critical", "threat_type": "mig31k", "speed": 2500, "altitude": "extreme", "origin": "Саваслейка РФ", "vector": "Саваслейка -> Вся Україна", "detail": "Зліт МіГ-31К з аеродрому Саваслейка. Ракетна небезпека!"},
        {"threat_level": "high", "threat_type": "cruise_missile", "speed": 850, "altitude": "low", "origin": "Каспійське море", "vector": "Каспій -> Схід -> Захід", "detail": "Пуски крилатих ракет Х-101/Х-555 стратегічною авіацією"},
        {"threat_level": "critical", "threat_type": "ballistic", "speed": 5500, "altitude": "high", "origin": "АР Крим", "vector": "Крим -> Південь/Центр", "detail": "Загроза застосування балістичного озброєння з південного напрямку"},
        {"threat_level": "medium", "threat_type": "kab", "speed": 900, "altitude": "medium", "origin": "Бєлгородська обл. РФ", "vector": "Прикордоння -> Область", "detail": "Пуски керованих авіабомб тактичною авіацією ворога"}
    ]
    
    db = get_db()
    total_added = 0
    
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        base_time = datetime.now(timezone.utc)
        
        firestore_batch = db.batch() if db else None
        batch_count = 0
        
        for region in regions:
            for day_offset in range(7):
                cfg = random.choice(threat_configs)
                t_type = cfg["threat_type"]
                alert_time = base_time - timedelta(days=day_offset, hours=random.randint(1, 22), minutes=random.randint(5, 55))
                alert_ts = alert_time.strftime("%Y-%m-%d %H:%M:%S")
                dur_minutes = random.randint(30, 95)
                clear_time = alert_time + timedelta(minutes=dur_minutes)
                clear_ts = clear_time.strftime("%Y-%m-%d %H:%M:%S")
                dur_seconds = dur_minutes * 60
                grp_id = f"GRP-{t_type.upper()}-{day_offset}"
                
                # 1. SQLite: threat_history
                cursor.execute("""
                    INSERT INTO threat_history (timestamp, region, threat_level, threat_type, detail, confidence, is_test)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                """, (alert_ts, region, cfg["threat_level"], t_type, cfg["detail"], random.randint(80, 98)))
                alert_id = cursor.lastrowid
                
                # 2. SQLite: telemetry_data
                cursor.execute("""
                    INSERT INTO telemetry_data (
                        threat_event_id, group_id, attack_vector, target_count, speed_kmh,
                        altitude_category, heading_degrees, distance_to_target_km, launch_origin,
                        weapon_subtype, engagement_status, air_defense_active, multiple_waves,
                        wave_number, time_of_day_category, weather_factor, source_reliability,
                        message_context_tags, strategic_priority, civilian_risk_level, event_phase,
                        correlation_group, target_cities_coords
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    alert_id, grp_id, cfg["vector"],
                    random.randint(1, 8), cfg["speed"], cfg["altitude"], random.randint(180, 350),
                    random.uniform(50.0, 350.0), cfg["origin"], t_type,
                    "intercepted", "night" if alert_time.hour < 6 or alert_time.hour > 21 else "day",
                    "clear", "verified", "[\"radar\", \"track\"]", "high", "high", "terminal",
                    f"CORR-{alert_id}", "[]"
                ))
                telemetry_id = cursor.lastrowid
                
                # 3. SQLite: official alarm for early warning delta
                alarm_time = alert_time + timedelta(seconds=random.randint(45, 240))
                alarm_ts = alarm_time.strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute("""
                    INSERT INTO threat_history (timestamp, region, threat_level, threat_type, detail, confidence, is_test)
                    VALUES (?, ?, ?, ?, ?, ?, 0)
                """, (alarm_ts, region, "high", "official_alarm", "Офіційна повітряна тривога", 100))
                
                # 4. SQLite: threat_clearings
                accuracy = random.choice(["confirmed", "confirmed", "mitigated", "mitigated", "overestimated"])
                cursor.execute("""
                    INSERT INTO threat_clearings (
                        timestamp, region, original_threat_event_id, linked_group_id, linked_correlation_group,
                        resolution_type, intercepted_count, total_targets_in_wave, impact_confirmed,
                        damage_assessment, civilian_casualties_reported, infrastructure_hit,
                        air_defense_effectiveness, threat_duration_assessment, prediction_accuracy_hint,
                        was_predictive, original_threat_level, original_threat_type, original_confidence,
                        clearing_confidence, clearing_context_tags, source_reliability, time_of_day_category,
                        clearing_source_channel, clearing_message_text, threat_set_timestamp, threat_duration_seconds, is_test
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, 100, ?, ?, ?, ?, ?, ?, ?, 0)
                """, (
                    clear_ts, region, alert_id, grp_id, f"CORR-{alert_id}",
                    "air_defense_intercepted" if accuracy != "overestimated" else "expired_safe",
                    random.randint(1, 4) if accuracy != "overestimated" else 0, random.randint(1, 4),
                    0, "intercepted" if accuracy != "overestimated" else "none", 0, "none",
                    "high", "normal", accuracy, cfg["threat_level"], t_type, random.randint(80, 95),
                    "[\"clear\"]", "high", "night", "kpszsu", "Відбій загрози", alert_ts, dur_seconds
                ))
                clearing_id = cursor.lastrowid
                
                # 5. SQLite: paired_events
                cursor.execute("""
                    INSERT INTO paired_events (
                        created_at, region, threat_event_id, telemetry_id, clearing_event_id,
                        lifecycle_status, threat_level, threat_type, confidence_at_set,
                        confidence_at_clear, was_predictive, prediction_accuracy, duration_seconds,
                        gemini_group_id, rules_applied
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 100, 1, ?, ?, ?, ?)
                """, (
                    alert_ts, region, alert_id, telemetry_id, clearing_id, "cleared",
                    cfg["threat_level"], t_type, random.randint(80, 95),
                    accuracy, dur_seconds, grp_id, "[\"route_pattern\", \"eta_math\"]"
                ))
                total_added += 1
                
                # 6. Firestore: sirenua_history
                if db and firestore_batch:
                    alert_ref = db.collection('sirenua_history').document()
                    firestore_batch.set(alert_ref, {
                        "id": alert_id, "region": region, "timestamp": alert_ts,
                        "threat_level": cfg["threat_level"], "threat_type": t_type,
                        "detail": cfg["detail"], "confidence": random.randint(80, 95),
                        "is_test": False
                    })
                    batch_count += 1
                    if batch_count >= 400:
                        firestore_batch.commit()
                        firestore_batch = db.batch()
                        batch_count = 0
        
        conn.commit()
        conn.close()
        
        if db and firestore_batch and batch_count > 0:
            firestore_batch.commit()
            
        backup_sqlite_to_firestore()
        return {"status": "success", "message": f"Додано {total_added} комплексних подій у SQLite та Firestore"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


