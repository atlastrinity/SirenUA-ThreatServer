"""
Threat Event Logging (SQLite + Firestore).
Functions: log_threat_to_db, log_threat_to_firestore, flush_history_batch, validate_prediction_on_alarm.
"""

import json
import time
from datetime import datetime, timezone

from core.config import DB_PATH
from database.db_helpers import get_db, is_duplicate_event, get_sqlite_connection, run_firestore_with_retry
from database.error_logger import log_error_to_db

import threading

# Firestore history batch buffer — collects writes and commits them in batches
_history_batch_buffer = []
_batch_lock = threading.Lock()
_batch_timer = None


def queue_history_for_batch(doc_data: dict, region: str):
    """Adds a history document to the in-memory batch buffer and schedules a flush."""
    global _batch_timer
    with _batch_lock:
        _history_batch_buffer.append((doc_data, region))
        if len(_history_batch_buffer) >= 20:
            if _batch_timer:
                _batch_timer.cancel()
                _batch_timer = None
            threading.Thread(target=flush_history_batch, daemon=True).start()
        elif _batch_timer is None:
            _batch_timer = threading.Timer(1.0, flush_history_batch)
            _batch_timer.start()


def log_threat_to_db(
    region: str,
    level: str,
    threat_type: str,
    detail: str = None,
    confidence: int = None,
    telemetry: dict = None,
    is_test: bool = False,
    rules_applied: list = None,
    is_predictive: bool = False,
):
    """Log threat event and its telemetry to SQLite. Returns the threat_event_id."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()

        # Prevent duplicate 'none' (clear) records for the same region and threat_type within 5 seconds
        if level == "none" and not is_test:
            cursor.execute("""
                SELECT id FROM threat_history 
                WHERE region = ? AND threat_level = 'none' AND threat_type = ? AND timestamp >= datetime('now', '-5 seconds')
                ORDER BY id DESC LIMIT 1
            """, (region, threat_type))
            if cursor.fetchone():
                conn.close()
                return None

        cursor.execute(
            "INSERT INTO threat_history (region, threat_level, threat_type, detail, confidence, is_test) VALUES (?, ?, ?, ?, ?, ?)",
            (region, level, threat_type, detail, confidence, 1 if is_test else 0)
        )
        event_id = cursor.lastrowid

        telemetry_id = None
        group_id = None

        if telemetry and isinstance(telemetry, dict) and event_id:
            group_id = telemetry.get("group_id")
            tags_json = json.dumps(telemetry.get("message_context_tags", []), ensure_ascii=False)
            cursor.execute('''
                INSERT INTO telemetry_data (
                    threat_event_id, group_id, attack_vector, target_count, speed_kmh,
                    altitude_category, heading_degrees, distance_to_target_km,
                    launch_origin, weapon_subtype, engagement_status,
                    air_defense_active, multiple_waves, wave_number,
                    time_of_day_category, weather_factor, source_reliability,
                    message_context_tags, strategic_priority, civilian_risk_level,
                    event_phase, correlation_group, target_cities_coords
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_id,
                group_id,
                telemetry.get("attack_vector", "unknown"),
                telemetry.get("target_count"),
                telemetry.get("speed_kmh"),
                telemetry.get("altitude_category", "unknown"),
                telemetry.get("heading_degrees"),
                telemetry.get("distance_to_target_km"),
                telemetry.get("launch_origin"),
                telemetry.get("weapon_subtype"),
                telemetry.get("engagement_status", "unknown"),
                1 if telemetry.get("air_defense_active") else 0,
                1 if telemetry.get("multiple_waves") else 0,
                telemetry.get("wave_number", 1),
                telemetry.get("time_of_day_category", "unknown"),
                telemetry.get("weather_factor", "unknown"),
                telemetry.get("source_reliability", "medium"),
                tags_json,
                telemetry.get("strategic_priority"),
                telemetry.get("civilian_risk_level", "moderate"),
                telemetry.get("event_phase", "unknown"),
                telemetry.get("correlation_group"),
                json.dumps(telemetry.get("target_cities_coords", {}), ensure_ascii=False) if telemetry.get("target_cities_coords") else None
            ))
            telemetry_id = cursor.lastrowid

        if level != "none" and event_id and threat_type != "official_alarm":
            rules_applied_json = json.dumps(rules_applied) if rules_applied else None
            cursor.execute('''
                INSERT INTO paired_events (
                    region, threat_event_id, telemetry_id, lifecycle_status,
                    threat_level, threat_type, confidence_at_set, was_predictive,
                    gemini_group_id, rules_applied
                ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?, ?)
            ''', (
                region, event_id, telemetry_id, level, threat_type,
                confidence, 1 if is_predictive else 0, group_id, rules_applied_json
            ))

        conn.commit()
        conn.close()
        return event_id
    except Exception as e:
        print(f"⚠️ Помилка запису в БД аналітики: {e}")
        log_error_to_db("server", str(e), endpoint="log_threat_to_db", context=f"region={region}, level={level}")
        return None


def log_threat_to_firestore(
    region: str,
    level: str,
    threat_type: str,
    detail: str = None,
    confidence: int = None,
    telemetry: dict = None,
    is_test: bool = False,
):
    """Buffers threat event for atomic batched write to Firebase Firestore."""
    db = get_db()
    if not db:
        return

    if not is_test and is_duplicate_event(region, level, threat_type):
        return

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    unique_id = int(time.time() * 1000)

    doc_data = {
        "id": unique_id,
        "region": region,
        "timestamp": timestamp,
        "threat_level": level,
        "threat_type": threat_type,
        "detail": detail,
        "confidence": confidence,
        "is_test": is_test
    }
    if telemetry:
        doc_data["telemetry"] = telemetry

    queue_history_for_batch(doc_data, region)


def flush_history_batch():
    """Flush all buffered Firestore history writes in a single batch operation."""
    global _batch_timer, _history_batch_buffer
    with _batch_lock:
        if _batch_timer:
            _batch_timer.cancel()
            _batch_timer = None
        if not _history_batch_buffer:
            return
        items = list(_history_batch_buffer)
        _history_batch_buffer.clear()

    db = get_db()
    if not db:
        return

    try:
        def perform_batch():
            batch = db.batch()
            for doc_data, _ in items:
                ref = db.collection('sirenua_history').document()
                batch.set(ref, doc_data)
            batch.commit()

        run_firestore_with_retry(
            perform_batch,
            operation_name="flush_history_batch",
            context_info=f"batch_size={len(items)}"
        )
        regions_list = sorted({r for _, r in items})
        summary_str = ", ".join(regions_list[:5]) + (f" +ще {len(regions_list)-5}" if len(regions_list) > 5 else "")
        print(f"🔥 [Firestore Batch] Збережено {len(items)} подій історії в одному пакеті ({summary_str})")
    except Exception as e:
        if "429" in str(e) or "Quota" in str(e):
            print(f"⚠️ [Firestore Batch] Quota 429 при пакетному записі {len(items)} подій. Історія надійно збережена в локальній SQLite.")
        else:
            print(f"❌ [Firestore Batch] Помилка пакетного запису {len(items)} подій: {e}")
            log_error_to_db("firebase", str(e), endpoint="flush_history_batch", context=f"count={len(items)}")


def validate_prediction_on_alarm(region: str):
    """Marks predictive paired_events as 'confirmed' when official alarm activates."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            UPDATE paired_events 
            SET prediction_accuracy = 'confirmed'
            WHERE region = ? 
              AND was_predictive = 1 
              AND lifecycle_status = 'active'
              AND prediction_accuracy IS NULL
        ''', (region,))
        updated = cursor.rowcount
        conn.commit()
        conn.close()
        if updated > 0:
            print(f"✅ [Validation] Офіційна тривога підтвердила {updated} предикцій Gemini для {region}")
    except Exception as e:
        print(f"⚠️ [Validation] Помилка валідації предикції: {e}")
        log_error_to_db("server", str(e), endpoint="validate_prediction_on_alarm", context=f"region={region}")
