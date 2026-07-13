"""
Threat Event Logging (SQLite + Firestore).
Functions: log_threat_to_db, log_threat_to_firestore, flush_history_batch, validate_prediction_on_alarm.
"""

import json
import time
from datetime import datetime, timezone

from core.config import DB_PATH
from database.db_helpers import get_db, is_duplicate_event, get_sqlite_connection
from database.error_logger import log_error_to_db

# Firestore history batch buffer — collects writes during batch mode for one flush
_history_batch_buffer = []


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
    """Log threat event to Firebase Firestore with retry on quota errors."""
    db = get_db()
    if not db:
        return

    if is_duplicate_event(region, level, threat_type):
        print(f"⚠️ Duplicate history event detected for {region} ({level}, {threat_type}), skipping write to Firestore.")
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

    max_retries = 3
    for attempt in range(max_retries):
        try:
            db.collection('sirenua_history').add(doc_data)
            print(f"🔥 Logged history event to Firestore for {region}: {level} ({threat_type}, is_test={is_test})")
            return
        except Exception as e:
            err_str = str(e)
            if ("429" in err_str or "Quota" in err_str) and attempt < max_retries - 1:
                wait = (2 ** attempt) * 5
                print(f"⚠️ Firestore quota hit writing history for {region}, retry {attempt+1}/{max_retries} in {wait}s")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, attempt={attempt+1}")
                time.sleep(wait)
            else:
                print(f"⚠️ Помилка запису історії в Firestore: {e}")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, final_failure")
                return
    print(f"❌ Firestore history write failed after {max_retries} retries for {region}")


def flush_history_batch():
    """Flush all buffered Firestore history writes in a single batch operation."""
    global _history_batch_buffer
    if not _history_batch_buffer:
        return

    db = get_db()
    if not db:
        _history_batch_buffer.clear()
        return

    items = list(_history_batch_buffer)
    _history_batch_buffer.clear()

    max_retries = 3
    for attempt in range(max_retries):
        try:
            batch = db.batch()
            for doc_data in items:
                ref = db.collection('sirenua_history').document()
                batch.set(ref, doc_data)
            batch.commit()
            print(f"🔥 Batch flush: {len(items)} history записів за один Firestore write")
            return
        except Exception as e:
            err_str = str(e)
            if ("429" in err_str or "Quota" in err_str) and attempt < max_retries - 1:
                wait = (2 ** attempt) * 5
                print(f"⚠️ Firestore quota hit on batch flush, retry {attempt+1}/{max_retries} in {wait}s")
                log_error_to_db("firebase", str(e), endpoint="flush_history_batch", context=f"batch_size={len(items)}, attempt={attempt+1}")
                time.sleep(wait)
            else:
                print(f"⚠️ Помилка batch flush Firestore history: {e}")
                log_error_to_db("firebase", str(e), endpoint="flush_history_batch", context=f"batch_size={len(items)}, final_failure")
                return


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
