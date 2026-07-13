"""
Threat Clearing Logging.
Functions: detect_mitigation_from_text, log_clearing_to_db.
"""

import sqlite3
import json
from datetime import datetime, timezone

from core.config import DB_PATH
from database.error_logger import log_error_to_db


def detect_mitigation_from_text(text: str) -> bool:
    """Returns True if message text contains Ukrainian keywords indicating interception/mitigation."""
    if not text:
        return False
    text_lower = text.lower()
    keywords = [
        "збит", "збило", "збили", "знищен", "ліквід",
        "локаційно втрат", "локаційна втрат",
        "втрачено радіолокац", "втрачено з радар",
        "робота ппо", "працює ппо", "працювала ппо", "роботу ппо",
        "реб", "електронної боротьб", "приглуш"
    ]
    return any(kw in text_lower for kw in keywords)


def log_clearing_to_db(
    region: str,
    clearing_telemetry: dict = None,
    source_channel: str = None,
    message_text: str = None,
    clearing_confidence: int = None,
    was_predictive: bool = False,
    is_test: bool = False,
):
    """Log threat clearing event linked to original threat. Closes active paired events."""
    if not clearing_telemetry:
        clearing_telemetry = {}

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        original_event_id = None
        original_level = None
        original_type = None
        original_confidence = None
        threat_set_ts = None
        threat_duration_sec = None

        # Try to find linked original threat event
        linked_gid = clearing_telemetry.get("linked_group_id")
        row = None
        if linked_gid:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN telemetry_data td ON th.id = td.threat_event_id
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND td.group_id = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region, linked_gid))
            row = cursor.fetchone()

        if not row:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
                WHERE th.region = ? AND th.threat_type = 'official_alarm' AND tc.id IS NULL
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()

        if not row:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
            row = cursor.fetchone()

        if not row:
            conn.close()
            return None

        original_event_id = row["id"]
        original_level = row["threat_level"]
        original_type = row["threat_type"]
        original_confidence = row["confidence"]
        threat_set_ts = row["timestamp"]

        try:
            set_time = datetime.fromisoformat(threat_set_ts.replace('Z', '+00:00') if threat_set_ts else "")
            now = datetime.now(timezone.utc)
            threat_duration_sec = int((now - set_time.replace(tzinfo=timezone.utc)).total_seconds())
            if threat_duration_sec < 0:
                threat_duration_sec = None
        except Exception:
            threat_duration_sec = None

        tags_json = json.dumps(clearing_telemetry.get("clearing_context_tags", []), ensure_ascii=False)

        cursor.execute('''
            INSERT INTO threat_clearings (
                region, original_threat_event_id, linked_group_id, linked_correlation_group,
                resolution_type, intercepted_count, total_targets_in_wave,
                impact_confirmed, damage_assessment, civilian_casualties_reported,
                infrastructure_hit, air_defense_effectiveness, threat_duration_assessment,
                prediction_accuracy_hint, was_predictive,
                original_threat_level, original_threat_type, original_confidence,
                clearing_confidence, clearing_context_tags,
                source_reliability, time_of_day_category,
                clearing_source_channel, clearing_message_text,
                threat_set_timestamp, threat_duration_seconds, is_test
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            region,
            original_event_id,
            clearing_telemetry.get("linked_group_id"),
            clearing_telemetry.get("linked_correlation_group"),
            clearing_telemetry.get("resolution_type", "unknown"),
            clearing_telemetry.get("intercepted_count"),
            clearing_telemetry.get("total_targets_in_wave"),
            1 if clearing_telemetry.get("impact_confirmed") else 0,
            clearing_telemetry.get("damage_assessment", "unknown"),
            1 if clearing_telemetry.get("civilian_casualties_reported") else 0,
            clearing_telemetry.get("infrastructure_hit"),
            clearing_telemetry.get("air_defense_effectiveness", "unknown"),
            clearing_telemetry.get("threat_duration_assessment", "unknown"),
            clearing_telemetry.get("prediction_accuracy_hint", "not_applicable"),
            1 if was_predictive else 0,
            original_level,
            original_type,
            original_confidence,
            clearing_confidence,
            tags_json,
            clearing_telemetry.get("source_reliability", "medium"),
            clearing_telemetry.get("time_of_day_category", "unknown"),
            source_channel,
            message_text[:500] if message_text else None,
            threat_set_ts,
            threat_duration_sec,
            1 if is_test else 0
        ))

        clearing_id = cursor.lastrowid
        prediction_accuracy = clearing_telemetry.get("prediction_accuracy_hint", "not_applicable")

        if original_event_id:
            cursor.execute('''
                SELECT prediction_accuracy FROM paired_events
                WHERE threat_event_id = ? AND lifecycle_status = 'active'
            ''', (original_event_id,))
            pe_row = cursor.fetchone()
            current_accuracy = pe_row[0] if pe_row else None

            if current_accuracy == 'confirmed' and prediction_accuracy != 'confirmed':
                prediction_accuracy = 'confirmed'
            elif prediction_accuracy in ["overestimated", "unknown", "not_applicable", "n/a"]:
                res_type = clearing_telemetry.get("resolution_type", "unknown")
                if res_type in ["intercepted", "lost_contact"] or detect_mitigation_from_text(message_text):
                    prediction_accuracy = 'mitigated'

            cursor.execute('''
                UPDATE paired_events SET
                    clearing_event_id = ?,
                    lifecycle_status = 'cleared',
                    confidence_at_clear = ?,
                    prediction_accuracy = ?,
                    duration_seconds = ?
                WHERE threat_event_id = ? AND lifecycle_status = 'active'
            ''', (
                clearing_id, clearing_confidence, prediction_accuracy,
                threat_duration_sec, original_event_id
            ))
            closed_count = cursor.rowcount
            if closed_count > 0:
                print(f"🔗 [Paired] Закрито {closed_count} paired_event(s) для {region} (accuracy: {prediction_accuracy})")

            if not clearing_telemetry.get("linked_group_id"):
                cursor.execute('''
                    UPDATE paired_events SET
                        clearing_event_id = ?,
                        lifecycle_status = 'cleared',
                        confidence_at_clear = ?,
                        prediction_accuracy = ?,
                        duration_seconds = CAST((strftime('%s', 'now') - strftime('%s', created_at)) AS INTEGER)
                    WHERE region = ? AND lifecycle_status = 'active'
                ''', (clearing_id, clearing_confidence, prediction_accuracy, region))
                other_closed = cursor.rowcount
                if other_closed > 0:
                    print(f"🔗 [Paired] Додатково закрито {other_closed} завислих подій для {region}")

        conn.commit()
        conn.close()

        res_type = clearing_telemetry.get("resolution_type", "unknown")
        pred_hint = clearing_telemetry.get("prediction_accuracy_hint", "n/a")
        dur = f"{threat_duration_sec}с" if threat_duration_sec else "?"
        print(f"📊 [Clearing DB] {region}: тип={res_type}, предикція={pred_hint}, тривалість={dur}, linked_event={original_event_id}")

        return clearing_id
    except Exception as e:
        print(f"⚠️ Помилка запису clearing в БД: {e}")
        log_error_to_db("server", str(e), endpoint="log_clearing_to_db", context=f"region={region}")
        return None
