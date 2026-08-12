"""
SirenUA Database & Push Notification Helpers.
Handles Firebase / Firestore clients, backups, and FCM queue worker.
"""

import os
import json
import sqlite3
import gzip
import base64
import asyncio
from datetime import datetime, timezone
from typing import Optional
from core.config import DB_PATH, logger
from database.connection import get_db
from database.connection import (
    get_db,
    get_sqlite_connection,
    execute_query_as_dicts,
    execute_write,
)

try:
    import firebase_admin
    from firebase_admin import messaging, firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

# Re-export helper functions from firestore_sync for backward compatibility
from database.firestore_sync import run_firestore_with_retry, local_sqlite_restore

# Map of Ukrainian region names to corresponding Firebase FCM topics
TOPIC_MAPPING = {
    "Вінницька область": "region_vinnytsia",
    "Волинська область": "region_volyn",
    "Дніпропетровська область": "region_dnipro",
    "Донецька область": "region_donetsk",
    "Житомирська область": "region_zhytomyr",
    "Закарпатська область": "region_zakarpattya",
    "Запорізька область": "region_zaporizhzhya",
    "Івано-Франківська область": "region_if",
    "Київська область": "region_kyiv_oblast",
    "м. Київ": "region_kyiv_city",
    "Кіровоградська область": "region_kirovohrad",
    "Луганська область": "region_luhansk",
    "Львівська область": "region_lviv",
    "Миколаївська область": "region_mykolaiv",
    "Одеська область": "region_odesa",
    "Полтавська область": "region_poltava",
    "Рівненська область": "region_rivne",
    "Сумська область": "region_sumy",
    "Тернопільська область": "region_ternopil",
    "Харківська область": "region_kharkiv",
    "Херсонська область": "region_kherson",
    "Хмельницька область": "region_khmelnytskyi",
    "Черкаська область": "region_cherkasy",
    "Чернівецька область": "region_chernivtsi",
    "Чернігівська область": "region_chernihiv"
}

fcm_queue = None
fcm_worker_task = None

def _log_error(source: str, message: str, endpoint: str = None, context: str = None, error_type: str = None):
    try:
        from database.analytics_db import log_error_to_db
        log_error_to_db(source, message, endpoint, context, error_type)
    except Exception as err:
        logger.error(f"Internal error logger failure: {err}")

def get_db():
    if not HAS_FIREBASE or not firebase_admin._apps:
        return None
    try:
        return firestore.client()
    except Exception as e:
        logger.error(f"Помилка отримання Firestore клієнта: {e}")
        _log_error("database_helpers", f"Помилка отримання Firestore клієнта: {e}", "get_db", error_type="firebase_error")
        return None

def backup_sqlite_to_firestore():
    """Стискає всю локальну базу даних SQLite та робить резервну копію у Firestore."""
        
    db = get_db()
    if not db:
        print("⚠️ [Backup] Firebase не ініціалізовано, пропуск резервного копіювання SQLite.")
        return False
        
    try:
        if not os.path.exists(DB_PATH):
            return False
            
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Перевірка наявності таблиць перед зчитуванням
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables_in_db = [r["name"] for r in cursor.fetchall()]
        
        backup_data = {}
        target_tables = ["gemini_rules", "paired_events", "threat_history", "threat_clearings", "telemetry_data", "gemini_rules_audit", "error_log"]
        
        for table in target_tables:
            if table in tables_in_db:
                cursor.execute(f"SELECT * FROM {table}")
                backup_data[table] = [dict(row) for row in cursor.fetchall()]
            else:
                backup_data[table] = []
                
        conn.close()
        
        # Додаємо мітку часу
        backup_data["backup_timestamp"] = str(datetime.now(timezone.utc))
        
        json_str = json.dumps(backup_data, ensure_ascii=False)
        compressed = gzip.compress(json_str.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        db.collection('sirenua_backup').document('sqlite_compressed').set({
            "data": encoded,
            "size_kb": round(len(encoded) / 1024, 2),
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        print(f"💾 [Backup] SQLite успішно збережено у Firestore (розмір: {len(encoded) / 1024:.2f} KB)")
        return True
    except Exception as e:
        logger.error(f"Помилка резервного копіювання SQLite у Firestore: {e}")
        _log_error("database_helpers", f"Помилка резервного копіювання SQLite: {e}", "backup_sqlite_to_firestore", error_type="database_error")
        return False

def restore_sqlite_from_firestore(force: bool = False):
    """Відновлює локальну базу даних SQLite зі стиснутого бекапу в Firestore."""
        
    db = get_db()
    if not db:
        print("⚠️ [Restore] Firebase не ініціалізовано, пропуск відновлення SQLite.")
        return False
        
    try:
        # Перевіряємо чи є дані локально. Якщо правила чи зв'язані події вже є — пропуск відновлення (якщо не примусово)
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Перевіряємо наявність таблиць
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gemini_rules'")
            has_rules_table = cursor.fetchone()
            
            rules_count = 0
            events_count = 0
            if has_rules_table:
                cursor.execute("SELECT COUNT(*) FROM gemini_rules")
                rules_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM paired_events")
                events_count = cursor.fetchone()[0]
            conn.close()
            
            if not force and (rules_count > 0 or events_count > 0):
                print("💾 [Restore] Локальна SQLite вже містить дані (rules чи events), пропуск відновлення.")
                return False
                
        doc_ref = db.collection('sirenua_backup').document('sqlite_compressed')
        doc = doc_ref.get()
        if not doc.exists:
            print("⚠️ [Restore] Бекап SQLite не знайдено у Firestore.")
            return False
            
        payload = doc.to_dict()
        encoded = payload.get("data")
        if not encoded:
            print("⚠️ [Restore] Дані бекапу SQLite порожні.")
            return False
            
        compressed = base64.b64decode(encoded)
        json_str = gzip.decompress(compressed).decode('utf-8')
        backup_data = json.loads(json_str)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        tables = [
            ("gemini_rules", ["id", "created_at", "updated_at", "rule_type", "source_region", "target_region", "threat_type", "rule_text", "rule_json", "evidence_count", "accuracy_score", "is_active", "last_validated"]),
            ("paired_events", ["id", "created_at", "region", "threat_event_id", "telemetry_id", "clearing_event_id", "lifecycle_status", "threat_level", "threat_type", "confidence_at_set", "confidence_at_clear", "was_predictive", "prediction_accuracy", "duration_seconds", "gemini_group_id", "rules_applied"]),
            ("threat_history", ["id", "timestamp", "region", "threat_level", "threat_type", "detail", "confidence", "is_test"]),
            ("threat_clearings", ["id", "timestamp", "region", "original_threat_event_id", "linked_group_id", "linked_correlation_group", "resolution_type", "intercepted_count", "total_targets_in_wave", "impact_confirmed", "damage_assessment", "civilian_casualties_reported", "infrastructure_hit", "air_defense_effectiveness", "threat_duration_assessment", "prediction_accuracy_hint", "was_predictive", "original_threat_level", "original_threat_type", "original_confidence", "clearing_confidence", "clearing_context_tags", "source_reliability", "time_of_day_category", "clearing_source_channel", "clearing_message_text", "threat_set_timestamp", "threat_duration_seconds", "is_test"]),
            ("telemetry_data", ["id", "threat_event_id", "group_id", "attack_vector", "target_count", "speed_kmh", "altitude_category", "heading_degrees", "distance_to_target_km", "launch_origin", "weapon_subtype", "engagement_status", "air_defense_active", "multiple_waves", "wave_number", "time_of_day_category", "weather_factor", "source_reliability", "message_context_tags", "strategic_priority", "civilian_risk_level", "event_phase", "correlation_group", "target_cities_coords"]),
            ("gemini_rules_audit", ["id", "timestamp", "action", "rule_type", "rule_text", "source_region", "target_region", "threat_type", "reason"]),
            ("error_log", ["id", "timestamp", "source", "error_type", "message", "endpoint", "context"])
        ]
        
        cursor.execute("PRAGMA foreign_keys = OFF")
        
        for table_name, columns in tables:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if not cursor.fetchone():
                continue
                
            rows = backup_data.get(table_name, [])
            if not rows:
                continue
                
            cursor.execute(f"DELETE FROM {table_name}")
            
            for row in rows:
                row_keys = [k for k in row.keys() if k in columns]
                placeholders = ", ".join(["?"] * len(row_keys))
                cols_str = ", ".join(row_keys)
                vals = [row[k] for k in row_keys]
                
                cursor.execute(f"INSERT OR REPLACE INTO {table_name} ({cols_str}) VALUES ({placeholders})", vals)
                
        cursor.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        conn.close()
        print("💾 [Restore] SQLite успішно відновлено з бекапу Firestore!")
        return True
    except Exception as e:
        logger.error(f"Помилка відновлення SQLite з Firestore: {e}")
        _log_error("database_helpers", f"Помилка відновлення SQLite: {e}", "restore_sqlite_from_firestore", error_type="database_error")
        return False

def is_duplicate_event(region: str, level: str, threat_type: Optional[str]) -> bool:
    """Checks local SQLite and Firestore to see if a similar history event was already logged within the last 20 seconds."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_level, threat_type, timestamp 
            FROM threat_history 
            WHERE region = ? 
            ORDER BY id DESC LIMIT 1
        ''', (region,))
        row = cursor.fetchone()
        conn.close()
        if row:
            latest_level, latest_type, latest_time_str = row[0], row[1], row[2]
            if latest_level == level and latest_type == threat_type and latest_time_str:
                latest_time = datetime.strptime(latest_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                current_time = datetime.now(timezone.utc)
                if abs((current_time - latest_time).total_seconds()) < 20:
                    return True
    except Exception as sq_err:
        logger.warning(f"SQLite duplicate check warning: {sq_err}")

    db = get_db()
    if not db:
        return False
    try:
        docs = db.collection("sirenua_history").where("region", "==", region).limit(5).get()
        if not docs:
            return False
            
        events = [doc.to_dict() for doc in docs]
        events.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        latest = events[0]
        
        latest_level = latest.get("threat_level")
        latest_type = latest.get("threat_type")
        latest_time_str = latest.get("timestamp")
        
        if latest_level == level and latest_type == threat_type and latest_time_str:
            latest_time = datetime.strptime(latest_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            current_time = datetime.now(timezone.utc)
            diff = (current_time - latest_time).total_seconds()
            if abs(diff) < 20:
                return True
    except Exception as e:
        logger.error(f"Error checking duplicate history in Firestore: {e}")
        _log_error("database_helpers", f"Error checking duplicate history: {e}", "is_duplicate_event", error_type="firebase_error")
    return False

# Re-export testing cleanup functions from testing package for backward compatibility
from testing import delete_test_history_from_firestore, delete_test_history_from_sqlite

async def fcm_queue_worker():
    global fcm_queue
    while True:
        try:
            item = await fcm_queue.get()
            await asyncio.to_thread(
                _send_fcm_notification_sync,
                item["region"],
                item["level"],
                item["threat_type"],
                item["detail"],
                item["confidence"],
                item["eta"],
                item.get("is_official_alarm", False),
                item.get("is_test", False)
            )
            await asyncio.sleep(0.1)
            fcm_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"Помилка у воркері черги FCM: {e}")
            _log_error("database_helpers", f"Помилка у воркері черги FCM: {e}", "fcm_queue_worker", error_type="firebase_error")
            await asyncio.sleep(1.0)

async def start_fcm_worker():
    global fcm_queue, fcm_worker_task
    if fcm_queue is None:
        fcm_queue = asyncio.Queue()
    if fcm_worker_task is None:
        fcm_worker_task = asyncio.create_task(fcm_queue_worker())
        print("🚀 FCM Queue Worker успішно запущено.")

def send_fcm_notification(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False, **kwargs):
    """Надсилає тихий data-push через FCM. Звук визначається клієнтом."""
    global fcm_queue
    if fcm_queue is not None:
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(
                fcm_queue.put_nowait,
                {
                    "region": region,
                    "level": level,
                    "threat_type": threat_type,
                    "detail": detail,
                    "confidence": confidence,
                    "eta": eta,
                    "is_official_alarm": is_official_alarm,
                    "is_test": is_test
                }
            )
            return
        except RuntimeError:
            pass
    _send_fcm_notification_sync(region, level, threat_type, detail, confidence, eta, is_official_alarm, is_test)

def _send_fcm_notification_sync(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False):
    """
    Надсилає тихий FCM data-push БЕЗ звуку.
    Звук, вібрація та рівень переривання визначаються виключно iOS-клієнтом
    на основі локальних налаштувань користувача (6 рубільників).
    """
    if not HAS_FIREBASE:
        return

    mapped_type = threat_type if threat_type else ("official_alarm" if is_official_alarm else None)
    if is_duplicate_event(region, level, mapped_type):
        print(f"⚠️ Duplicate FCM Push detected for {region} ({level}, {mapped_type}), skipping.")
        return

    topic = TOPIC_MAPPING.get(region)
    if not topic:
        return

    # --- Формування title/body (для банера) та event_type/sound_file ---
    is_clear = (level == "none")
    if is_clear:
        if is_official_alarm:
            title = f"🟢 Відбій тривоги: {region}"
            body = "Офіційну тривогу завершено." if not detail else detail
            event_type = "clear"
            sound_file = "vidbiy.wav"
        else:
            title = f"🟢 Відбій загрози: {region}"
            body = "Загрозу знято." if not detail else detail
            event_type = "threat_clear"
            sound_file = "clearance.wav"
    else:
        if is_official_alarm:
            title = f"🔴 Повітряна тривога: {region}"
            body = detail if detail else "Пройдіть в укриття!"
            event_type = "alarm"
            sound_file = "siren.wav"
        else:
            level_ukr = {"critical": "КРИТИЧНА", "high": "ВИСОКА", "medium": "СЕРЕДНЯ", "low": "НИЗЬКА"}.get(level, level)
            type_str = f" ({threat_type})" if threat_type else ""
            title = f"⚠️ Загроза {level_ukr}: {region}{type_str}"
            body = detail if detail else "Зафіксовано рух ворожих цілей."
            event_type = "threat"
            sound_file = "warning.wav"

    try:
        # Тихий APNS push — без звуку, без critical.
        # iOS-клієнт сам вирішує чи грати звук на основі своїх налаштувань.
        apns_config = messaging.APNSConfig(
            headers={
                "apns-priority": "10",
                "apns-push-type": "alert",
            },
            payload=messaging.APNSPayload(
                aps=messaging.Aps(
                    sound="default",
                    content_available=True,
                    mutable_content=True,
                    badge=0 if is_clear else 1,
                )
            )
        )

        # Android: data-only, без звуку
        android_config = messaging.AndroidConfig(
            priority="high",
        )

        message = messaging.Message(
            notification=messaging.Notification(
                title=title,
                body=body
            ),
            data={
                "region": region,
                "threat_level": level,
                "threat_type": threat_type or "",
                "is_official": "true" if is_official_alarm else "false",
                "is_test": "true" if is_test else "false",
                "confidence": str(confidence) if confidence is not None else "",
                "eta": eta or "",
                # For iOS NotificationServiceExtension: determines which user toggle to check
                "event_type": event_type,
                "sound_file": sound_file,
            },
            topic=topic,
            android=android_config,
            apns=apns_config
        )

        response = messaging.send(message)
        print(f"🔔 FCM Push (silent) надіслано в топік {topic} (відповідь: {response})")
    except Exception as e:
        logger.error(f"Помилка відправки FCM Push для {region}: {e}")
        _log_error("database_helpers", f"Помилка відправки FCM Push для {region}: {e}", "send_fcm_notification", context=f"region={region}, topic={topic}", error_type="firebase_error")


from contextlib import contextmanager
from typing import Generator, List, Dict, Any

def get_kyiv_offset_hours() -> int:
    """Returns current Kyiv timezone offset in hours from UTC (e.g. 2 or 3)."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        
        dt = datetime.now(kiev_tz)
        return int(dt.strftime('%z')[:3])
    except Exception:
        return 3  # Fallback to Kyiv default (UTC+3)


def get_kyiv_tz_modifier() -> str:
    """Returns SQLite strftime modifier for Kyiv timezone, e.g. '+3 hours'."""
    offset_hours = get_kyiv_offset_hours()
    return f"'{offset_hours:+d} hours'"


@contextmanager
def get_db_cursor(db_path: str = DB_PATH) -> Generator[sqlite3.Cursor, None, None]:
    """Context manager for managing SQLite connection and cursor safely."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def query_all(query: str, params: tuple = (), db_path: str = DB_PATH) -> List[Dict[str, Any]]:
    """Executes a SELECT query and returns all rows formatted as dictionaries."""
    with get_db_cursor(db_path) as cursor:
        cursor.execute(query, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def query_one(query: str, params: tuple = (), db_path: str = DB_PATH) -> Optional[Dict[str, Any]]:
    """Executes a SELECT query and returns a single row as a dictionary or None."""
    with get_db_cursor(db_path) as cursor:
        cursor.execute(query, params)
        row = cursor.fetchone()
        return dict(row) if row else None


def execute_non_query(query: str, params: tuple = (), db_path: str = DB_PATH) -> int:
    """Executes an INSERT, UPDATE, or DELETE query and returns the affected row count."""
    with get_db_cursor(db_path) as cursor:
        cursor.execute(query, params)
        return cursor.rowcount
