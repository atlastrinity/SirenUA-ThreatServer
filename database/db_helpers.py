"""
SirenUA Database & Push Notification Helpers.
Handles Firebase / Firestore clients, backups, and FCM queue worker.
"""

import sqlite3
import asyncio
from datetime import datetime, timezone
from typing import Optional
from core.config import DB_PATH, logger
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

# Re-export Firestore sync helpers for backward compatibility.
# The canonical implementations live in database.firestore_sync.
from database.firestore_sync import (
    run_firestore_with_retry,
    local_sqlite_restore,
    backup_sqlite_to_firestore,
    restore_sqlite_from_firestore,
)

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

def is_duplicate_event(region: str, level: str, threat_type: Optional[str]) -> bool:
    """Checks local SQLite and Firestore to see if a similar history event was already logged within the last 20 seconds."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT threat_level, threat_type, timestamp 
            FROM threat_history 
            WHERE region = ? 
            ORDER BY id DESC LIMIT 2
        ''', (region,))
        rows = cursor.fetchall()
        conn.close()
        if rows:
            current_time = datetime.now(timezone.utc)
            for row in rows:
                latest_level, latest_type, latest_time_str = row[0], row[1], row[2]
                if latest_time_str:
                    try:
                        latest_time = datetime.strptime(latest_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    except ValueError:
                        continue
                    time_diff = abs((current_time - latest_time).total_seconds())
                    # Only treat as duplicate if a previous event matching level was logged between 2s and 20s ago
                    if 2.0 <= time_diff < 20.0 and latest_level == level and latest_type == threat_type:
                        return True
            return False
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
