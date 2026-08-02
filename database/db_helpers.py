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
import time
from datetime import datetime, timezone
from typing import Optional
from core.config import DB_PATH, logger

try:
    import firebase_admin
    from firebase_admin import messaging, firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

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
        from database.error_logger import log_error_to_db
        log_error_to_db(source, message, endpoint, context, error_type)
    except Exception as err:
        logger.error(f"Internal error logger failure: {err}")

def get_sqlite_connection(db_path: str = None) -> sqlite3.Connection:
    """
    Створює безпечне підключення до бази даних SQLite.
    Налаштовує busy timeout (20 секунд) та WAL (Write-Ahead Logging) режим.
    """
    if db_path is None:
        db_path = DB_PATH
    conn = sqlite3.connect(db_path, timeout=20.0)
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
    except Exception:
        pass
    return conn

def get_db():
    if not HAS_FIREBASE or not firebase_admin._apps:
        return None
    try:
        return firestore.client()
    except Exception as e:
        logger.error(f"Помилка отримання Firestore клієнта: {e}")
        _log_error("database_helpers", f"Помилка отримання Firestore клієнта: {e}", "get_db", error_type="firebase_error")
        return None

def local_sqlite_backup(db_path: str = None) -> bool:
    """
    Створює повну локальну атомарну резервну копію SQLite БД (threat_analytics.db -> backups/threat_analytics_backup.db).
    Використовує офіційний механізм sqlite3 backup API для 100% цілісності навіть під навантаженням.
    """
    if db_path is None:
        db_path = DB_PATH
    if not os.path.exists(db_path) or os.path.getsize(db_path) == 0:
        return False
        
    try:
        backup_dir = os.path.join(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", "backups")
        os.makedirs(backup_dir, exist_ok=True)
        backup_path = os.path.join(backup_dir, "threat_analytics_backup.db")
        latest_path = os.path.join(backup_dir, "threat_analytics_backup_latest.db")

        src_conn = get_sqlite_connection(db_path)
        dst_conn = sqlite3.connect(backup_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        import shutil
        shutil.copy2(backup_path, latest_path)
        logger.info(f"💾 [Local DB Backup] Атомарний бекап SQLite збережено у {backup_path}")
        return True
    except Exception as e:
        logger.error(f"⚠️ Помилка створення локального бекапу SQLite: {e}")
        return False


def local_sqlite_restore(db_path: str = None) -> bool:
    """
    Автоматично відновлює локальну SQLite БД з атомарного бекапу backups/threat_analytics_backup.db у разі пошкодження.
    """
    if db_path is None:
        db_path = DB_PATH
        
    backup_dir = os.path.join(os.path.dirname(db_path) if os.path.dirname(db_path) else ".", "backups")
    latest_path = os.path.join(backup_dir, "threat_analytics_backup_latest.db")
    backup_path = os.path.join(backup_dir, "threat_analytics_backup.db")

    source_to_restore = None
    if os.path.exists(latest_path) and os.path.getsize(latest_path) > 0:
        source_to_restore = latest_path
    elif os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
        source_to_restore = backup_path

    if not source_to_restore:
        return False

    try:
        import shutil
        shutil.copy2(source_to_restore, db_path)
        logger.info(f"🔄 [Auto-Recovery] Успішно відновлено базу SQLite з резервної копії {source_to_restore}")
        return True
    except Exception as e:
        logger.error(f"⚠️ Помилка відновлення SQLite з локального бекапу: {e}")
        return False


def backup_sqlite_to_firestore():
    """Стискає всю локальну базу даних SQLite та робить резервну копію у Firestore."""
        
    db = get_db()
    if not db:
        print("⚠️ [Backup] Firebase не ініціалізовано, пропуск резервного копіювання SQLite.")
        return False
        
    try:
        if not os.path.exists(DB_PATH):
            return False
            
        conn = get_sqlite_connection(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Safety check: don't overwrite a full backup with an empty/tiny DB
        # This prevents data loss when container restarts and restore failed (e.g. 429 quota)
        history_count = 0
        try:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_history'")
            if cursor.fetchone():
                cursor.execute("SELECT COUNT(*) FROM threat_history")
                history_count = cursor.fetchone()[0]
        except Exception:
            pass
        
        if history_count < 50:
            print(f"⚠️ [Backup] Локальна SQLite містить лише {history_count} записів threat_history — пропуск бекапу для захисту від перезапису повних даних.")
            conn.close()
            return False
        
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
        
        doc_ref = db.collection('sirenua_backup').document('sqlite_compressed')
        run_firestore_with_retry(
            lambda: doc_ref.set({
                "data": encoded,
                "size_kb": round(len(encoded) / 1024, 2),
                "updated_at": firestore.SERVER_TIMESTAMP
            }),
            operation_name="backup_sqlite_to_firestore_set",
            context_info="saving_sqlite_compressed",
            max_retries=3
        )
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
        # Перевіряємо чи є РЕАЛЬНІ оперативні дані (не seed-правила).
        # threat_history > 50 означає що є реальні дані моніторингу, а не тільки seed.
        if os.path.exists(DB_PATH):
            conn = get_sqlite_connection(DB_PATH)
            cursor = conn.cursor()
            
            history_count = 0
            try:
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='threat_history'")
                if cursor.fetchone():
                    cursor.execute("SELECT COUNT(*) FROM threat_history")
                    history_count = cursor.fetchone()[0]
            except Exception:
                pass
            conn.close()
            
            if not force and history_count > 50:
                print(f"💾 [Restore] Локальна SQLite вже містить {history_count} реальних подій, пропуск відновлення.")
                return False
                
        doc_ref = db.collection('sirenua_backup').document('sqlite_compressed')
        doc = run_firestore_with_retry(
            lambda: doc_ref.get(),
            operation_name="restore_sqlite_from_firestore_get",
            context_info="fetching_sqlite_compressed",
            max_retries=3
        )
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
        
        conn = get_sqlite_connection(DB_PATH)
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


def _restore_from_payload(encoded: str) -> bool:
    """Відновлює SQLite з raw base64+gzip payload (без Firestore)."""
    try:
        compressed = base64.b64decode(encoded)
        json_str = gzip.decompress(compressed).decode('utf-8')
        backup_data = json.loads(json_str)
        
        conn = get_sqlite_connection(DB_PATH)
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
        
        total_restored = 0
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
            total_restored += len(rows)
                
        cursor.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        conn.close()
        try:
            from api.admin.analytics_intelligence import _ANALYTICS_CACHE
            _ANALYTICS_CACHE.clear()
        except Exception:
            pass
        print(f"💾 [Restore Upload] SQLite успішно відновлено з завантаженого бекапу! ({total_restored} записів)")
        return True
    except Exception as e:
        logger.error(f"Помилка відновлення SQLite з завантаженого бекапу: {e}")
        return False


_recent_events_cache = {}

def is_duplicate_event(region: str, level: str, threat_type: Optional[str], window_seconds: int = 20) -> bool:
    """
    Checks if a similar threat event was already logged for the region within window_seconds.
    Uses fast in-memory TTL cache + local SQLite (threat_history) for zero network overhead & zero Firestore quota usage.
    """
    global _recent_events_cache
    now_ts = time.time()
    cache_key = (region, level, threat_type or "")

    # Fast In-Memory Check (O(1))
    last_seen_ts = _recent_events_cache.get(cache_key)
    if last_seen_ts and (now_ts - last_seen_ts) < window_seconds:
        return True

    # Fallback to local SQLite check
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT timestamp, threat_level, threat_type FROM threat_history WHERE region = ? ORDER BY id DESC LIMIT 1",
            (region,)
        )
        row = cursor.fetchone()
        conn.close()

        if row:
            latest_time_str = row[0]
            latest_level = row[1]
            latest_type = row[2]

            if latest_level == level and (latest_type == threat_type or (not latest_type and not threat_type)) and latest_time_str:
                try:
                    latest_time = datetime.strptime(latest_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
                    diff = (datetime.now(timezone.utc) - latest_time).total_seconds()
                    if abs(diff) < window_seconds:
                        _recent_events_cache[cache_key] = now_ts
                        return True
                except Exception:
                    pass
    except Exception as e:
        logger.error(f"Error checking duplicate history in SQLite: {e}")

    _recent_events_cache[cache_key] = now_ts
    return False


def delete_test_history_from_firestore():
    db = get_db()
    if not db:
        return
    try:
        docs = db.collection('sirenua_history').where('is_test', '==', True).get()
        deleted_count = 0
        for doc in docs:
            doc.reference.delete()
            deleted_count += 1
        print(f"🧹 Видалено {deleted_count} тестових записів з історії Firestore")
    except Exception as e:
        logger.error(f"Помилка видалення тестової історії з Firestore: {e}")
        _log_error("database_helpers", f"Помилка видалення тестової історії: {e}", "delete_test_history_from_firestore", error_type="firebase_error")

def delete_test_history_from_sqlite():
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            DELETE FROM paired_events 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
               OR clearing_event_id IN (SELECT id FROM threat_clearings WHERE is_test = 1)
        ''')
        paired_deleted = cursor.rowcount

        cursor.execute('''
            DELETE FROM telemetry_data 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
        ''')
        
        cursor.execute("DELETE FROM threat_history WHERE is_test = 1")
        threats_deleted = cursor.rowcount
        
        cursor.execute("DELETE FROM threat_clearings WHERE is_test = 1")
        clearings_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        print(f"🧹 Видалено тестові записи з SQLite: {threats_deleted} загроз, {clearings_deleted} відбоїв, {paired_deleted} зв'язаних подій")
    except Exception as e:
        logger.error(f"Помилка видалення тестової історії з SQLite: {e}")
        _log_error("database_helpers", f"Помилка видалення тестової історії з SQLite: {e}", "delete_test_history_from_sqlite", error_type="database_error")

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
                item["play_sound"],
                item["confidence"],
                item["eta"],
                item.get("is_official_alarm", False),
                item.get("is_test", False)
            )
            if item.get("play_sound", True):
                await asyncio.sleep(1.5)
            else:
                await asyncio.sleep(0.05)
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

def send_fcm_notification(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False):
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
                    "play_sound": play_sound,
                    "confidence": confidence,
                    "eta": eta,
                    "is_official_alarm": is_official_alarm,
                    "is_test": is_test
                }
            )
            return
        except RuntimeError:
            pass
    _send_fcm_notification_sync(region, level, threat_type, detail, play_sound, confidence, eta, is_official_alarm, is_test)

def _send_fcm_notification_sync(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False):
    if not HAS_FIREBASE:
        return
    try:
        firebase_admin.get_app()
    except (ValueError, AttributeError):
        return

    mapped_type = threat_type if threat_type else ("official_alarm" if is_official_alarm else None)
    if is_duplicate_event(region, level, mapped_type):
        print(f"⚠️ Duplicate FCM Push detected for {region} ({level}, {mapped_type}), skipping.")
        return

    topic = TOPIC_MAPPING.get(region)
    if not topic:
        return

    if level == "none":
        if is_official_alarm:
            title = f"🟢 Відбій: {region}"
            body = "Загрозу знято."
            sound = "clearance.wav"
        else:
            title = f"🟢 Відбій: {region}"
            body = "Загрозу знято."
            sound = None
    else:
        sound = "warning.wav" if play_sound else None
        if is_official_alarm:
            title = f"🔴 Повітряна тривога: {region}"
            body = detail if detail else "Пройдіть в укриття!"
        else:
            level_ukr = {"critical": "КРИТИЧНА", "high": "ВИСОКА", "medium": "СЕРЕДНЯ", "low": "НИЗЬКА"}.get(level, level)
            type_str = f" ({threat_type})" if threat_type else ""
            title = f"⚠️ Загроза {level_ukr}: {region}{type_str}"
            body = detail if detail else "Зафіксовано рух ворожих цілей."

    try:
        android_config = None
        if sound:
            android_config = messaging.AndroidConfig(
                notification=messaging.AndroidNotification(
                    sound=sound,
                    channel_id="sirenua_alarms_channel"
                )
            )
        
        apns_config = None
        if sound:
            crit_sound = messaging.CriticalSound(
                name=sound,
                volume=1.0,
                critical=True
            )
            apns_config = messaging.APNSConfig(
                payload=messaging.APNSPayload(
                    aps=messaging.Aps(
                        sound=crit_sound
                    )
                )
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
                "eta": eta or ""
            },
            topic=topic,
            android=android_config,
            apns=apns_config
        )

        response = messaging.send(message)
        print(f"🔔 FCM Push надіслано в топік {topic} (відповідь: {response})")
    except Exception as e:
        logger.error(f"Помилка відправки FCM Push для {region}: {e}")
        _log_error("database_helpers", f"Помилка відправки FCM Push для {region}: {e}", "send_fcm_notification", context=f"region={region}, topic={topic}", error_type="firebase_error")


def run_firestore_with_retry(operation_func, operation_name: str, context_info: str = "", max_retries: int = 2):
    """
    Runs a Firestore database operation with automatic retry on transient errors.
    Gracefully handles HTTP 429 Quota Exceeded without spamming error logs.
    """
    for attempt in range(max_retries):
        try:
            return operation_func()
        except Exception as e:
            err_str = str(e)
            if "429" in err_str or "Quota" in err_str:
                logger.warning(f"⚠️ [Firestore Quota] {operation_name} ({context_info}): 429 Quota exceeded.")
                raise e
            elif attempt < max_retries - 1:
                wait = (2 ** attempt) * 2
                logger.warning(f"⚠️ Firestore operation {operation_name} retry {attempt+1}/{max_retries} in {wait}s ({context_info})")
                time.sleep(wait)
            else:
                logger.error(f"⚠️ Error executing Firestore operation {operation_name}: {e}")
                raise e



def execute_query_as_dicts(query: str, params: tuple = (), json_fields: list = None) -> list:
    """
    Executes a SQLite query and returns the results as a list of dictionaries,
    optionally parsing specified fields as JSON objects.
    """
    conn = get_sqlite_connection()
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        results = []
        for row in rows:
            d = dict(row)
            if json_fields:
                for field in json_fields:
                    val = d.get(field)
                    if val and isinstance(val, str):
                        try:
                            d[field] = json.loads(val)
                        except (json.JSONDecodeError, TypeError):
                            pass
            results.append(d)
        return results
    finally:
        conn.close()


def execute_write(query: str, params: tuple = ()):
    """Executes a SQLite write query (INSERT, UPDATE, DELETE) and commits it."""
    conn = get_sqlite_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
    finally:
        conn.close()


