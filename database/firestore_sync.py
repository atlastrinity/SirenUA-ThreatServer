"""
Firestore & SQLite Atomic Backup / Sync Helpers.
"""

import os
import time
import json
import gzip
import base64
import sqlite3
import shutil
from core.config import DB_PATH, logger
from database.connection import get_sqlite_connection, _log_error


try:
    import firebase_admin
    from firebase_admin import firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False
    firestore = None


def get_db():
    """Отримує Firestore клієнта."""
    if not HAS_FIREBASE or firestore is None:
        logger.error("firebase_admin не встановлено")
        _log_error("database_helpers", "firebase_admin не встановлено", "get_db", error_type="firebase_error")
        return None
    try:
        return firestore.client()
    except Exception as e:
        logger.error(f"Помилка отримання Firestore клієнта: {e}")
        _log_error("database_helpers", f"Помилка отримання Firestore клієнта: {e}", "get_db", error_type="firebase_error")
        return None


def run_firestore_with_retry(operation_func, operation_name="firestore_op", context_info="", max_retries=3, initial_delay=1.0):
    """Виконує функцію Firestore з повторними спробами при мережевих помилках."""
    delay = initial_delay
    last_exception = None
    
    for attempt in range(1, max_retries + 1):
        try:
            return operation_func()
        except Exception as e:
            last_exception = e
            error_msg = str(e)
            is_network_error = any(net_err in error_msg.lower() for net_err in [
                "unavailable", "deadline exceeded", "connection reset", "socket", 
                "timeout", "service unavailable", "internal server error", "503", "504"
            ])
            
            if is_network_error and attempt < max_retries:
                logger.warning(f"⚠️ [Firestore Retry] {operation_name} спроба {attempt}/{max_retries} невдала: {e}. Повтор через {delay:.1f}s...")
                time.sleep(delay)
                delay *= 2
            else:
                break
                
    logger.error(f"❌ [Firestore Error] {operation_name} зазнав невдачі після {max_retries} спроб: {last_exception}")
    _log_error(
        source="firestore_sync",
        message=f"Помилка {operation_name}: {last_exception}",
        endpoint=operation_name,
        context=context_info,
        error_type="firebase_error"
    )
    if last_exception:
        raise last_exception
    raise RuntimeError(f"Firestore operation {operation_name} failed")


def _get_backup_paths(db_path: str = None):
    """Допоміжна функція для визначення шляхів до резервних копій БД."""
    target_path = db_path or DB_PATH
    base_dir = os.path.dirname(target_path) if os.path.dirname(target_path) else "."
    backup_dir = os.path.join(base_dir, "backups")
    backup_path = os.path.join(backup_dir, "threat_analytics_backup.db")
    latest_path = os.path.join(backup_dir, "threat_analytics_backup_latest.db")
    return target_path, backup_dir, backup_path, latest_path


def local_sqlite_backup(db_path: str = None) -> bool:
    """Створює локальний атомарний бекап SQLite."""
    target_path, backup_dir, backup_path, latest_path = _get_backup_paths(db_path)
    if not os.path.exists(target_path) or os.path.getsize(target_path) == 0:
        return False
        
    try:
        os.makedirs(backup_dir, exist_ok=True)
        src_conn = get_sqlite_connection(target_path)
        dst_conn = sqlite3.connect(backup_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        shutil.copy2(backup_path, latest_path)
        logger.info(f"💾 [Local DB Backup] Атомарний бекап SQLite збережено у {backup_path}")
        return True
    except Exception as e:
        logger.error(f"⚠️ Помилка створення локального бекапу SQLite: {e}")
        return False


def local_sqlite_restore(db_path: str = None) -> bool:
    """Відновлює локальну SQLite БД з атомарного бекапу."""
    target_path, backup_dir, backup_path, latest_path = _get_backup_paths(db_path)

    source_to_restore = None
    if os.path.exists(latest_path) and os.path.getsize(latest_path) > 0:
        source_to_restore = latest_path
    elif os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
        source_to_restore = backup_path

    if not source_to_restore:
        return False

    try:
        src_conn = sqlite3.connect(source_to_restore)
        dst_conn = get_sqlite_connection(db_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()
        logger.info(f"🔄 [Local DB Restore] SQLite успішно відновлено з локального бекапу {source_to_restore}")
        return True
    except Exception as e:
        logger.error(f"⚠️ Помилка відновлення локального бекапу SQLite: {e}")
        return False


def backup_sqlite_to_firestore():
    """Створює знімок SQLite БД і завантажує в Firestore."""
    if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
        return False
        
    db = get_db()
    if not db:
        print("⚠️ [Backup] Firebase не ініціалізовано, пропуск резервного копіювання SQLite.")
        return False

    try:
        conn = get_sqlite_connection(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        tables = [
            ("gemini_rules", ["id", "created_at", "updated_at", "rule_type", "source_region", "target_region", "threat_type", "rule_text", "rule_json", "evidence_count", "accuracy_score", "is_active", "last_validated"], None),
            ("paired_events", ["id", "created_at", "region", "threat_event_id", "telemetry_id", "clearing_event_id", "lifecycle_status", "threat_level", "threat_type", "confidence_at_set", "confidence_at_clear", "was_predictive", "prediction_accuracy", "duration_seconds", "gemini_group_id", "rules_applied"], None),
            ("threat_history", ["id", "timestamp", "region", "threat_level", "threat_type", "detail", "confidence", "is_test"], None),
            ("threat_clearings", ["id", "timestamp", "region", "original_threat_event_id", "linked_group_id", "linked_correlation_group", "resolution_type", "intercepted_count", "total_targets_in_wave", "impact_confirmed", "damage_assessment", "civilian_casualties_reported", "infrastructure_hit", "air_defense_effectiveness", "threat_duration_assessment", "prediction_accuracy_hint", "was_predictive", "original_threat_level", "original_threat_type", "original_confidence", "clearing_confidence", "clearing_context_tags", "source_reliability", "time_of_day_category", "clearing_source_channel", "clearing_message_text", "threat_set_timestamp", "threat_duration_seconds", "is_test"], None),
            ("telemetry_data", ["id", "threat_event_id", "group_id", "attack_vector", "target_count", "speed_kmh", "altitude_category", "heading_degrees", "distance_to_target_km", "launch_origin", "weapon_subtype", "engagement_status", "air_defense_active", "multiple_waves", "wave_number", "time_of_day_category", "weather_factor", "source_reliability", "message_context_tags", "strategic_priority", "civilian_risk_level", "event_phase", "correlation_group", "target_cities_coords"], None),
            ("gemini_rules_audit", ["id", "timestamp", "action", "rule_type", "rule_text", "source_region", "target_region", "threat_type", "reason"], None),
            ("error_log", ["id", "timestamp", "source", "error_type", "message", "endpoint", "context"], None),
            ("analytics_reports", ["id", "created_at", "report_date", "report_type", "summary_text", "trajectory_data", "launch_data", "risk_matrix", "generated_by"], 200),
            ("palantir_reports", ["id", "created_at", "report_date", "threat_assessment_summary", "palantir_vectors_json", "launch_hubs_json", "risk_matrix_json", "confidence_index", "generated_by"], 200),
        ]
        
        backup_data = {}
        for item in tables:
            table_name, columns = item[0], item[1]
            limit = item[2] if len(item) > 2 else None
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if cursor.fetchone():
                cols_str = ", ".join(columns)
                query = f"SELECT {cols_str} FROM {table_name}"
                if limit:
                    query += f" ORDER BY id DESC LIMIT {limit}"
                cursor.execute(query)
                rows = cursor.fetchall()
                backup_data[table_name] = [dict(r) for r in rows]
                
        conn.close()
        
        json_str = json.dumps(backup_data, ensure_ascii=False)
        compressed = gzip.compress(json_str.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        doc_ref = db.collection('sirenua_backup').document('sqlite_compressed')
        run_firestore_with_retry(
            lambda: doc_ref.set({
                "timestamp": firestore.SERVER_TIMESTAMP,
                "data": encoded,
                "version": "2.0",
                "tables_backed_up": list(backup_data.keys()),
                "uncompressed_size_kb": len(json_str) / 1024,
                "compressed_size_kb": len(compressed) / 1024
            }),
            operation_name="backup_sqlite_to_firestore_set",
            context_info="saving_sqlite_compressed",
            max_retries=3
        )
        local_sqlite_backup()
        print(f"💾 [Backup] SQLite атомарно стиснуто ({len(compressed)/1024:.1f} KB) і збережено в Firestore & Local!")
        return True
    except Exception as e:
        logger.error(f"Помилка резервного копіювання SQLite у Firestore: {e}")
        _log_error("database_helpers", f"Помилка резервного копіювання SQLite: {e}", "backup_sqlite_to_firestore", error_type="database_error")
        return False


def _restore_from_payload(encoded: str) -> bool:
    """Відновлює SQLite з raw base64+gzip payload."""
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
            ("error_log", ["id", "timestamp", "source", "error_type", "message", "endpoint", "context"]),
            ("analytics_reports", ["id", "created_at", "report_date", "report_type", "summary_text", "trajectory_data", "launch_data", "risk_matrix", "generated_by"]),
            ("palantir_reports", ["id", "created_at", "report_date", "threat_assessment_summary", "palantir_vectors_json", "launch_hubs_json", "risk_matrix_json", "confidence_index", "generated_by"]),
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


def delete_test_history_from_firestore() -> int:
    """Видаляє тестові загрози та кліринги з Firestore (sirenua_history)."""
    db = get_db()
    if not db:
        return 0
    deleted_count = 0
    try:
        for coll_name in ['sirenua_history', 'threat_history']:
            docs = list(db.collection(coll_name).where('is_test', '==', True).limit(450).get())
            if docs:
                batch = db.batch()
                for doc in docs:
                    batch.delete(doc.reference)
                batch.commit()
                deleted_count += len(docs)
        return deleted_count
    except Exception as e:
        logger.error(f"Помилка видалення тестової історії з Firestore: {e}")
        return deleted_count


def restore_from_local_baseline() -> bool:
    """Відновлює SQLite з локального baseline-бекапу, якщо Firestore недоступний або 429."""
    baseline_path = os.path.join(os.path.dirname(__file__), "baseline_backup.json.gz")
    if not os.path.exists(baseline_path):
        return False
    try:
        with open(baseline_path, "rb") as f:
            compressed = f.read()
        encoded = base64.b64encode(compressed).decode('utf-8')
        success = _restore_from_payload(encoded)
        if success:
            print(f"📦 [Baseline Restore] SQLite успішно ініціалізовано з baseline_backup.json.gz (94 події, 7 таблиць)!")
        return success
    except Exception as e:
        logger.error(f"Помилка відновлення з baseline_backup: {e}")
        return False


def restore_sqlite_from_firestore(force: bool = False):
    """Відновлює локальну базу даних SQLite зі стиснутого бекапу в Firestore або з локального baseline-бекапу."""
    db = get_db()
    if not db:
        print("⚠️ [Restore] Firebase не ініціалізовано, спроба завантаження з baseline_backup...")
        return restore_from_local_baseline()
        
    try:
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
        if not doc or not doc.exists:
            print("⚠️ [Restore] Бекап sqlite_compressed не знайдено, спроба завантаження з колекції sirenua_history...")
            res = _restore_from_sirenua_history_collection(db)
            if not res:
                return restore_from_local_baseline()
            return res
            
        payload = doc.to_dict() or {}
        encoded = payload.get("data")
        if not encoded:
            print("⚠️ [Restore] Дані бекапу SQLite порожні, спроба завантаження з колекції sirenua_history...")
            res = _restore_from_sirenua_history_collection(db)
            if not res:
                return restore_from_local_baseline()
            return res
            
        success = _restore_from_payload(encoded)
        if success:
            print("💾 [Restore] SQLite успішно відновлено з бекапу Firestore!")
        else:
            print("⚠️ [Restore] Не вдалося відновити з payload, спроба завантаження з baseline_backup...")
            success = restore_from_local_baseline()
        return success
    except Exception as e:
        logger.error(f"Помилка відновлення SQLite з Firestore: {e}")
        _log_error("database_helpers", f"Помилка відновлення SQLite: {e}", "restore_sqlite_from_firestore", error_type="database_error")
        res = _restore_from_sirenua_history_collection(db)
        if not res:
            return restore_from_local_baseline()
        return res


def _restore_from_sirenua_history_collection(db) -> bool:
    """Підтягує записи історії з колекції sirenua_history в локальну базі SQLite, якщо стиснутий бекап відсутній."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                region TEXT,
                threat_level TEXT,
                threat_type TEXT,
                detail TEXT,
                confidence INTEGER,
                is_test BOOLEAN DEFAULT 0
            )
        ''')
        conn.commit()

        docs = db.collection('sirenua_history').limit(500).get()
        restored_count = 0
        for doc in docs:
            d = doc.to_dict()
            region = d.get('region')
            level = d.get('threat_level')
            threat_type = d.get('threat_type')
            detail = d.get('detail')
            confidence = d.get('confidence')
            timestamp = d.get('timestamp')
            is_test = 1 if d.get('is_test') else 0
            
            if region and timestamp and level:
                cursor.execute(
                    "SELECT 1 FROM threat_history WHERE region = ? AND timestamp = ? AND threat_level = ?",
                    (region, timestamp, level)
                )
                if not cursor.fetchone():
                    cursor.execute(
                        "INSERT INTO threat_history (region, threat_level, threat_type, detail, confidence, timestamp, is_test) VALUES (?, ?, ?, ?, ?, ?, ?)",
                        (region, level, threat_type, detail, confidence, timestamp, is_test)
                    )
                    restored_count += 1
        
        conn.commit()
        conn.close()
        if restored_count > 0:
            print(f"💾 [Restore] Успішно відновлено {restored_count} подій з колекції sirenua_history в SQLite!")
            return True
        return False
    except Exception as e:
        logger.error(f"Помилка відновлення з sirenua_history: {e}")
        return False


def try_background_restore_if_empty() -> bool:
    """Перевіряє, чи SQLite містить мало записів (наприклад, через 429 ліміти при старті), і намагається підтягнути бекап."""
    try:
        conn = get_sqlite_connection(DB_PATH)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM threat_history")
        count = cursor.fetchone()[0]
        conn.close()
        if count < 10:
            print(f"🔄 [AutoRestore] У SQLite лише {count} подій. Спроба відновлення з Firestore...")
            return restore_sqlite_from_firestore(force=True)
    except Exception as e:
        logger.warning(f"⚠️ [AutoRestore] Помилка фонового відновлення: {e}")
    return False
