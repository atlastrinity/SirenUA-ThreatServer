"""
Import all historical events from Firestore `sirenua_history` into SQLite `threat_history`
and reconstruct `paired_events` and `threat_clearings` for the analytics dashboard.
"""

import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import time
import json
import sqlite3
from datetime import datetime, timezone

import core.config
from core.config import DB_PATH, logger
from core.firebase_init import init_firebase
from database.db_helpers import get_db, get_sqlite_connection, backup_sqlite_to_firestore


def import_all_firestore_history():
    print("🚀 Початок імпорту повної історії з Firestore у локальну SQLite БД...")
    t0 = time.time()
    
    init_firebase()
    db = get_db()
    if not db:
        print("❌ Firebase не ініціалізовано!")
        return False

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Ensure tables exist
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

    # Load existing keys into set to avoid duplicate insertions
    cursor.execute("SELECT region, timestamp, threat_level, threat_type, is_test FROM threat_history")
    existing_keys = set(cursor.fetchall())
    print(f"   Знайдено {len(existing_keys)} існуючих унікальних ключів у локальній threat_history.")

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT,
            threat_event_id INTEGER,
            telemetry_id INTEGER,
            clearing_event_id INTEGER,
            lifecycle_status TEXT DEFAULT 'active',
            threat_level TEXT,
            threat_type TEXT,
            confidence_at_set INTEGER,
            confidence_at_clear INTEGER,
            was_predictive BOOLEAN DEFAULT 0,
            prediction_accuracy TEXT,
            duration_seconds INTEGER,
            gemini_group_id TEXT,
            rules_applied TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_clearings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT,
            original_threat_event_id INTEGER,
            linked_group_id TEXT,
            linked_correlation_group TEXT,
            resolution_type TEXT,
            intercepted_count INTEGER DEFAULT 0,
            total_targets_in_wave INTEGER DEFAULT 0,
            impact_confirmed BOOLEAN DEFAULT 0,
            damage_assessment TEXT,
            civilian_casualties_reported INTEGER DEFAULT 0,
            infrastructure_hit BOOLEAN DEFAULT 0,
            air_defense_effectiveness TEXT,
            threat_duration_assessment TEXT,
            prediction_accuracy_hint TEXT,
            was_predictive BOOLEAN DEFAULT 0,
            original_threat_level TEXT,
            original_threat_type TEXT,
            original_confidence INTEGER,
            clearing_confidence INTEGER,
            clearing_context_tags TEXT,
            source_reliability TEXT,
            time_of_day_category TEXT,
            clearing_source_channel TEXT,
            clearing_message_text TEXT,
            threat_set_timestamp DATETIME,
            threat_duration_seconds INTEGER,
            is_test BOOLEAN DEFAULT 0
        )
    ''')
    conn.commit()

    # Step 1: Stream and batch insert all threat_history records
    print("📡 Завантаження та збереження записів з Firestore (sirenua_history)...")
    batch = []
    batch_size = 2000
    total_streamed = 0
    total_inserted = 0

    for doc in db.collection('sirenua_history').stream():
        total_streamed += 1
        d = doc.to_dict()
        region = d.get('region')
        level = d.get('threat_level')
        threat_type = d.get('threat_type')
        detail = d.get('detail')
        confidence = d.get('confidence')
        timestamp = d.get('timestamp')
        is_test = 1 if d.get('is_test') else 0

        if region and timestamp and level:
            key = (region, timestamp, level, threat_type, is_test)
            if key not in existing_keys:
                existing_keys.add(key)
                batch.append((timestamp, region, level, threat_type, detail, confidence, is_test))

        if len(batch) >= batch_size:
            cursor.executemany('''
                INSERT INTO threat_history 
                (timestamp, region, threat_level, threat_type, detail, confidence, is_test)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', batch)
            conn.commit()
            total_inserted += len(batch)
            batch.clear()
            print(f"   Оброблено {total_streamed} документів...")

    if batch:
        cursor.executemany('''
            INSERT INTO threat_history 
            (timestamp, region, threat_level, threat_type, detail, confidence, is_test)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', batch)
        conn.commit()
        total_inserted += len(batch)
        batch.clear()

    cursor.execute("SELECT COUNT(*) FROM threat_history")
    total_history_rows = cursor.fetchone()[0]
    print(f"✅ Всього в threat_history тепер: {total_history_rows} записів (стрімлено {total_streamed} з Firestore) за {time.time()-t0:.2f}s.")

    # Step 2: Reconstruct paired_events for threat sessions
    print("🔗 Реконструкція paired_events на основі хронології загроз...")
    cursor.execute("SELECT COUNT(*) FROM paired_events")
    paired_count = cursor.fetchone()[0]
    
    # We will build paired_events for all non-alarm events that don't already have a paired_event
    cursor.execute('''
        SELECT th.id, th.timestamp, th.region, th.threat_level, th.threat_type, th.confidence, th.is_test
        FROM threat_history th
        WHERE th.threat_level != 'none' 
          AND th.threat_type NOT IN ('official_alarm', 'threat_clear')
          AND th.id NOT IN (SELECT threat_event_id FROM paired_events WHERE threat_event_id IS NOT NULL)
        ORDER BY th.timestamp ASC, th.id ASC
    ''')
    threat_events = cursor.fetchall()
    print(f"   Знайдено {len(threat_events)} загроз для формування paired_events...")

    paired_batch = []
    for t_id, t_ts, t_region, t_level, t_type, t_conf, t_test in threat_events:
        # Find next clearing or threat state change in that region
        cursor.execute('''
            SELECT id, timestamp, threat_level
            FROM threat_history
            WHERE region = ? AND timestamp > ?
            ORDER BY timestamp ASC, id ASC
            LIMIT 1
        ''', (t_region, t_ts))
        next_ev = cursor.fetchone()

        lifecycle_status = 'cleared' if next_ev and next_ev[2] == 'none' else ('active' if not next_ev else 'cleared')
        duration_sec = None
        clearing_id = None
        
        if next_ev:
            clearing_id = next_ev[0]
            try:
                dt_start = datetime.fromisoformat(t_ts.replace("Z", "+00:00"))
                dt_end = datetime.fromisoformat(next_ev[1].replace("Z", "+00:00"))
                duration_sec = max(0, int((dt_end - dt_start).total_seconds()))
            except Exception:
                pass

        # Estimate prediction accuracy hint
        pred_accuracy = 'mitigated' if duration_sec and duration_sec < 7200 else ('confirmed' if duration_sec else None)
        
        paired_batch.append((
            t_ts, t_region, t_id, None, clearing_id, lifecycle_status,
            t_level, t_type, t_conf, None, 0, pred_accuracy, duration_sec, None, None
        ))

        if len(paired_batch) >= 2000:
            cursor.executemany('''
                INSERT INTO paired_events (
                    created_at, region, threat_event_id, telemetry_id, clearing_event_id,
                    lifecycle_status, threat_level, threat_type, confidence_at_set,
                    confidence_at_clear, was_predictive, prediction_accuracy,
                    duration_seconds, gemini_group_id, rules_applied
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', paired_batch)
            conn.commit()
            paired_batch.clear()

    if paired_batch:
        cursor.executemany('''
            INSERT INTO paired_events (
                created_at, region, threat_event_id, telemetry_id, clearing_event_id,
                lifecycle_status, threat_level, threat_type, confidence_at_set,
                confidence_at_clear, was_predictive, prediction_accuracy,
                duration_seconds, gemini_group_id, rules_applied
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', paired_batch)
        conn.commit()
        paired_batch.clear()

    cursor.execute("SELECT COUNT(*) FROM paired_events")
    final_paired = cursor.fetchone()[0]
    print(f"✅ Всього в paired_events: {final_paired} сесій.")

    # Step 3: Optimize and VACUUM SQLite database
    print("🧹 Оптимізація та VACUUM SQLite бази даних...")
    conn.commit()
    conn.close()

    conn = sqlite3.connect(DB_PATH)
    conn.execute("VACUUM")
    conn.close()
    
    new_size = os.path.getsize(DB_PATH)
    print(f"💾 Розмір БД після VACUUM: {new_size / (1024*1024):.2f} MB (було 664 MB).")

    # Step 4: Create full snapshot in Firestore
    print("☁️ Створення свіжого повного бекапу SQLite в Firestore...")
    backup_sqlite_to_firestore()
    print(f"🎉 Імпорт успішно завершено за {time.time()-t0:.2f}s!")
    return True


if __name__ == "__main__":
    import_all_firestore_history()
