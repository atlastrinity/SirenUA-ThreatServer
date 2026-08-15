"""
SirenUA Smart Incremental Local Backup Service.
Executes an append-only incremental backup every 5 minutes, ensuring historical data is never lost.
"""

import os
import sys
import time
import shutil
import sqlite3
import asyncio
from datetime import datetime, timezone
from core.config import DB_PATH, logger


def get_archive_db_path() -> str:
    """Returns the path to the permanent cumulative smart backup database."""
    base_dir = os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else "."
    backup_dir = os.path.join(base_dir, "backups")
    os.makedirs(backup_dir, exist_ok=True)
    return os.path.join(backup_dir, "threat_analytics_smart_archive.db")


def init_archive_tables(archive_conn: sqlite3.Connection):
    """Ensures that all tables and unique indexes exist in the archive database."""
    cursor = archive_conn.cursor()
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
    cursor.execute('''
        CREATE UNIQUE INDEX IF NOT EXISTS idx_archive_threat_history_uniq 
        ON threat_history (region, timestamp, threat_level, threat_type, is_test)
    ''')

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

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_event_id INTEGER,
            group_id TEXT,
            attack_vector TEXT,
            target_count INTEGER,
            speed_kmh REAL,
            altitude_category TEXT,
            heading_degrees REAL,
            distance_to_target_km REAL,
            launch_origin TEXT,
            weapon_subtype TEXT,
            engagement_status TEXT,
            air_defense_active BOOLEAN DEFAULT 0,
            multiple_waves BOOLEAN DEFAULT 0,
            wave_number INTEGER DEFAULT 1,
            time_of_day_category TEXT,
            weather_factor TEXT,
            source_reliability TEXT,
            message_context_tags TEXT,
            strategic_priority TEXT,
            civilian_risk_level TEXT,
            event_phase TEXT,
            correlation_group TEXT,
            target_cities_coords TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rule_type TEXT,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            rule_text TEXT,
            rule_json TEXT,
            evidence_count INTEGER DEFAULT 1,
            accuracy_score REAL DEFAULT 1.0,
            is_active BOOLEAN DEFAULT 1,
            last_validated DATETIME
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS error_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT,
            error_type TEXT,
            message TEXT,
            endpoint TEXT,
            context TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT,
            rule_type TEXT,
            rule_text TEXT,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            reason TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS analytics_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            report_date TEXT,
            report_type TEXT,
            summary_text TEXT,
            trajectory_data TEXT,
            launch_data TEXT,
            risk_matrix TEXT,
            generated_by TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS palantir_reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            report_date TEXT,
            threat_assessment_summary TEXT,
            palantir_vectors_json TEXT,
            launch_hubs_json TEXT,
            risk_matrix_json TEXT,
            confidence_index REAL,
            generated_by TEXT
        )
    ''')
    archive_conn.commit()


def smart_local_incremental_backup() -> dict:
    """
    Appends new records from the active database to the permanent smart archive.
    Append-only: never deletes any records from the backup.
    """
    if not os.path.exists(DB_PATH) or os.path.getsize(DB_PATH) == 0:
        return {"status": "skipped", "reason": "empty_source"}

    archive_path = get_archive_db_path()
    added_stats = {}

    try:
        # 1. Initialize archive DB
        archive_conn = sqlite3.connect(archive_path, timeout=30.0)
        archive_conn.execute("PRAGMA journal_mode = WAL")
        init_archive_tables(archive_conn)
        archive_conn.close()

        # 2. Attach archive DB to live DB connection and copy new rows
        src_conn = sqlite3.connect(DB_PATH, timeout=30.0)
        src_conn.execute(f"ATTACH DATABASE '{archive_path}' AS archive_db")

        tables_to_sync = [
            ("threat_history", "INSERT OR IGNORE INTO archive_db.threat_history (timestamp, region, threat_level, threat_type, detail, confidence, is_test) SELECT timestamp, region, threat_level, threat_type, detail, confidence, is_test FROM main.threat_history"),
            ("paired_events", "INSERT OR IGNORE INTO archive_db.paired_events (created_at, region, threat_event_id, telemetry_id, clearing_event_id, lifecycle_status, threat_level, threat_type, confidence_at_set, confidence_at_clear, was_predictive, prediction_accuracy, duration_seconds, gemini_group_id, rules_applied) SELECT created_at, region, threat_event_id, telemetry_id, clearing_event_id, lifecycle_status, threat_level, threat_type, confidence_at_set, confidence_at_clear, was_predictive, prediction_accuracy, duration_seconds, gemini_group_id, rules_applied FROM main.paired_events"),
            ("threat_clearings", "INSERT OR IGNORE INTO archive_db.threat_clearings (timestamp, region, original_threat_event_id, linked_group_id, linked_correlation_group, resolution_type, intercepted_count, total_targets_in_wave, impact_confirmed, damage_assessment, civilian_casualties_reported, infrastructure_hit, air_defense_effectiveness, threat_duration_assessment, prediction_accuracy_hint, was_predictive, original_threat_level, original_threat_type, original_confidence, clearing_confidence, clearing_context_tags, source_reliability, time_of_day_category, clearing_source_channel, clearing_message_text, threat_set_timestamp, threat_duration_seconds, is_test) SELECT timestamp, region, original_threat_event_id, linked_group_id, linked_correlation_group, resolution_type, intercepted_count, total_targets_in_wave, impact_confirmed, damage_assessment, civilian_casualties_reported, infrastructure_hit, air_defense_effectiveness, threat_duration_assessment, prediction_accuracy_hint, was_predictive, original_threat_level, original_threat_type, original_confidence, clearing_confidence, clearing_context_tags, source_reliability, time_of_day_category, clearing_source_channel, clearing_message_text, threat_set_timestamp, threat_duration_seconds, is_test FROM main.threat_clearings"),
            ("telemetry_data", "INSERT OR IGNORE INTO archive_db.telemetry_data (threat_event_id, group_id, attack_vector, target_count, speed_kmh, altitude_category, heading_degrees, distance_to_target_km, launch_origin, weapon_subtype, engagement_status, air_defense_active, multiple_waves, wave_number, time_of_day_category, weather_factor, source_reliability, message_context_tags, strategic_priority, civilian_risk_level, event_phase, correlation_group, target_cities_coords) SELECT threat_event_id, group_id, attack_vector, target_count, speed_kmh, altitude_category, heading_degrees, distance_to_target_km, launch_origin, weapon_subtype, engagement_status, air_defense_active, multiple_waves, wave_number, time_of_day_category, weather_factor, source_reliability, message_context_tags, strategic_priority, civilian_risk_level, event_phase, correlation_group, target_cities_coords FROM main.telemetry_data"),
            ("gemini_rules", "INSERT OR REPLACE INTO archive_db.gemini_rules (id, created_at, updated_at, rule_type, source_region, target_region, threat_type, rule_text, rule_json, evidence_count, accuracy_score, is_active, last_validated) SELECT id, created_at, updated_at, rule_type, source_region, target_region, threat_type, rule_text, rule_json, evidence_count, accuracy_score, is_active, last_validated FROM main.gemini_rules"),
            ("gemini_rules_audit", "INSERT OR IGNORE INTO archive_db.gemini_rules_audit (id, timestamp, action, rule_type, rule_text, source_region, target_region, threat_type, reason) SELECT id, timestamp, action, rule_type, rule_text, source_region, target_region, threat_type, reason FROM main.gemini_rules_audit"),
            ("palantir_reports", "INSERT OR REPLACE INTO archive_db.palantir_reports (id, created_at, report_date, threat_assessment_summary, palantir_vectors_json, launch_hubs_json, risk_matrix_json, confidence_index, generated_by) SELECT id, created_at, report_date, threat_assessment_summary, palantir_vectors_json, launch_hubs_json, risk_matrix_json, confidence_index, generated_by FROM main.palantir_reports"),
            ("analytics_reports", "INSERT OR REPLACE INTO archive_db.analytics_reports (id, created_at, report_date, report_type, summary_text, trajectory_data, launch_data, risk_matrix, generated_by) SELECT id, created_at, report_date, report_type, summary_text, trajectory_data, launch_data, risk_matrix, generated_by FROM main.analytics_reports"),
            ("error_log", "INSERT OR IGNORE INTO archive_db.error_log (id, timestamp, source, error_type, message, endpoint, context) SELECT id, timestamp, source, error_type, message, endpoint, context FROM main.error_log"),
        ]

        total_appended = 0
        for table, query in tables_to_sync:
            try:
                cur = src_conn.execute(query)
                added_stats[table] = cur.rowcount
                if cur.rowcount > 0:
                    total_appended += cur.rowcount
            except Exception as te:
                logger.debug(f"[Smart Backup] Помилка синхронізації таблиці {table}: {te}")

        src_conn.commit()
        src_conn.close()

        # 3. Also update latest full snapshot file
        base_dir = os.path.dirname(DB_PATH) if os.path.dirname(DB_PATH) else "."
        latest_path = os.path.join(base_dir, "backups", "threat_analytics_backup_latest.db")
        
        src_conn = sqlite3.connect(DB_PATH, timeout=30.0)
        dst_conn = sqlite3.connect(latest_path)
        with dst_conn:
            src_conn.backup(dst_conn)
        dst_conn.close()
        src_conn.close()

        if total_appended > 0:
            logger.info(f"💾 [Smart Backup 5m] Успішно дозаписано {total_appended} нових подій у постійний архів ({archive_path}).")
        return {"status": "success", "appended": total_appended, "stats": added_stats}
    except Exception as e:
        logger.error(f"❌ [Smart Backup Error] Помилка розумного бекапу: {e}")
        return {"status": "error", "error": str(e)}


async def periodic_smart_backup_loop():
    """Background task running smart local incremental backups every 5 minutes (300s)."""
    logger.info("🛡️ [Smart Backup Worker] Запущено фоновий розумний бекап кожні 5 хвилин.")
    while True:
        try:
            await asyncio.sleep(300)  # 5 minutes
            await asyncio.to_thread(smart_local_incremental_backup)
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.error(f"⚠️ [Smart Backup Worker] Помилка в циклі: {e}")
