"""
Threat Monitoring Server — FastAPI сервер моніторингу загроз.

Запуск:
    python server.py          # мок-режим (для тестування)
    python server.py --live   # живий режим з Telegram (потрібні ключі)

API:
    GET  /api/threats           — поточний стан загроз для всіх областей
    GET  /api/shelters          — пошук найближчих укриттів за координатами
    POST /api/threats/mock      — встановити загрозу вручну (мок-режим)
    POST /api/threats/scenario  — запустити тестовий сценарій
    POST /api/threats/clear     — очистити всі загрози
"""

import os
import sys
import asyncio
from datetime import datetime, timezone
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import sqlite3
import json
import aiohttp

from mock_mode import MockThreatManager, get_db
from shelter_manager import ShelterManager

try:
    import firebase_admin
    from firebase_admin import credentials
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

# --- База даних Аналітики ---
DB_PATH = "threat_analytics.db"

def init_analytics_db():
    conn = sqlite3.connect(DB_PATH)
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
    # Migrate existing tables — add columns if missing
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN detail TEXT")
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN confidence INTEGER")
    except sqlite3.OperationalError:
        pass  # column already exists
    try:
        cursor.execute("ALTER TABLE threat_history ADD COLUMN is_test BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists
    
    # --- Telemetry Data Table ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS telemetry_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            threat_event_id INTEGER NOT NULL,
            group_id TEXT,
            attack_vector TEXT,
            target_count INTEGER,
            speed_kmh INTEGER,
            altitude_category TEXT,
            heading_degrees INTEGER,
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
            FOREIGN KEY (threat_event_id) REFERENCES threat_history(id)
        )
    ''')
    
    # Indexes for fast aggregations
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_group ON telemetry_data(group_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_vector ON telemetry_data(attack_vector)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_correlation ON telemetry_data(correlation_group)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_telemetry_event ON telemetry_data(threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_history_region_ts ON threat_history(region, timestamp)')
    
    # --- Threat Clearings Table (lifecycle) ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS threat_clearings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            original_threat_event_id INTEGER,
            linked_group_id TEXT,
            linked_correlation_group TEXT,
            resolution_type TEXT DEFAULT 'unknown',
            intercepted_count INTEGER,
            total_targets_in_wave INTEGER,
            impact_confirmed BOOLEAN DEFAULT 0,
            damage_assessment TEXT DEFAULT 'unknown',
            civilian_casualties_reported BOOLEAN DEFAULT 0,
            infrastructure_hit TEXT,
            air_defense_effectiveness TEXT DEFAULT 'unknown',
            threat_duration_assessment TEXT DEFAULT 'unknown',
            prediction_accuracy_hint TEXT DEFAULT 'not_applicable',
            was_predictive BOOLEAN DEFAULT 0,
            original_threat_level TEXT,
            original_threat_type TEXT,
            original_confidence INTEGER,
            clearing_confidence INTEGER,
            clearing_context_tags TEXT,
            source_reliability TEXT DEFAULT 'medium',
            time_of_day_category TEXT DEFAULT 'unknown',
            clearing_source_channel TEXT,
            clearing_message_text TEXT,
            threat_set_timestamp DATETIME,
            threat_duration_seconds INTEGER,
            is_test BOOLEAN DEFAULT 0,
            FOREIGN KEY (original_threat_event_id) REFERENCES threat_history(id)
        )
    ''')
    
    try:
        cursor.execute("ALTER TABLE threat_clearings ADD COLUMN is_test BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass  # column already exists

    # Indexes for clearings
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_region ON threat_clearings(region)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_group ON threat_clearings(linked_group_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_original ON threat_clearings(original_threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_resolution ON threat_clearings(resolution_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_prediction ON threat_clearings(prediction_accuracy_hint)')
    
    # --- Self-Learning Rules Table ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            rule_type TEXT NOT NULL,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            rule_text TEXT NOT NULL,
            rule_json TEXT,
            evidence_count INTEGER DEFAULT 1,
            accuracy_score REAL DEFAULT 0.5,
            is_active BOOLEAN DEFAULT 1,
            last_validated DATETIME
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_type ON gemini_rules(rule_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_active ON gemini_rules(is_active)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_regions ON gemini_rules(source_region, target_region)')
    
    # --- Paired Events (Lifecycle) Table ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS paired_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            region TEXT NOT NULL,
            threat_event_id INTEGER NOT NULL,
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
            rules_applied TEXT,
            FOREIGN KEY (threat_event_id) REFERENCES threat_history(id),
            FOREIGN KEY (clearing_event_id) REFERENCES threat_clearings(id)
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_region ON paired_events(region)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_status ON paired_events(lifecycle_status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_threat ON paired_events(threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_paired_group ON paired_events(gemini_group_id)')
    
    # --- Error Log Table ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS error_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            source TEXT NOT NULL,
            error_type TEXT NOT NULL,
            message TEXT NOT NULL,
            endpoint TEXT,
            context TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_source ON error_log(source)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_type ON error_log(error_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_error_ts ON error_log(timestamp)')
    
    # --- Gemini Rules Audit Log ---
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS gemini_rules_audit (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT NOT NULL,
            rule_type TEXT,
            rule_text TEXT,
            source_region TEXT,
            target_region TEXT,
            threat_type TEXT,
            reason TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_audit_ts ON gemini_rules_audit(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_audit_action ON gemini_rules_audit(action)')

    conn.commit()
    conn.close()
    print("💾 Аналітична БД ініціалізована (threat_history + telemetry_data + threat_clearings + gemini_rules + paired_events + error_log + gemini_rules_audit)")


def log_error_to_db(source: str, message: str, endpoint: str = None, context: str = None):
    """Log an error event to the error_log table. Source: 'server', 'firebase', 'gemini'."""
    error_msg = str(message)
    # Classify error type
    if "429" in error_msg or "Quota" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower():
        error_type = "429_rate_limit"
    elif "500" in error_msg or "Internal" in error_msg:
        error_type = "500_server"
    elif "timeout" in error_msg.lower() or "Timeout" in error_msg:
        error_type = "timeout"
    elif "connection" in error_msg.lower() or "ConnectionError" in error_msg:
        error_type = "connection"
    elif "auth" in error_msg.lower() or "permission" in error_msg.lower() or "403" in error_msg:
        error_type = "auth"
    else:
        error_type = "general"
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO error_log (source, error_type, message, endpoint, context) VALUES (?, ?, ?, ?, ?)",
            (source, error_type, error_msg[:2000], endpoint, context)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # Don't recurse on logging failure


def log_rule_audit_to_db(action: str, rule_type: str = None, rule_text: str = None,
                          source_region: str = None, target_region: str = None,
                          threat_type: str = None, reason: str = None):
    """Log a Gemini rule addition/removal/deactivation to the audit table."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (action, rule_type, rule_text[:1000] if rule_text else None, source_region, target_region, threat_type, reason)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def log_threat_to_db(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False, rules_applied: list = None, is_predictive: bool = False):
    """Log threat event and its telemetry to SQLite. Returns the threat_event_id.
    Also creates a paired_event record for lifecycle tracking."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO threat_history (region, threat_level, threat_type, detail, confidence, is_test) VALUES (?, ?, ?, ?, ?, ?)",
            (region, level, threat_type, detail, confidence, 1 if is_test else 0)
        )
        event_id = cursor.lastrowid
        
        telemetry_id = None
        group_id = None
        
        # Insert telemetry if provided
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
                    event_phase, correlation_group
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                telemetry.get("correlation_group")
            ))
            telemetry_id = cursor.lastrowid
        
        # Create paired_event for lifecycle tracking (only for non-none threats)
        if level != "none" and event_id:
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

def log_threat_to_firestore(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False):
    """Log threat event to Firebase Firestore with retry on quota errors."""
    db = get_db()
    if not db:
        return
    import time
    from datetime import datetime, timezone
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
                wait = (2 ** attempt) * 5  # 5s, 10s
                print(f"⚠️ Firestore quota hit writing history for {region}, retry {attempt+1}/{max_retries} in {wait}s")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, attempt={attempt+1}")
                time.sleep(wait)
            else:
                print(f"⚠️ Помилка запису історії в Firestore: {e}")
                log_error_to_db("firebase", str(e), endpoint="log_threat_to_firestore", context=f"region={region}, final_failure")
                return
    print(f"❌ Firestore history write failed after {max_retries} retries for {region}")

def log_clearing_to_db(region: str, clearing_telemetry: dict = None,
                       source_channel: str = None, message_text: str = None,
                       clearing_confidence: int = None, was_predictive: bool = False,
                       is_test: bool = False):
    """Log threat clearing event with full lifecycle data linked to original threat.
    Also closes the corresponding paired_event and updates prediction accuracy."""
    if not clearing_telemetry:
        clearing_telemetry = {}
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Look up the most recent active threat for this region
        original_event_id = None
        original_level = None
        original_type = None
        original_confidence = None
        threat_set_ts = None
        threat_duration_sec = None
        
        # First try by linked_group_id if available
        linked_gid = clearing_telemetry.get("linked_group_id")
        if linked_gid:
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN telemetry_data td ON th.id = td.threat_event_id
                WHERE th.region = ? AND td.group_id = ?
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region, linked_gid))
        else:
            # Fallback: find the most recent non-none threat for this region
            cursor.execute('''
                SELECT id, timestamp, threat_level, threat_type, confidence
                FROM threat_history
                WHERE region = ? AND threat_level != 'none'
                ORDER BY timestamp DESC LIMIT 1
            ''', (region,))
        
        row = cursor.fetchone()
        if row:
            original_event_id = row["id"]
            original_level = row["threat_level"]
            original_type = row["threat_type"]
            original_confidence = row["confidence"]
            threat_set_ts = row["timestamp"]
            # Calculate duration in seconds
            try:
                from datetime import datetime, timezone
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
        
        # --- Close the corresponding paired_event ---
        prediction_accuracy = clearing_telemetry.get("prediction_accuracy_hint", "not_applicable")
        if original_event_id:
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
        
        conn.commit()
        conn.close()
        
        # Log details
        res_type = clearing_telemetry.get("resolution_type", "unknown")
        pred_hint = clearing_telemetry.get("prediction_accuracy_hint", "n/a")
        dur = f"{threat_duration_sec}с" if threat_duration_sec else "?"
        print(f"📊 [Clearing DB] {region}: тип={res_type}, предикція={pred_hint}, тривалість={dur}, linked_event={original_event_id}")
        
        return clearing_id
    except Exception as e:
        print(f"⚠️ Помилка запису clearing в БД: {e}")
        log_error_to_db("server", str(e), endpoint="log_clearing_to_db", context=f"region={region}")
        return None


# Глобальний менеджер загроз (in-memory)
threat_manager = MockThreatManager()
shelter_manager = ShelterManager()
telegram_monitor = None
is_live_mode = "--live" in sys.argv or os.environ.get("LIVE_MODE", "false").lower() == "true"

# Track last logged threat states to avoid duplicate logging and properly detect changes
last_logged_states = {}  # region -> (level, is_active, threat_type)

# Firestore history batch buffer — collects writes during _batch_mode for one flush
_history_batch_buffer = []

main_loop = None

def validate_prediction_on_alarm(region: str):
    """When an official alarm activates for a region, check if Gemini had a
    predictive (yellow) threat for it and mark the prediction as 'confirmed'.
    This feeds the Rules Learner with validation data."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        # Find active predictive paired_events for this region
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

def flush_history_batch():
    """Flush all buffered Firestore history writes in a single batch operation."""
    global _history_batch_buffer
    if not _history_batch_buffer:
        return
    
    db = get_db()
    if not db:
        _history_batch_buffer.clear()
        return
    
    import time
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


def safe_run_task(coro):
    """Safely schedules a coroutine from any thread (e.g. background threadpool)
    in the main asyncio event loop."""
    global main_loop
    if main_loop and main_loop.is_running():
        asyncio.run_coroutine_threadsafe(coro, main_loop)
    else:
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            # Fallback if no loop is running in current context (unlikely but safe)
            new_loop = asyncio.new_event_loop()
            asyncio.set_event_loop(new_loop)
            new_loop.run_until_complete(coro)
            new_loop.close()

def on_threat_changed(region, state, telemetry=None, rules_applied=None):
    global last_logged_states, _history_batch_buffer
    prev_level, prev_active, prev_type = last_logged_states.get(region, ("none", False, None))
    
    is_batch = getattr(threat_manager, '_batch_mode', False)
    
    # 1. Official air alarm status change logging
    if prev_active != state.is_active:
        log_level = "high" if state.is_active else "none"
        detail = "Повітряна тривога" if state.is_active else "Відбій повітряної тривоги"
        safe_run_task(asyncio.to_thread(log_threat_to_db, region, log_level, "official_alarm", detail))
        
        # Validate Gemini predictions when official alarm turns ON
        if state.is_active:
            safe_run_task(asyncio.to_thread(validate_prediction_on_alarm, region))
        
        if is_batch:
            # Buffer for batch flush
            from datetime import datetime, timezone
            import time
            _history_batch_buffer.append({
                "id": int(time.time() * 1000),
                "region": region,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "threat_level": log_level,
                "threat_type": "official_alarm",
                "detail": detail,
                "confidence": None,
                "is_test": state.is_test
            })
        else:
            safe_run_task(asyncio.to_thread(log_threat_to_firestore, region, log_level, "official_alarm", detail, is_test=state.is_test))
        
    # 2. AI/Telegram threat level change logging
    if prev_level != state.level:
        current_type = state.threat_type
        if (current_type and current_type != "official_alarm") or (prev_type and prev_type != "official_alarm" and state.level == "none"):
            if state.level != "none":
                safe_run_task(asyncio.to_thread(log_threat_to_db, region, state.level, current_type, state.detail, state.confidence, telemetry=telemetry, rules_applied=rules_applied, is_predictive=getattr(state, 'is_predictive', False)))
                if is_batch:
                    from datetime import datetime, timezone
                    import time
                    doc_data = {
                        "id": int(time.time() * 1000),
                        "region": region,
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "threat_level": state.level,
                        "threat_type": current_type,
                        "detail": state.detail,
                        "confidence": state.confidence,
                        "is_test": state.is_test
                    }
                    if telemetry:
                        doc_data["telemetry"] = telemetry
                    _history_batch_buffer.append(doc_data)
                else:
                    safe_run_task(asyncio.to_thread(log_threat_to_firestore, region, state.level, current_type, state.detail, state.confidence, telemetry=telemetry, is_test=state.is_test))
            elif prev_level != "none":
                # Threat has cleared
                safe_run_task(asyncio.to_thread(log_threat_to_db, region, "none", prev_type, "Відбій загрози"))
                if is_batch:
                    from datetime import datetime, timezone
                    import time
                    _history_batch_buffer.append({
                        "id": int(time.time() * 1000),
                        "region": region,
                        "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                        "threat_level": "none",
                        "threat_type": prev_type,
                        "detail": "Відбій загрози",
                        "confidence": None,
                        "is_test": state.is_test
                    })
                else:
                    safe_run_task(asyncio.to_thread(log_threat_to_firestore, region, "none", prev_type, "Відбій загрози", is_test=state.is_test))
            
    last_logged_states[region] = (state.level, state.is_active, state.threat_type)

threat_manager.on_change = on_threat_changed

def init_firebase():
    if not HAS_FIREBASE:
        print("⚠️ Попередження: Бібліотека firebase-admin не встановлена. Сповіщення не надсилатимуться.")
        return
    
    # Пріоритет 1: шлях або JSON-рядок зі змінної оточення
    # Пріоритет 2: файл у папці threat_server
    # Пріоритет 3: файл у корені
    cred_env = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    
    if cred_env:
        # Спробуємо розпарсити як JSON-рядок
        if cred_env.strip().startswith("{"):
            try:
                import json
                cred_dict = json.loads(cred_env)
                cred = credentials.Certificate(cred_dict)
                firebase_admin.initialize_app(cred)
                print("🔥 Firebase Admin SDK ініціалізовано за допомогою JSON-рядка з змінної оточення.")
                return
            except Exception as e:
                print(f"⚠️ Помилка ініціалізації Firebase за JSON-рядком: {e}")
        
        # Якщо це не JSON, спробуємо як шлях до файлу
        if os.path.exists(cred_env):
            try:
                cred = credentials.Certificate(cred_env)
                firebase_admin.initialize_app(cred)
                print(f"🔥 Firebase Admin SDK ініціалізовано за допомогою файлу: {cred_env}")
                return
            except Exception as e:
                print(f"⚠️ Помилка ініціалізації Firebase за файлом ключів: {e}")

    # Fallback до файлів за замовчуванням
    default_paths = ["threat_server/firebase-credentials.json", "firebase-credentials.json"]
    for path in default_paths:
        if os.path.exists(path):
            try:
                cred = credentials.Certificate(path)
                firebase_admin.initialize_app(cred)
                print(f"🔥 Firebase Admin SDK ініціалізовано за допомогою дефолтного файлу: {path}")
                return
            except Exception as e:
                print(f"⚠️ Помилка ініціалізації Firebase за дефолтним файлом {path}: {e}")

    # Останній варіант - спробувати замовчування
    try:
        firebase_admin.initialize_app()
        print("🔥 Firebase Admin SDK ініціалізовано (Default Credentials / Env).")
    except Exception as e:
        print("⚠️ Попередження: Не знайдено credentials. Сповіщення у фоні не працюватимуть.")

aerial_alerts_task = None

async def poll_aerial_alerts():
    """Фонова задача для опитування офіційного API тривог (alerts.in.ua або ubilling)."""
    token = os.environ.get("ALERTS_TOKEN")
    
    if token:
        print("⏳ Запуск фонового опитування офіційних тривог з alerts.in.ua...")
        url = "https://api.alerts.in.ua/v1/alerts/active.json"
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "SirenUA-ThreatServer/1.0"
        }
    else:
        print("⏳ Запуск фонового опитування офіційних тривог з ubilling (резервний режим, ALERTS_TOKEN не знайдено)...")
        url = "https://ubilling.net.ua/aerialalerts/"
        headers = {"User-Agent": "SirenUA-ThreatServer/1.0"}

    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=8.0) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if token:
                            # Парсинг формату alerts.in.ua
                            active_alerts = data.get("alerts", [])
                            active_regions = set()
                            
                            for alert in active_alerts:
                                loc_type = alert.get("location_type")
                                loc_title = alert.get("location_title")
                                if loc_title:
                                    if loc_type == "oblast" or loc_title == "м. Київ":
                                        active_regions.add(loc_title)
                            
                            from mock_mode import ALL_REGIONS
                            for region_name in ALL_REGIONS.keys():
                                is_active = region_name in active_regions
                                threat_manager.set_alarm_active(region_name, is_active)
                        else:
                            # Резервний парсинг ubilling
                            states = data.get("states", {})
                            for region_name, state_data in states.items():
                                is_active = state_data.get("alertnow", False)
                                threat_manager.set_alarm_active(region_name, is_active)
                    else:
                        print(f"⚠️ Помилка опитування тривог (URL: {url}): HTTP статус {response.status}")
        except Exception as e:
            print(f"⚠️ Помилка під час опитування тривог (URL: {url}): {e}")
            log_error_to_db("server", str(e), endpoint="poll_aerial_alerts", context=f"url={url}")
        
        
        sleep_interval = 15.0 if token else 10.0
        await asyncio.sleep(sleep_interval)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка Telegram моніторингу."""
    global telegram_monitor, aerial_alerts_task, main_loop
    main_loop = asyncio.get_running_loop()
    
    # Ініціалізація Firebase Cloud Messaging
    init_firebase()
    
    # Запуск воркера черги FCM повідомлень
    try:
        from mock_mode import start_fcm_worker
        await start_fcm_worker()
    except Exception as e:
        print(f"⚠️ Помилка запуску FCM воркера: {e}")
    
    # Ініціалізація БД аналітики
    init_analytics_db()

    # Завантаження збереженого стану загроз (асинхронно у фоновому пулі)
    try:
        await asyncio.to_thread(threat_manager.load_from_db)
        # Ініціалізація відслідковуваного стану після завантаження
        for r, s in threat_manager.threats.items():
            last_logged_states[r] = (s.level, s.is_active, s.threat_type)
    except Exception as e:
        print(f"⚠️ Помилка асинхронного завантаження стану загроз: {e}")

    # Завантаження бази укриттів з OpenStreetMap у фоні (не блокує стартап API)
    async def load_shelters_background():
        try:
            await shelter_manager.load()
            await shelter_manager.start_refresh_loop()
        except Exception as e:
            print(f"⚠️ Помилка завантаження укриттів: {e}")
            
    asyncio.create_task(load_shelters_background())
    
    # Запуск фонового опитування офіційного API
    aerial_alerts_task = asyncio.create_task(poll_aerial_alerts())

    if is_live_mode:
        from telegram_monitor import TelegramThreatMonitor
        telegram_monitor = TelegramThreatMonitor(threat_manager)
        await telegram_monitor.start()
        print("🟢 Сервер запущено в LIVE режимі (Telegram)")
    else:
        print("🟡 Сервер запущено в MOCK режимі (тестування)")
    
    yield
    
    # Зупинка фонового опитування
    if aerial_alerts_task:
        aerial_alerts_task.cancel()
        try:
            await aerial_alerts_task
        except asyncio.CancelledError:
            pass
            
    await shelter_manager.stop()
    if telegram_monitor:
        await telegram_monitor.stop()


app = FastAPI(
    title="SirenUA Threat Monitor",
    description="API моніторингу рівня загрози для областей України",
    version="1.0.0",
    lifespan=lifespan,
)

# Дозвіл CORS для iOS додатку
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- Pydantic моделі ---

class ThreatSetRequest(BaseModel):
    region: str
    level: str  # none, low, medium, high, critical
    threat_type: Optional[str] = None
    detail: Optional[str] = None


class ShelterUploadItem(BaseModel):
    name: Optional[str] = None
    address: Optional[str] = None
    lat: float
    lon: float
    type: str = "bomb_shelter"
    capacity: Optional[int] = None
    accessible: bool = False


class ShelterUploadRequest(BaseModel):
    shelters: list[ShelterUploadItem]


class ScenarioRequest(BaseModel):
    scenario: str  # mig_takeoff, shaheds_south, cruise_missiles_west, massive_attack, ballistic_kharkiv


class TelegramTestRequest(BaseModel):
    text: str
    channel: str = "kpszsu"


# --- API Endpoints ---

@app.get("/")
async def root():
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.1.0",
        "status": "running",
        "mode": "live" if is_live_mode else "mock",
        "telegram_connected": telegram_monitor is not None and telegram_monitor.is_running,
        "shelters_loaded": shelter_manager.total_count,
    }


@app.get("/api/threats")
async def get_threats():
    """Повертає поточний стан загроз для всіх областей."""
    return {
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "live" if is_live_mode else "mock",
        "threats": threat_manager.get_all_threats(),
    }


@app.get("/api/gemini/status")
async def get_gemini_status():
    """Повертає поточний статус ШІ-аналізатора Gemini."""
    if not is_live_mode:
        return {"status": "mock", "error": "Сервер працює в тестовому (MOCK) режимі"}
        
    if telegram_monitor is None or telegram_monitor.analyzer is None:
        return {"status": "offline", "error": "Моніторинг не запущено"}
        
    analyzer = telegram_monitor.analyzer
    if not analyzer.is_configured:
        return {"status": "offline", "error": "API-ключ GEMINI_API_KEY не налаштовано"}
        
    if analyzer.last_error:
        return {"status": "error", "error": analyzer.last_error}
        
    return {"status": "ok", "error": None}

@app.get("/api/analytics/heatmap")
async def get_heatmap_data(days: int = 7):
    """Повертає історичні дані загроз для побудови теплової карти."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Запит рахує кількість тривог по регіонах за останні `days` днів
        cursor.execute('''
            SELECT region, COUNT(*) as threat_count, MAX(timestamp) as last_threat 
            FROM threat_history 
            WHERE timestamp >= datetime('now', ?) 
            GROUP BY region
            ORDER BY threat_count DESC
        ''', (f'-{days} days',))
        
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "days": days,
            "data": [dict(row) for row in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/telemetry/{region}")
async def get_region_telemetry(region: str, limit: int = 50, days: int = 30):
    """Повна телеметрія для регіону з групуванням."""
    from urllib.parse import unquote
    region = unquote(region)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT th.id, th.timestamp, th.region, th.threat_level, th.threat_type,
                   th.detail, th.confidence,
                   td.group_id, td.attack_vector, td.target_count, td.speed_kmh,
                   td.altitude_category, td.heading_degrees, td.distance_to_target_km,
                   td.launch_origin, td.weapon_subtype, td.engagement_status,
                   td.air_defense_active, td.multiple_waves, td.wave_number,
                   td.time_of_day_category, td.weather_factor, td.source_reliability,
                   td.message_context_tags, td.strategic_priority, td.civilian_risk_level,
                   td.event_phase, td.correlation_group
            FROM threat_history th
            LEFT JOIN telemetry_data td ON th.id = td.threat_event_id
            WHERE th.region = ? AND th.timestamp >= datetime('now', ?)
            ORDER BY th.timestamp DESC
            LIMIT ?
        ''', (region, f'-{days} days', min(limit, 200)))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            if event.get("message_context_tags"):
                try:
                    event["message_context_tags"] = json.loads(event["message_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    event["message_context_tags"] = []
            events.append(event)
        
        return {
            "region": region,
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/groups")
async def get_attack_groups(days: int = 7, limit: int = 50):
    """Список атакових хвиль/груп за останні N днів."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                td.group_id,
                td.correlation_group,
                td.attack_vector,
                COUNT(DISTINCT th.id) as event_count,
                COUNT(DISTINCT th.region) as region_count,
                GROUP_CONCAT(DISTINCT th.region) as regions,
                MIN(th.timestamp) as first_seen,
                MAX(th.timestamp) as last_seen,
                AVG(th.confidence) as avg_confidence,
                AVG(td.speed_kmh) as avg_speed,
                SUM(td.target_count) as total_targets,
                MAX(td.wave_number) as max_wave,
                GROUP_CONCAT(DISTINCT th.threat_type) as threat_types
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.group_id IS NOT NULL
              AND th.timestamp >= datetime('now', ?)
            GROUP BY td.group_id
            ORDER BY MAX(th.timestamp) DESC
            LIMIT ?
        ''', (f'-{days} days', min(limit, 100)))
        
        rows = cursor.fetchall()
        conn.close()
        
        groups = []
        for row in rows:
            group = dict(row)
            group["regions"] = group["regions"].split(",") if group["regions"] else []
            group["threat_types"] = group["threat_types"].split(",") if group["threat_types"] else []
            if group["avg_confidence"]:
                group["avg_confidence"] = round(group["avg_confidence"], 1)
            if group["avg_speed"]:
                group["avg_speed"] = round(group["avg_speed"], 1)
            groups.append(group)
        
        return {
            "days": days,
            "total_groups": len(groups),
            "groups": groups
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/stats")
async def get_analytics_stats(days: int = 7):
    """Агреговані показники за останні N днів."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Average speed by threat type
        cursor.execute('''
            SELECT th.threat_type, 
                   AVG(td.speed_kmh) as avg_speed,
                   COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.speed_kmh IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY th.threat_type
        ''', (day_filter,))
        speed_by_type = [{"type": r["threat_type"], "avg_speed": round(r["avg_speed"], 1), "count": r["count"]} for r in cursor.fetchall()]
        
        # 2. Top attack vectors
        cursor.execute('''
            SELECT td.attack_vector, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.attack_vector != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.attack_vector
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        top_vectors = [dict(r) for r in cursor.fetchall()]
        
        # 3. Average confidence by threat type
        cursor.execute('''
            SELECT threat_type, AVG(confidence) as avg_confidence, COUNT(*) as count
            FROM threat_history
            WHERE confidence IS NOT NULL AND timestamp >= datetime('now', ?)
            GROUP BY threat_type
        ''', (day_filter,))
        confidence_by_type = [{"type": r["threat_type"], "avg_confidence": round(r["avg_confidence"], 1), "count": r["count"]} for r in cursor.fetchall()]
        
        # 4. Hourly distribution
        cursor.execute('''
            SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY hour
            ORDER BY hour
        ''', (day_filter,))
        hourly_histogram = [dict(r) for r in cursor.fetchall()]
        
        # 5. Top targeted regions
        cursor.execute('''
            SELECT region, COUNT(*) as count, 
                   AVG(confidence) as avg_confidence
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY region
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        top_regions = [{"region": r["region"], "count": r["count"], "avg_confidence": round(r["avg_confidence"], 1) if r["avg_confidence"] else None} for r in cursor.fetchall()]
        
        # 6. Engagement status distribution (interception rate)
        cursor.execute('''
            SELECT td.engagement_status, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.engagement_status != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.engagement_status
            ORDER BY count DESC
        ''', (day_filter,))
        engagement_stats = [dict(r) for r in cursor.fetchall()]
        
        # 7. Wave frequency
        cursor.execute('''
            SELECT COUNT(DISTINCT td.group_id) as total_waves,
                   AVG(td.wave_number) as avg_waves_per_attack
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.group_id IS NOT NULL AND th.timestamp >= datetime('now', ?)
        ''', (day_filter,))
        wave_row = cursor.fetchone()
        wave_stats = {
            "total_waves": wave_row["total_waves"] if wave_row else 0,
            "avg_waves_per_attack": round(wave_row["avg_waves_per_attack"], 1) if wave_row and wave_row["avg_waves_per_attack"] else 0
        }
        
        # 8. Total events
        cursor.execute('''
            SELECT COUNT(*) as total FROM threat_history WHERE timestamp >= datetime('now', ?)
        ''', (day_filter,))
        total = cursor.fetchone()["total"]
        
        conn.close()
        
        return {
            "days": days,
            "total_events": total,
            "avg_speed_by_type": speed_by_type,
            "top_attack_vectors": top_vectors,
            "avg_confidence_by_type": confidence_by_type,
            "hourly_histogram": hourly_histogram,
            "top_targeted_regions": top_regions,
            "engagement_stats": engagement_stats,
            "wave_stats": wave_stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/patterns")
async def get_patterns(days: int = 14):
    """Виявлені патерни атак (час доби, напрямки, типи)."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Time-of-day pattern
        cursor.execute('''
            SELECT td.time_of_day_category, th.threat_type, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.time_of_day_category != 'unknown' AND th.timestamp >= datetime('now', ?)
            GROUP BY td.time_of_day_category, th.threat_type
            ORDER BY count DESC
        ''', (day_filter,))
        time_patterns = [dict(r) for r in cursor.fetchall()]
        
        # 2. Launch origin frequency
        cursor.execute('''
            SELECT td.launch_origin, COUNT(*) as count, 
                   GROUP_CONCAT(DISTINCT th.threat_type) as threat_types
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.launch_origin IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.launch_origin
            ORDER BY count DESC LIMIT 10
        ''', (day_filter,))
        origin_patterns = []
        for r in cursor.fetchall():
            d = dict(r)
            d["threat_types"] = d["threat_types"].split(",") if d["threat_types"] else []
            origin_patterns.append(d)
        
        # 3. Strategic priority targets
        cursor.execute('''
            SELECT td.strategic_priority, COUNT(*) as count,
                   GROUP_CONCAT(DISTINCT th.region) as regions
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.strategic_priority IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.strategic_priority
            ORDER BY count DESC
        ''', (day_filter,))
        priority_patterns = []
        for r in cursor.fetchall():
            d = dict(r)
            d["regions"] = d["regions"].split(",") if d["regions"] else []
            priority_patterns.append(d)
        
        # 4. Day-of-week distribution
        cursor.execute('''
            SELECT CAST(strftime('%w', timestamp) AS INTEGER) as day_of_week, COUNT(*) as count
            FROM threat_history
            WHERE timestamp >= datetime('now', ?)
            GROUP BY day_of_week
            ORDER BY day_of_week
        ''', (day_filter,))
        day_names = ['Неділя', 'Понеділок', 'Вівторок', 'Середа', 'Четвер', "П'ятниця", 'Субота']
        dow_dist = [{"day": day_names[r["day_of_week"]], "day_number": r["day_of_week"], "count": r["count"]} for r in cursor.fetchall()]
        
        # 5. Civilian risk level distribution
        cursor.execute('''
            SELECT td.civilian_risk_level, COUNT(*) as count
            FROM telemetry_data td
            JOIN threat_history th ON td.threat_event_id = th.id
            WHERE td.civilian_risk_level IS NOT NULL AND th.timestamp >= datetime('now', ?)
            GROUP BY td.civilian_risk_level
            ORDER BY count DESC
        ''', (day_filter,))
        risk_dist = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
        return {
            "days": days,
            "time_of_day_patterns": time_patterns,
            "launch_origin_patterns": origin_patterns,
            "strategic_priority_patterns": priority_patterns,
            "day_of_week_distribution": dow_dist,
            "civilian_risk_distribution": risk_dist
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/lifecycle/{region}")
async def get_lifecycle_data(region: str, days: int = 30, limit: int = 50):
    """Повний lifecycle загроз для регіону: встановлення → зняття з телеметрією обох подій."""
    from urllib.parse import unquote
    region = unquote(region)
    
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT 
                tc.id as clearing_id,
                tc.timestamp as clearing_timestamp,
                tc.region,
                tc.original_threat_event_id,
                tc.linked_group_id,
                tc.linked_correlation_group,
                tc.resolution_type,
                tc.intercepted_count,
                tc.total_targets_in_wave,
                tc.impact_confirmed,
                tc.damage_assessment,
                tc.civilian_casualties_reported,
                tc.infrastructure_hit,
                tc.air_defense_effectiveness,
                tc.threat_duration_assessment,
                tc.prediction_accuracy_hint,
                tc.was_predictive,
                tc.original_threat_level,
                tc.original_threat_type,
                tc.original_confidence,
                tc.clearing_confidence,
                tc.clearing_context_tags,
                tc.source_reliability,
                tc.time_of_day_category,
                tc.clearing_source_channel,
                tc.threat_set_timestamp,
                tc.threat_duration_seconds
            FROM threat_clearings tc
            WHERE tc.region = ? AND tc.timestamp >= datetime('now', ?)
            ORDER BY tc.timestamp DESC
            LIMIT ?
        ''', (region, f'-{days} days', min(limit, 200)))
        
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            if event.get("clearing_context_tags"):
                try:
                    event["clearing_context_tags"] = json.loads(event["clearing_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    event["clearing_context_tags"] = []
            events.append(event)
        
        return {
            "region": region,
            "count": len(events),
            "lifecycle_events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/predictions")
async def get_prediction_accuracy(days: int = 30):
    """Валідація точності предиктивних (жовтих) регіонів — ключова аналітика для покращення моделі."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # 1. Overall prediction accuracy
        cursor.execute('''
            SELECT 
                prediction_accuracy_hint,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY prediction_accuracy_hint
            ORDER BY count DESC
        ''', (day_filter,))
        accuracy_dist = [dict(r) for r in cursor.fetchall()]
        
        # 2. Prediction accuracy by region
        cursor.execute('''
            SELECT 
                region,
                prediction_accuracy_hint,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY region, prediction_accuracy_hint
            ORDER BY region, count DESC
        ''', (day_filter,))
        by_region_raw = cursor.fetchall()
        
        region_accuracy = {}
        for r in by_region_raw:
            rn = r["region"]
            if rn not in region_accuracy:
                region_accuracy[rn] = {"region": rn, "predictions": [], "total": 0}
            region_accuracy[rn]["predictions"].append({
                "hint": r["prediction_accuracy_hint"],
                "count": r["count"]
            })
            region_accuracy[rn]["total"] += r["count"]
        
        # 3. Resolution type distribution for predictive regions
        cursor.execute('''
            SELECT 
                resolution_type,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND timestamp >= datetime('now', ?)
            GROUP BY resolution_type
            ORDER BY count DESC
        ''', (day_filter,))
        pred_resolution_dist = [dict(r) for r in cursor.fetchall()]
        
        # 4. Air defense effectiveness for predictive regions
        cursor.execute('''
            SELECT 
                air_defense_effectiveness,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND air_defense_effectiveness != 'unknown'
              AND timestamp >= datetime('now', ?)
            GROUP BY air_defense_effectiveness
            ORDER BY count DESC
        ''', (day_filter,))
        pred_ad_eff = [dict(r) for r in cursor.fetchall()]
        
        # 5. Average threat duration for confirmed vs overestimated predictions
        cursor.execute('''
            SELECT 
                prediction_accuracy_hint,
                AVG(threat_duration_seconds) as avg_duration_sec,
                COUNT(*) as count
            FROM threat_clearings
            WHERE was_predictive = 1 AND threat_duration_seconds IS NOT NULL
              AND timestamp >= datetime('now', ?)
            GROUP BY prediction_accuracy_hint
        ''', (day_filter,))
        duration_by_accuracy = [dict(r) for r in cursor.fetchall()]
        
        # 6. Total stats
        cursor.execute('''
            SELECT 
                COUNT(*) as total_clearings,
                SUM(CASE WHEN was_predictive = 1 THEN 1 ELSE 0 END) as predictive_clearings,
                SUM(CASE WHEN was_predictive = 0 THEN 1 ELSE 0 END) as direct_clearings,
                SUM(CASE WHEN impact_confirmed = 1 THEN 1 ELSE 0 END) as total_impacts,
                SUM(CASE WHEN civilian_casualties_reported = 1 THEN 1 ELSE 0 END) as civilian_incidents,
                AVG(threat_duration_seconds) as avg_duration_sec
            FROM threat_clearings
            WHERE timestamp >= datetime('now', ?)
        ''', (day_filter,))
        totals = dict(cursor.fetchone())
        if totals.get("avg_duration_sec"):
            totals["avg_duration_sec"] = round(totals["avg_duration_sec"], 1)
        
        conn.close()
        
        return {
            "days": days,
            "totals": totals,
            "prediction_accuracy_distribution": accuracy_dist,
            "prediction_accuracy_by_region": list(region_accuracy.values()),
            "predictive_resolution_types": pred_resolution_dist,
            "predictive_air_defense_effectiveness": pred_ad_eff,
            "avg_duration_by_accuracy": duration_by_accuracy
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/rules")
async def get_rules(active_only: bool = True, rule_type: str = None, limit: int = 50):
    """Список правил самонавчання Gemini."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM gemini_rules WHERE 1=1"
        params = []
        
        if active_only:
            query += " AND is_active = 1"
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        
        query += " ORDER BY evidence_count DESC, accuracy_score DESC LIMIT ?"
        params.append(min(limit, 200))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        rules = []
        for row in rows:
            rule = dict(row)
            if rule.get("rule_json"):
                try:
                    rule["rule_json"] = json.loads(rule["rule_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
            rules.append(rule)
        
        return {
            "total": len(rules),
            "active_only": active_only,
            "rules": rules
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/analytics/paired-events")
async def get_paired_events(region: str = None, status: str = None, days: int = 7, limit: int = 50):
    """Спарені події (lifecycle): загроза → телеметрія → clearing."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = """
            SELECT pe.*, 
                   th.timestamp as threat_timestamp,
                   th.detail as threat_detail,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type,
                   tc.air_defense_effectiveness,
                   tc.clearing_context_tags
            FROM paired_events pe
            LEFT JOIN threat_history th ON pe.threat_event_id = th.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.created_at >= datetime('now', ?)
        """
        params = [f'-{days} days']
        
        if region:
            from urllib.parse import unquote
            query += " AND pe.region = ?"
            params.append(unquote(region))
        if status:
            query += " AND pe.lifecycle_status = ?"
            params.append(status)
        
        query += " ORDER BY pe.created_at DESC LIMIT ?"
        params.append(min(limit, 200))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            if event.get("clearing_context_tags"):
                try:
                    event["clearing_context_tags"] = json.loads(event["clearing_context_tags"])
                except (json.JSONDecodeError, TypeError):
                    pass
            if event.get("rules_applied"):
                try:
                    event["rules_applied"] = json.loads(event["rules_applied"])
                except (json.JSONDecodeError, TypeError):
                    pass
            events.append(event)
        
        return {
            "total": len(events),
            "days": days,
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/analytics/rules/rebuild")
async def rebuild_rules():
    """Примусовий перерахунок правил самонавчання на основі paired_events."""
    try:
        # Try through active telegram_monitor if running
        if telegram_monitor and hasattr(telegram_monitor, 'analyzer') and telegram_monitor.analyzer:
            count = await asyncio.to_thread(telegram_monitor.analyzer.run_rules_learner)
            return {"status": "ok", "rules_updated": count}
        
        # Fallback: create analyzer on the fly
        from gemini_analyzer import GeminiThreatAnalyzer
        analyzer = GeminiThreatAnalyzer(error_callback=log_error_to_db, rule_audit_callback=log_rule_audit_to_db)
        count = await asyncio.to_thread(analyzer.run_rules_learner)
        return {"status": "ok", "rules_updated": count}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/history/{region}")
async def get_region_history(region: str, limit: int = 200, date: str = None):
    """Повертає хронологію загроз для конкретної області з Firebase Firestore.
    
    Args:
        region: Назва області
        limit: Максимальна кількість подій (default 200)
        date: Дата у форматі YYYY-MM-DD. Якщо не вказано, повертає за сьогодні.
    """
    from urllib.parse import unquote
    from datetime import datetime as dt, timedelta
    region = unquote(region)
    
    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firebase Firestore недоступний")
    
    # Determine date range in Europe/Kiev timezone, then convert to UTC for Firestore query comparison
    try:
        import zoneinfo
    except ImportError:
        from backports import zoneinfo
    
    kyiv_tz = zoneinfo.ZoneInfo("Europe/Kiev")
    
    if date:
        try:
            # Parse target date as local date (midnight start) in Kiev timezone
            parsed_date = dt.strptime(date, "%Y-%m-%d")
            local_start = parsed_date.replace(tzinfo=kyiv_tz)
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірний формат дати. Використовуйте YYYY-MM-DD")
    else:
        # If no date provided, get current time in Kiev timezone
        current_local = dt.now(kyiv_tz)
        local_start = current_local.replace(hour=0, minute=0, second=0, microsecond=0)
    
    local_end = local_start + timedelta(days=1)
    
    # Convert local start and end of the day in Kiev to UTC
    utc_start = local_start.astimezone(timezone.utc)
    utc_end = local_end.astimezone(timezone.utc)
    
    date_start = utc_start.strftime("%Y-%m-%d %H:%M:%S")
    date_end = utc_end.strftime("%Y-%m-%d %H:%M:%S")
        
    try:
        # Fetch by region only (avoids composite index requirement), then filter by date in Python
        docs = await asyncio.to_thread(
            lambda: db.collection('sirenua_history')
                      .where('region', '==', region)
                      .get()
        )
        
        events = []
        for doc in docs:
            d = doc.to_dict()
            ts = d.get('timestamp', '')
            # Filter by date range in Python
            if date_start <= ts < date_end:
                events.append(d)
        
        # Sort by timestamp descending
        events.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        
        # Limit results
        events = events[:min(limit, 200)]
        
        return {
            "region": region,
            "date": local_start.strftime("%Y-%m-%d"),
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))





@app.post("/api/threats/mock")
async def set_mock_threat(request: ThreatSetRequest):
    """Встановити загрозу вручну для тестування."""
    valid_levels = {"none", "low", "medium", "high", "critical"}
    if request.level not in valid_levels:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid level '{request.level}'. Valid: {valid_levels}"
        )

    success = threat_manager.set_threat(
        region=request.region,
        level=request.level,
        threat_type=request.threat_type,
        detail=request.detail,
        is_test=True,
    )

    if not success:
        raise HTTPException(
            status_code=404,
            detail=f"Region '{request.region}' not found"
        )

    return {"status": "ok", "region": request.region, "level": request.level}


@app.post("/api/threats/scenario")
async def set_scenario(request: ScenarioRequest):
    """Запустити тестовий сценарій."""
    valid_scenarios = {
        "mig_takeoff", "shaheds_south", "cruise_missiles_west",
        "massive_attack", "ballistic_kharkiv", "clear"
    }
    if request.scenario not in valid_scenarios:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scenario '{request.scenario}'. Valid: {valid_scenarios}"
        )

    if request.scenario == "clear":
        await asyncio.to_thread(threat_manager.clear_all, only_test=True)
    else:
        await asyncio.to_thread(threat_manager.set_scenario, request.scenario)

    return {"status": "ok", "scenario": request.scenario}


@app.post("/api/threats/clear")
async def clear_all_threats():
    """Очистити всі загрози."""
    await asyncio.to_thread(threat_manager.clear_all, only_test=True)
    return {"status": "ok", "message": "All threats cleared"}


@app.post("/api/telegram/test")
async def test_telegram_message(request: TelegramTestRequest):
    """Сімулювати отримання повідомлення з Telegram та обробити його негайно."""
    global telegram_monitor
    if telegram_monitor is None:
        raise HTTPException(
            status_code=503,
            detail="Telegram monitor not initialized or running in mock-only mode"
        )
    
    if telegram_monitor.analyzer.is_configured:
        print(f"🧪 [Test Endpoint] Analyzing message: {request.text[:80]}...")
        results = await telegram_monitor.analyzer.analyze_batch([{"channel": request.channel, "text": request.text}])
        if results:
            await telegram_monitor._apply_gemini_analysis(results, is_test=True)
            return {
                "status": "ok",
                "message": "Message analyzed via Gemini immediately",
                "results": results
            }
        else:
            return {"status": "ok", "message": "Analyzed via Gemini, but no targets identified"}
    else:
        await telegram_monitor._process_message_regex(request.text, request.channel)
        return {"status": "ok", "message": "Analyzed via Regex fallback immediately"}


@app.get("/api/shelters")
async def get_shelters(lat: float, lon: float, radius: float = 1500, limit: int = 50):
    """Пошук найближчих укриттів у заданому радіусі (метри)."""
    if not shelter_manager.is_loaded:
        raise HTTPException(status_code=503, detail="Shelter database is loading, try again in a minute.")

    # Clamp values
    radius = max(100, min(radius, 50_000))  # 100m — 50km
    limit = max(1, min(limit, 100))

    results = shelter_manager.find_nearby(lat, lon, radius, limit=limit)
    return {
        "count": len(results),
        "radius_m": radius,
        "total_in_db": shelter_manager.total_count,
        "shelters": results,
    }


@app.post("/api/shelters/upload_json")
async def upload_shelters_json(req: ShelterUploadRequest):
    """Прихований ендпоінт для завантаження масиву укриттів (JSON) в Firestore."""
    if not HAS_FIREBASE:
        raise HTTPException(status_code=500, detail="Firebase не ініціалізовано")
        
    try:
        from firebase_admin import firestore
        db = firestore.client()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Помилка Firestore: {e}")
        
    batch = db.batch()
    count = 0
    
    for s in req.shelters:
        doc_ref = db.collection("sirenua_shelters").document()
        batch.set(doc_ref, {
            "name": s.name,
            "address": s.address,
            "lat": s.lat,
            "lon": s.lon,
            "type": s.type,
            "capacity": s.capacity,
            "accessible": s.accessible,
            "source": "gov"
        })
        count += 1
        
        # Обмеження Firestore batch - 500 операцій
        if count % 400 == 0:
            batch.commit()
            batch = db.batch()
            
    if count % 400 != 0:
        batch.commit()
        
    # Перезавантажуємо кеш укриттів
    asyncio.create_task(shelter_manager.load())
    
    return {"status": "success", "uploaded": count}


@app.post("/api/admin/seed_history")
async def seed_history():
    """Генерує початкову історію подій у Firestore для всіх областей."""
    db = get_db()
    if not db:
        raise HTTPException(status_code=503, detail="Firebase Firestore недоступний")
        
    import random
    import time
    from datetime import datetime, timedelta, timezone
    
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
    
    threat_templates = [
        {"threat_level": "high", "threat_type": "mig31k", "detail": "Зліт МіГ-31К з аеродрому Саваслейка. Ракетна небезпека!"},
        {"threat_level": "medium", "threat_type": "shahed", "detail": "Група ударних БпЛА типу 'Shahed' наближається з півдня."},
        {"threat_level": "high", "threat_type": "cruise_missile", "detail": "Запуск крилатих ракет Х-101/Х-555 з бортів Ту-95МС."},
        {"threat_level": "critical", "threat_type": "ballistic", "detail": "Загроза застосування балістичного озброєння з Криму!"},
    ]
    
    total_added = 0
    
    try:
        for region in regions:
            base_time = datetime.now(timezone.utc)
            
            for i in range(3):
                # 1. Початок тривоги
                alert_time = base_time - timedelta(days=i, hours=random.randint(2, 6))
                alert_timestamp = alert_time.strftime("%Y-%m-%d %H:%M:%S")
                
                # 2. Відбій тривоги
                clear_time = alert_time + timedelta(minutes=random.randint(45, 120))
                clear_timestamp = clear_time.strftime("%Y-%m-%d %H:%M:%S")
                
                alert_id = int(alert_time.timestamp() * 1000)
                clear_id = int(clear_time.timestamp() * 1000)
                
                is_tactical = random.choice([True, False])
                
                if is_tactical:
                    template = random.choice(threat_templates)
                    
                    alert_doc = {
                        "id": alert_id,
                        "region": region,
                        "timestamp": alert_timestamp,
                        "threat_level": template["threat_level"],
                        "threat_type": template["threat_type"],
                        "detail": template["detail"],
                        "confidence": random.randint(70, 95),
                        "telemetry": {
                            "source_reliability": "high",
                            "civilian_risk_level": "high" if template["threat_level"] == "high" else "moderate",
                            "message_context_tags": ["rocket", "alert"] if template["threat_type"] != "shahed" else ["shahed", "drone"]
                        }
                    }
                    
                    clear_doc = {
                        "id": clear_id,
                        "region": region,
                        "timestamp": clear_timestamp,
                        "threat_level": "none",
                        "threat_type": template["threat_type"],
                        "detail": "Відбій загрози",
                        "confidence": 100
                    }
                else:
                    alert_doc = {
                        "id": alert_id,
                        "region": region,
                        "timestamp": alert_timestamp,
                        "threat_level": "high",
                        "threat_type": "official_alarm",
                        "detail": "Повітряна тривога",
                        "confidence": 100
                    }
                    
                    clear_doc = {
                        "id": clear_id,
                        "region": region,
                        "timestamp": clear_timestamp,
                        "threat_level": "none",
                        "threat_type": "official_alarm",
                        "detail": "Відбій повітряної тривоги",
                        "confidence": 100
                    }
                
                db.collection('sirenua_history').add(alert_doc)
                db.collection('sirenua_history').add(clear_doc)
                total_added += 2
                
        return {"status": "success", "message": f"Додано {total_added} записів хронології у Firestore для всіх областей"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ========================== ADMIN PANEL API ==========================

@app.get("/api/admin/errors")
async def get_admin_errors(source: str = None, error_type: str = None, days: int = 7, limit: int = 100):
    """Список помилок з фільтрами."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM error_log WHERE timestamp >= datetime('now', ?)"
        params = [f'-{days} days']
        
        if source:
            query += " AND source = ?"
            params.append(source)
        if error_type:
            query += " AND error_type = ?"
            params.append(error_type)
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "total": len(rows),
            "errors": [dict(r) for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/errors/stats")
async def get_admin_errors_stats(days: int = 7):
    """Агреговані лічильники помилок."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except ImportError:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
        tz_modifier = f"'{offset_hours:+d} hours'"
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        # By source
        cursor.execute('''
            SELECT source, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY source ORDER BY count DESC
        ''', (day_filter,))
        by_source = [dict(r) for r in cursor.fetchall()]
        
        # By type
        cursor.execute('''
            SELECT error_type, COUNT(*) as count FROM error_log
            WHERE timestamp >= datetime('now', ?)
            GROUP BY error_type ORDER BY count DESC
        ''', (day_filter,))
        by_type = [dict(r) for r in cursor.fetchall()]
        
        # Hourly (last 48h)
        cursor.execute(f'''
            SELECT strftime('%Y-%m-%d %H:00', datetime(timestamp, {tz_modifier})) as hour, COUNT(*) as count
            FROM error_log
            WHERE timestamp >= datetime('now', '-2 days')
            GROUP BY hour ORDER BY hour
        ''')
        hourly = [dict(r) for r in cursor.fetchall()]
        
        # Total
        cursor.execute("SELECT COUNT(*) as total FROM error_log WHERE timestamp >= datetime('now', ?)", (day_filter,))
        total = cursor.fetchone()["total"]
        
        conn.close()
        return {"total": total, "by_source": by_source, "by_type": by_type, "hourly": hourly}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/chronology")
async def get_admin_chronology(region: str = None, days: int = 7):
    """Хронологія загроз: встановлення → зняття, з match_type."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except ImportError:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
        tz_modifier = f"'{offset_hours:+d} hours'"
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        query = '''
            SELECT pe.id, pe.region, pe.threat_level, pe.threat_type,
                   pe.confidence_at_set, pe.confidence_at_clear,
                   pe.was_predictive, pe.prediction_accuracy,
                   pe.lifecycle_status, pe.duration_seconds,
                   pe.gemini_group_id,
                   th.timestamp as threat_timestamp,
                   th.detail as threat_detail,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type
            FROM paired_events pe
            LEFT JOIN threat_history th ON pe.threat_event_id = th.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.created_at >= datetime('now', ?)
        '''
        params = [day_filter]
        
        if region:
            from urllib.parse import unquote
            query += " AND pe.region = ?"
            params.append(unquote(region))
        
        query += " ORDER BY th.timestamp DESC LIMIT 500"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Daily aggregation
        daily_agg_query = f'''
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.lifecycle_status = 'active' THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM paired_events pe
            LEFT JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE pe.created_at >= datetime('now', ?)
        '''
        agg_params = [day_filter]
        if region:
            daily_agg_query += " AND pe.region = ?"
            agg_params.append(unquote(region))
        daily_agg_query += " GROUP BY day ORDER BY day"
        
        cursor.execute(daily_agg_query, agg_params)
        daily_stats = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            # Determine match_type
            if event.get("prediction_accuracy") == "confirmed":
                event["match_type"] = "match"
            elif event.get("prediction_accuracy") == "overestimated":
                event["match_type"] = "mismatch"
            elif event.get("lifecycle_status") == "active":
                event["match_type"] = "active"
            else:
                event["match_type"] = "cleared"
            events.append(event)
        
        return {
            "total": len(events),
            "days": days,
            "events": events,
            "daily_stats": daily_stats
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/rules/history")
async def get_admin_rules_history(days: int = 30, limit: int = 200):
    """Аудит-лог змін правил Gemini."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM gemini_rules_audit
            WHERE timestamp >= datetime('now', ?)
            ORDER BY timestamp DESC LIMIT ?
        ''', (f'-{days} days', min(limit, 500)))
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "total": len(rows),
            "entries": [dict(r) for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========================== HTML ADMIN PANEL ==========================

from fastapi.responses import HTMLResponse

ADMIN_HTML = '''<!DOCTYPE html>
<html lang="uk">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SirenUA Admin Panel</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.4/dist/chart.umd.min.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--text2:#8b949e;--accent:#58a6ff;--red:#f85149;--green:#3fb950;--yellow:#d29922;--orange:#db6d28;--purple:#bc8cff}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,-apple-system,sans-serif;line-height:1.5}
.header{background:linear-gradient(135deg,#1a1e26,#161b22);border-bottom:1px solid var(--border);padding:16px 24px;display:flex;align-items:center;gap:16px}
.header h1{font-size:20px;font-weight:600;background:linear-gradient(135deg,var(--accent),var(--purple));-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.header .status{margin-left:auto;font-size:13px;color:var(--text2)}
.header .status .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--green);margin-right:6px;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.tabs{display:flex;background:var(--card);border-bottom:1px solid var(--border);padding:0 24px;gap:4px}
.tab{padding:12px 20px;cursor:pointer;color:var(--text2);font-size:14px;font-weight:500;border-bottom:2px solid transparent;transition:all .2s}
.tab:hover{color:var(--text)}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab .badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:600;margin-left:6px;vertical-align:middle}
.tab .badge.red{background:rgba(248,81,73,.2);color:var(--red)}
.tab .badge.blue{background:rgba(88,166,255,.2);color:var(--accent)}
.tab .badge.green{background:rgba(63,185,80,.2);color:var(--green)}
.content{padding:24px;display:none}
.content.active{display:block}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px}
.stat-card h3{font-size:13px;color:var(--text2);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px}
.stat-card .value{font-size:32px;font-weight:700}
.stat-card .value.red{color:var(--red)}
.stat-card .value.green{color:var(--green)}
.stat-card .value.yellow{color:var(--yellow)}
.chart-box{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:20px;margin-bottom:16px}
.chart-box h3{font-size:14px;margin-bottom:12px;color:var(--text)}
.chart-box canvas{max-height:250px}
.filters{display:flex;gap:12px;margin-bottom:16px;flex-wrap:wrap;align-items:center}
.filters select,.filters input{background:var(--card);border:1px solid var(--border);color:var(--text);padding:8px 12px;border-radius:8px;font-size:13px}
.filters label{font-size:13px;color:var(--text2)}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;background:var(--card);border-bottom:2px solid var(--border);color:var(--text2);font-weight:600;text-transform:uppercase;letter-spacing:.3px;font-size:11px;position:sticky;top:0}
td{padding:10px 12px;border-bottom:1px solid var(--border)}
tr:hover{background:rgba(88,166,255,.05)}
.badge-src{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-src.server{background:rgba(88,166,255,.15);color:var(--accent)}
.badge-src.firebase{background:rgba(219,109,40,.15);color:var(--orange)}
.badge-src.gemini{background:rgba(188,140,255,.15);color:var(--purple)}
.badge-type{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.badge-type.rate{background:rgba(248,81,73,.2);color:var(--red)}
.badge-type.timeout{background:rgba(210,153,34,.2);color:var(--yellow)}
.badge-type.general{background:rgba(139,148,158,.2);color:var(--text2)}
.match-icon{font-size:16px;margin-right:4px}
.timeline-day{margin-bottom:16px}
.timeline-day h4{font-size:14px;color:var(--accent);padding:8px 0;border-bottom:1px solid var(--border);margin-bottom:8px}
.tl-event{display:grid;grid-template-columns:180px 1fr 120px 100px;gap:8px;padding:8px 4px;border-bottom:1px solid rgba(48,54,61,.5);align-items:center;font-size:13px}
.tl-event:hover{background:rgba(88,166,255,.05)}
.rule-card{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:14px 16px;margin-bottom:8px}
.rule-card.added{border-left:3px solid var(--green)}
.rule-card.removed,.rule-card.deactivated{border-left:3px solid var(--red)}
.rule-card.decayed{border-left:3px solid var(--yellow)}
.rule-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}
.rule-action{padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}
.rule-action.added{background:rgba(63,185,80,.15);color:var(--green)}
.rule-action.removed,.rule-action.deactivated{background:rgba(248,81,73,.15);color:var(--red)}
.table-wrapper{max-height:600px;overflow-y:auto;border-radius:8px;border:1px solid var(--border)}
.empty{text-align:center;padding:40px;color:var(--text2);font-size:14px}
.refresh-info{font-size:11px;color:var(--text2);text-align:right;padding:4px 0}
</style>
</head>
<body>
<div class="header">
  <h1>🚨 SirenUA Admin Panel</h1>
  <div class="status"><span class="dot"></span>Live Monitoring</div>
</div>
<div class="tabs">
  <div class="tab active" data-tab="errors">🔴 Помилки <span class="badge red" id="err-badge">0</span></div>
  <div class="tab" data-tab="chronology">📊 Хронологія <span class="badge blue" id="chr-badge">0</span></div>
  <div class="tab" data-tab="rules">🧠 Правила Gemini <span class="badge green" id="rul-badge">0</span></div>
</div>

<!-- TAB 1: ERRORS -->
<div class="content active" id="tab-errors">
  <div class="filters">
    <label>Джерело:</label>
    <select id="f-source"><option value="">Всі</option><option value="server">Server</option><option value="firebase">Firebase</option><option value="gemini">Gemini</option></select>
    <label>Тип:</label>
    <select id="f-type"><option value="">Всі</option><option value="429_rate_limit">429 Rate Limit</option><option value="500_server">500 Server</option><option value="timeout">Timeout</option><option value="connection">Connection</option><option value="auth">Auth</option><option value="general">General</option></select>
    <label>Днів:</label>
    <select id="f-days"><option value="1">1</option><option value="3">3</option><option value="7" selected>7</option><option value="30">30</option></select>
    <button onclick="loadErrors()" style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px">Оновити</button>
  </div>
  <div class="grid">
    <div class="stat-card"><h3>Всього помилок</h3><div class="value red" id="err-total">0</div></div>
    <div class="stat-card"><h3>429 Rate Limit</h3><div class="value yellow" id="err-429">0</div></div>
    <div class="stat-card"><h3>Firebase</h3><div class="value" style="color:var(--orange)" id="err-fb">0</div></div>
    <div class="stat-card"><h3>Gemini</h3><div class="value" style="color:var(--purple)" id="err-gem">0</div></div>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr">
    <div class="chart-box"><h3>Помилки по джерелах</h3><canvas id="chart-src"></canvas></div>
    <div class="chart-box"><h3>Помилки по годинах (48г)</h3><canvas id="chart-hourly"></canvas></div>
  </div>
  <div class="table-wrapper"><table><thead><tr><th>Час</th><th>Джерело</th><th>Тип</th><th>Повідомлення</th><th>Endpoint</th></tr></thead><tbody id="err-body"></tbody></table></div>
  <div class="refresh-info">Автооновлення кожні 60с</div>
</div>

<!-- TAB 2: CHRONOLOGY -->
<div class="content" id="tab-chronology">
  <div class="filters">
    <label>Днів:</label>
    <select id="chr-days"><option value="1">1</option><option value="3">3</option><option value="7" selected>7</option><option value="14">14</option><option value="30">30</option></select>
    <label>Область:</label>
    <select id="chr-region"><option value="">Всі</option></select>
    <button onclick="loadChronology()" style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px">Оновити</button>
  </div>
  <div class="grid" style="grid-template-columns:1fr 1fr">
    <div class="chart-box"><h3>Загрози / Зняття по днях</h3><canvas id="chart-daily"></canvas></div>
    <div class="chart-box"><h3>Точність передбачень (%)</h3><canvas id="chart-accuracy"></canvas></div>
  </div>
  <div class="grid">
    <div class="stat-card"><h3>Всього подій</h3><div class="value" style="color:var(--accent)" id="chr-total">0</div></div>
    <div class="stat-card"><h3>✅ Співпадіння</h3><div class="value green" id="chr-match">0</div></div>
    <div class="stat-card"><h3>❌ Неспівпадіння</h3><div class="value red" id="chr-mismatch">0</div></div>
    <div class="stat-card"><h3>⏱️ Активні</h3><div class="value yellow" id="chr-active">0</div></div>
  </div>
  <div id="timeline-container"></div>
  <div class="refresh-info">Автооновлення кожні 60с</div>
</div>

<!-- TAB 3: RULES -->
<div class="content" id="tab-rules">
  <div class="filters">
    <label>Днів аудиту:</label>
    <select id="rul-days"><option value="7">7</option><option value="14">14</option><option value="30" selected>30</option></select>
    <button onclick="loadRules()" style="background:var(--accent);color:#fff;border:none;padding:8px 16px;border-radius:8px;cursor:pointer;font-size:13px">Оновити</button>
  </div>
  <h3 style="margin:16px 0 8px;font-size:15px">Активні правила</h3>
  <div class="table-wrapper" style="max-height:400px"><table><thead><tr><th>Тип</th><th>Правило</th><th>Регіон</th><th>Тип загрози</th><th>Accuracy</th><th>Evidence</th><th>Оновлено</th></tr></thead><tbody id="rules-active-body"></tbody></table></div>
  <h3 style="margin:24px 0 8px;font-size:15px">📜 Аудит-лог правил</h3>
  <div id="rules-audit"></div>
  <div class="refresh-info">Автооновлення кожні 60с</div>
</div>

<script>
const API = '';
let srcChart, hourlyChart, dailyChart, accChart;

// Tabs
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.content').forEach(x => x.classList.remove('active'));
    t.classList.add('active');
    document.getElementById('tab-' + t.dataset.tab).classList.add('active');
  });
});

function fmtTime(ts) {
  if (!ts) return '—';
  try {
    const d = new Date(ts + (ts.includes('Z') || ts.includes('+') ? '' : 'Z'));
    return d.toLocaleString('uk-UA', {timeZone:'Europe/Kiev', hour:'2-digit', minute:'2-digit', second:'2-digit', day:'2-digit', month:'2-digit'});
  } catch(e) { return ts; }
}

function fmtDuration(s) {
  if (!s) return '—';
  if (s < 60) return s + 'с';
  if (s < 3600) return Math.round(s/60) + 'хв';
  return Math.round(s/3600*10)/10 + 'год';
}

// === ERRORS ===
async function loadErrors() {
  const src = document.getElementById('f-source').value;
  const typ = document.getElementById('f-type').value;
  const days = document.getElementById('f-days').value;
  
  const params = new URLSearchParams({days});
  if (src) params.set('source', src);
  if (typ) params.set('error_type', typ);
  
  try {
    const [errRes, statRes] = await Promise.all([
      fetch(API + '/api/admin/errors?' + params),
      fetch(API + '/api/admin/errors/stats?days=' + days)
    ]);
    const errors = await errRes.json();
    const stats = await statRes.json();
    
    document.getElementById('err-total').textContent = stats.total;
    document.getElementById('err-badge').textContent = stats.total;
    
    const r429 = stats.by_type.find(x => x.error_type === '429_rate_limit');
    document.getElementById('err-429').textContent = r429 ? r429.count : 0;
    const fb = stats.by_source.find(x => x.source === 'firebase');
    document.getElementById('err-fb').textContent = fb ? fb.count : 0;
    const gm = stats.by_source.find(x => x.source === 'gemini');
    document.getElementById('err-gem').textContent = gm ? gm.count : 0;
    
    // Source chart
    if (srcChart) srcChart.destroy();
    const srcLabels = stats.by_source.map(x => x.source);
    const srcData = stats.by_source.map(x => x.count);
    const srcColors = srcLabels.map(s => s === 'server' ? '#58a6ff' : s === 'firebase' ? '#db6d28' : '#bc8cff');
    srcChart = new Chart(document.getElementById('chart-src'), {
      type: 'doughnut',
      data: {labels: srcLabels, datasets: [{data: srcData, backgroundColor: srcColors, borderWidth: 0}]},
      options: {responsive: true, plugins: {legend: {position: 'bottom', labels: {color: '#c9d1d9', font: {size: 12}}}}}
    });
    
    // Hourly chart
    if (hourlyChart) hourlyChart.destroy();
    hourlyChart = new Chart(document.getElementById('chart-hourly'), {
      type: 'line',
      data: {
        labels: stats.hourly.map(x => x.hour.split(' ')[1] || x.hour),
        datasets: [{label: 'Помилки', data: stats.hourly.map(x => x.count), borderColor: '#f85149', backgroundColor: 'rgba(248,81,73,.1)', fill: true, tension: .3, pointRadius: 2}]
      },
      options: {responsive: true, scales: {x: {ticks: {color: '#8b949e', maxTicksLimit: 12}}, y: {ticks: {color: '#8b949e'}, beginAtZero: true}}, plugins: {legend: {display: false}}}
    });
    
    // Table
    const body = document.getElementById('err-body');
    if (!errors.errors.length) {
      body.innerHTML = '<tr><td colspan="5" class="empty">Помилок не знайдено 🎉</td></tr>';
    } else {
      body.innerHTML = errors.errors.map(e => {
        const srcCls = e.source;
        const typCls = e.error_type.includes('429') ? 'rate' : e.error_type.includes('timeout') ? 'timeout' : 'general';
        return `<tr>
          <td style="white-space:nowrap">${fmtTime(e.timestamp)}</td>
          <td><span class="badge-src ${srcCls}">${e.source}</span></td>
          <td><span class="badge-type ${typCls}">${e.error_type}</span></td>
          <td style="max-width:400px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(e.message||'').replace(/"/g,'&quot;')}">${e.message||''}</td>
          <td style="color:var(--text2);font-size:12px">${e.endpoint||'—'}</td>
        </tr>`;
      }).join('');
    }
  } catch(e) { console.error('Errors load failed:', e); }
}

// === CHRONOLOGY ===
async function loadChronology() {
  const days = document.getElementById('chr-days').value;
  const region = document.getElementById('chr-region').value;
  const params = new URLSearchParams({days});
  if (region) params.set('region', region);
  
  try {
    const res = await fetch(API + '/api/admin/chronology?' + params);
    const data = await res.json();
    
    const matches = data.events.filter(e => e.match_type === 'match').length;
    const mismatches = data.events.filter(e => e.match_type === 'mismatch').length;
    const active = data.events.filter(e => e.match_type === 'active').length;
    
    document.getElementById('chr-total').textContent = data.total;
    document.getElementById('chr-badge').textContent = data.total;
    document.getElementById('chr-match').textContent = matches;
    document.getElementById('chr-mismatch').textContent = mismatches;
    document.getElementById('chr-active').textContent = active;
    
    // Daily bar chart
    if (dailyChart) dailyChart.destroy();
    dailyChart = new Chart(document.getElementById('chart-daily'), {
      type: 'bar',
      data: {
        labels: data.daily_stats.map(d => d.day),
        datasets: [
          {label: 'Загрози', data: data.daily_stats.map(d => d.total_events), backgroundColor: 'rgba(248,81,73,.6)'},
          {label: 'Зняття', data: data.daily_stats.map(d => d.cleared), backgroundColor: 'rgba(63,185,80,.6)'}
        ]
      },
      options: {responsive: true, scales: {x: {ticks: {color: '#8b949e'}}, y: {ticks: {color: '#8b949e'}, beginAtZero: true}}, plugins: {legend: {labels: {color: '#c9d1d9'}}}}
    });
    
    // Accuracy line chart
    if (accChart) accChart.destroy();
    const accData = data.daily_stats.map(d => {
      const total = (d.confirmed || 0) + (d.overestimated || 0);
      return total > 0 ? Math.round(d.confirmed / total * 100) : null;
    });
    accChart = new Chart(document.getElementById('chart-accuracy'), {
      type: 'line',
      data: {
        labels: data.daily_stats.map(d => d.day),
        datasets: [{label: 'Точність %', data: accData, borderColor: '#3fb950', backgroundColor: 'rgba(63,185,80,.1)', fill: true, tension: .3, pointRadius: 3, spanGaps: true}]
      },
      options: {responsive: true, scales: {x: {ticks: {color: '#8b949e'}}, y: {ticks: {color: '#8b949e'}, beginAtZero: true, max: 100}}, plugins: {legend: {display: false}}}
    });
    
    // Timeline
    const container = document.getElementById('timeline-container');
    const grouped = {};
    data.events.forEach(ev => {
      const day = (ev.threat_timestamp || '').split(' ')[0] || 'Невідомо';
      if (!grouped[day]) grouped[day] = [];
      grouped[day].push(ev);
    });
    
    if (Object.keys(grouped).length === 0) {
      container.innerHTML = '<div class="empty">Подій не знайдено</div>';
    } else {
      container.innerHTML = Object.entries(grouped).sort((a,b) => b[0].localeCompare(a[0])).map(([day, events]) => {
        return `<div class="timeline-day"><h4>📅 ${day} (${events.length} подій)</h4>
        ${events.map(ev => {
          const icon = ev.match_type === 'match' ? '✅' : ev.match_type === 'mismatch' ? '❌' : ev.match_type === 'active' ? '⏱️' : '🔄';
          return `<div class="tl-event">
            <div style="color:var(--text2)">${fmtTime(ev.threat_timestamp)}</div>
            <div><span class="match-icon">${icon}</span><strong>${ev.region||''}</strong> — ${ev.threat_type||''} (${ev.threat_level||''})</div>
            <div style="font-size:12px;color:var(--text2)">${fmtDuration(ev.duration_seconds)}</div>
            <div style="font-size:12px;color:var(--text2)">${ev.lifecycle_status||''}</div>
          </div>`;
        }).join('')}
        </div>`;
      }).join('');
    }
  } catch(e) { console.error('Chronology load failed:', e); }
}

// === RULES ===
async function loadRules() {
  const days = document.getElementById('rul-days').value;
  
  try {
    const [rulesRes, auditRes] = await Promise.all([
      fetch(API + '/api/analytics/rules?active_only=true&limit=100'),
      fetch(API + '/api/admin/rules/history?days=' + days)
    ]);
    const rules = await rulesRes.json();
    const audit = await auditRes.json();
    
    document.getElementById('rul-badge').textContent = rules.total;
    
    // Active rules table
    const tbody = document.getElementById('rules-active-body');
    if (!rules.rules.length) {
      tbody.innerHTML = '<tr><td colspan="7" class="empty">Немає активних правил</td></tr>';
    } else {
      tbody.innerHTML = rules.rules.map(r => `<tr>
        <td><span class="badge-src" style="background:rgba(63,185,80,.15);color:var(--green)">${r.rule_type||''}</span></td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${(r.rule_text||'').replace(/"/g,'&quot;')}">${r.rule_text||''}</td>
        <td style="font-size:12px">${r.source_region||''} → ${r.target_region||''}</td>
        <td style="font-size:12px">${r.threat_type||''}</td>
        <td style="font-weight:600;color:${r.accuracy_score >= 0.7 ? 'var(--green)' : r.accuracy_score >= 0.5 ? 'var(--yellow)' : 'var(--red)'}">${(r.accuracy_score*100).toFixed(0)}%</td>
        <td>${r.evidence_count||0}</td>
        <td style="font-size:12px;color:var(--text2)">${fmtTime(r.updated_at)}</td>
      </tr>`).join('');
    }
    
    // Audit log
    const auditDiv = document.getElementById('rules-audit');
    if (!audit.entries.length) {
      auditDiv.innerHTML = '<div class="empty">Аудит-лог порожній</div>';
    } else {
      auditDiv.innerHTML = audit.entries.map(e => {
        const cls = e.action === 'added' ? 'added' : e.action === 'deactivated' ? 'deactivated' : 'removed';
        return `<div class="rule-card ${cls}">
          <div class="rule-header">
            <span class="rule-action ${cls}">${e.action}</span>
            <span style="font-size:12px;color:var(--text2)">${fmtTime(e.timestamp)}</span>
          </div>
          <div style="font-size:13px;margin-bottom:4px">${e.rule_text || e.reason || '—'}</div>
          <div style="font-size:11px;color:var(--text2)">
            ${e.rule_type ? 'Тип: ' + e.rule_type + ' | ' : ''}
            ${e.threat_type ? 'Загроза: ' + e.threat_type + ' | ' : ''}
            ${e.source_region ? e.source_region + ' → ' + (e.target_region||'') + ' | ' : ''}
            ${e.reason ? 'Причина: ' + e.reason : ''}
          </div>
        </div>`;
      }).join('');
    }
  } catch(e) { console.error('Rules load failed:', e); }
}

// Populate region selector
async function loadRegions() {
  try {
    const res = await fetch(API + '/api/threats');
    const data = await res.json();
    const sel = document.getElementById('chr-region');
    Object.keys(data.threats || {}).sort().forEach(r => {
      const opt = document.createElement('option');
      opt.value = r; opt.textContent = r;
      sel.appendChild(opt);
    });
  } catch(e) {}
}

// Initial load
loadErrors();
loadChronology();
loadRules();
loadRegions();

// Auto-refresh every 60s
setInterval(() => {
  const active = document.querySelector('.tab.active')?.dataset.tab;
  if (active === 'errors') loadErrors();
  else if (active === 'chronology') loadChronology();
  else if (active === 'rules') loadRules();
}, 60000);
</script>
</body>
</html>'''


@app.get("/admin", response_class=HTMLResponse)
async def admin_panel():
    """HTML адмін-панель моніторингу."""
    return ADMIN_HTML


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 8085))
    mode = "LIVE (Telegram)" if is_live_mode else "MOCK (тестування)"
    
    print(f"🚀 SirenUA Threat Monitor Server")
    print(f"📡 Mode: {mode}")
    print(f"🌐 URL: http://localhost:{port}")
    print(f"📋 API Docs: http://localhost:{port}/docs")
    print()

    if not is_live_mode:
        print("Тестові сценарії:")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"mig_takeoff\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"shaheds_south\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/scenario -H 'Content-Type: application/json' -d '{{\"scenario\": \"massive_attack\"}}'")
        print(f"  curl -X POST http://localhost:{port}/api/threats/clear")
        print()
    else:
        print("⚡ Підключення до Telegram каналів...")
        print("   При першому запуску потрібно ввести номер телефону та код.")
        print()

    uvicorn.run(app, host="0.0.0.0", port=port)
