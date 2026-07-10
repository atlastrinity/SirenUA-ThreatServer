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

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
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
    
    # Migrate telemetry_data table — add target_cities_coords if missing
    try:
        cursor.execute("ALTER TABLE telemetry_data ADD COLUMN target_cities_coords TEXT")
    except sqlite3.OperationalError:
        pass
    
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

    # Seed mock rules and audit entries if empty and in mock mode
    if not is_live_mode:
        cursor.execute("SELECT COUNT(*) as c FROM gemini_rules")
        if cursor.fetchone()[0] == 0:
            cursor.execute("""
                INSERT INTO gemini_rules (id, rule_type, source_region, target_region, threat_type, confidence_delta, accuracy_score, evidence_count, is_active)
                VALUES ('mock_rule_1', 'route_pattern', 'Crimea', 'Zaporizhzhia', 'shahed', 15, 0.85, 12, 1)
            """)
            cursor.execute("""
                INSERT INTO gemini_rules (id, rule_type, source_region, target_region, threat_type, confidence_delta, accuracy_score, evidence_count, is_active)
                VALUES ('mock_rule_2', 'confidence_correction', 'Kursk', 'Sumy', 'mig31k', 25, 0.90, 8, 1)
            """)
            cursor.execute("""
                INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason)
                VALUES ('added', 'route_pattern', 'Детекція БПЛА типу Shahed з Криму в бік Запоріжжя', 'Crimea', 'Zaporizhzhia', 'shahed', 'Аналіз 12 аналогічних траєкторій за тиждень')
            """)
            cursor.execute("""
                INSERT INTO gemini_rules_audit (action, rule_type, rule_text, source_region, target_region, threat_type, reason)
                VALUES ('added', 'confidence_correction', 'Зліт МіГ-31К з Курська в бік Сум', 'Kursk', 'Sumy', 'mig31k', 'Корекція рівня загрози на основі високої ймовірності ракетного удару')
            """)

    conn.commit()
    conn.close()
    print("💾 Аналітична БД ініціалізована (threat_history + telemetry_data + threat_clearings + gemini_rules + paired_events + error_log + gemini_rules_audit)")


def log_error_to_db(source: str, message: str, endpoint: str = None, context: str = None, error_type: str = None):
    """Log an error event to the error_log table. Source: 'server', 'firebase', 'gemini'."""
    error_msg = str(message)
    # Classify error type if not provided
    if not error_type:
        if "429" in error_msg or "Quota" in error_msg or "RESOURCE_EXHAUSTED" in error_msg or "rate limit" in error_msg.lower():
            error_type = "429_rate_limit"
        elif "500" in error_msg or "Internal" in error_msg:
            error_type = "500_server"
        elif "timeout" in error_msg.lower() or "Timeout" in error_msg:
            error_type = "timeout"
        elif "connection" in error_msg.lower() or "ConnectionError" in error_msg or "socket" in error_msg.lower() or "network" in error_msg.lower() or "http" in error_msg.lower():
            error_type = "network_error"
        elif "auth" in error_msg.lower() or "permission" in error_msg.lower() or "403" in error_msg or "credential" in error_msg.lower():
            error_type = "auth"
        elif "traceback" in error_msg.lower() or "exception" in error_msg.lower() or "syntax" in error_msg.lower() or "system" in error_msg.lower() or "sqlite" in error_msg.lower():
            error_type = "systemic"
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
        
        # Create paired_event for lifecycle tracking (only for non-none AI/Telegram threats, NOT official_alarm)
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

def log_threat_to_firestore(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False):
    """Log threat event to Firebase Firestore with retry on quota errors."""
    db = get_db()
    if not db:
        return
        
    from mock_mode import is_duplicate_event
    if is_duplicate_event(region, level, threat_type):
        print(f"⚠️ Duplicate history event detected for {region} ({level}, {threat_type}), skipping write to Firestore.")
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

def detect_mitigation_from_text(text: str) -> bool:
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
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND td.group_id = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region, linked_gid))
        else:
            # Fallback: find the most recent non-none active threat for this region
            cursor.execute('''
                SELECT th.id, th.timestamp, th.threat_level, th.threat_type, th.confidence
                FROM threat_history th
                JOIN paired_events pe ON th.id = pe.threat_event_id
                WHERE th.region = ? AND pe.lifecycle_status = 'active'
                ORDER BY th.timestamp DESC LIMIT 1
            ''', (region,))
        
        row = cursor.fetchone()
        if not row:
            # No active threat to clear (e.g. already cleared manually by telegram_monitor.py)
            conn.close()
            return None
            
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
            # Check if it was already confirmed in real-time (by official alarm)
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
            
            # Додатково закриваємо всі інші завислі активні події для цього регіону (якщо це загальний відбій)
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
# region -> {"active_threats": {threat_id: {...}}, "is_active": bool, "level": str}
last_logged_states = {}

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
    
    # Retrieve previous state structure
    prev_state_dict = last_logged_states.get(region)
    if not isinstance(prev_state_dict, dict) or "active_threats" not in prev_state_dict:
        # Migrate from old format (tuple) or initialize
        old_val = last_logged_states.get(region)
        if isinstance(old_val, tuple) and len(old_val) == 3:
            p_level, p_active, p_type = old_val
            dummy_threats = {}
            if p_level != "none" and p_type and p_type != "official_alarm":
                dummy_threats["dummy_id"] = {
                    "level": p_level,
                    "threat_type": p_type,
                    "detail": "Попередньо виявлена загроза",
                    "confidence": 75,
                    "is_predictive": False,
                    "is_test": False
                }
            prev_state_dict = {
                "active_threats": dummy_threats,
                "is_active": p_active,
                "level": p_level
            }
        else:
            prev_state_dict = {
                "active_threats": {},
                "is_active": False,
                "level": "none"
            }
            
    prev_active = prev_state_dict["is_active"]
    prev_level = prev_state_dict["level"]
    prev_active_threats = prev_state_dict["active_threats"]
    
    is_batch = getattr(threat_manager, '_batch_mode', False)
    
    # 1. Official air alarm status change logging
    if prev_active != state.is_active:
        log_level = "high" if state.is_active else "none"
        detail = "Повітряна тривога" if state.is_active else "Відбій повітряної тривоги"
        safe_run_task(asyncio.to_thread(log_threat_to_db, region, log_level, "official_alarm", detail))
        
        # Validate Gemini predictions when official alarm turns ON
        if state.is_active:
            safe_run_task(asyncio.to_thread(validate_prediction_on_alarm, region))
        else:
            # Official alarm turned OFF -> Close paired event for official alarm in SQLite
            clearing_telemetry = {
                "resolution_type": "all_clear_official",
                "prediction_accuracy_hint": "confirmed"
            }
            safe_run_task(asyncio.to_thread(
                log_clearing_to_db,
                region=region,
                clearing_telemetry=clearing_telemetry,
                source_channel="official_alarm",
                message_text="Відбій повітряної тривоги (офіційно)",
                is_test=state.is_test
            ))
        
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
            
    # 2. AI/Telegram threat level/type changes tracking
    # Build dictionary of current active threats
    curr_active_threats = {
        t.threat_id: {
            "level": t.level,
            "threat_type": t.threat_type,
            "detail": t.detail,
            "confidence": t.confidence,
            "is_predictive": getattr(t, "is_predictive", False),
            "is_test": t.is_test
        }
        for t in state.active_threats
        if t.threat_type and t.threat_type != "official_alarm"
    }
    
    # Detect added threats
    added_ids = set(curr_active_threats.keys()) - set(prev_active_threats.keys())
    for tid in added_ids:
        t_data = curr_active_threats[tid]
        safe_run_task(asyncio.to_thread(
            log_threat_to_db,
            region=region,
            level=t_data["level"],
            threat_type=t_data["threat_type"],
            detail=t_data["detail"],
            confidence=t_data["confidence"],
            telemetry=telemetry,
            rules_applied=rules_applied,
            is_predictive=t_data["is_predictive"]
        ))
        
        if is_batch:
            from datetime import datetime, timezone
            import time
            doc_data = {
                "id": int(time.time() * 1000),
                "region": region,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "threat_level": t_data["level"],
                "threat_type": t_data["threat_type"],
                "detail": t_data["detail"],
                "confidence": t_data["confidence"],
                "is_test": t_data["is_test"]
            }
            if telemetry:
                doc_data["telemetry"] = telemetry
            _history_batch_buffer.append(doc_data)
        else:
            safe_run_task(asyncio.to_thread(
                log_threat_to_firestore,
                region=region,
                level=t_data["level"],
                threat_type=t_data["threat_type"],
                detail=t_data["detail"],
                confidence=t_data["confidence"],
                telemetry=telemetry,
                is_test=t_data["is_test"]
            ))
            
    # Detect cleared threats
    cleared_ids = set(prev_active_threats.keys()) - set(curr_active_threats.keys())
    for tid in cleared_ids:
        t_data = prev_active_threats[tid]
        safe_run_task(asyncio.to_thread(
            log_threat_to_db,
            region,
            "none",
            t_data["threat_type"],
            "Відбій загрози"
        ))
        
        # Determine prediction accuracy and resolution type
        resolution_type = "expired"
        prediction_accuracy = "overestimated"
        if state.is_active:
            prediction_accuracy = "confirmed"
            resolution_type = "impact"
            
        c_telemetry = telemetry if telemetry else {
            "resolution_type": resolution_type,
            "prediction_accuracy_hint": prediction_accuracy,
            "damage_assessment": "unknown",
            "impact_confirmed": state.is_active
        }
        
        safe_run_task(asyncio.to_thread(
            log_clearing_to_db,
            region=region,
            clearing_telemetry=c_telemetry,
            source_channel="auto_clear" if not state.is_active else "official_alarm",
            message_text="Автоматичне зняття загрози або відбій тривоги",
            is_test=t_data["is_test"]
        ))
        
        if is_batch:
            from datetime import datetime, timezone
            import time
            _history_batch_buffer.append({
                "id": int(time.time() * 1000),
                "region": region,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
                "threat_level": "none",
                "threat_type": t_data["threat_type"],
                "detail": "Відбій загрози",
                "confidence": None,
                "is_test": t_data["is_test"]
            })
        else:
            safe_run_task(asyncio.to_thread(
                log_threat_to_firestore,
                region,
                "none",
                t_data["threat_type"],
                "Відбій загрози",
                is_test=t_data["is_test"]
            ))
            
    # Save structured state to last_logged_states
    last_logged_states[region] = {
        "active_threats": curr_active_threats,
        "is_active": state.is_active,
        "level": state.level
    }

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

    # Відновлення БД SQLite з Firestore (якщо локальна БД порожня)
    try:
        from mock_mode import restore_sqlite_from_firestore
        await asyncio.to_thread(restore_sqlite_from_firestore)
    except Exception as e:
        print(f"⚠️ Помилка автоматичного відновлення SQLite: {e}")

    # Завантаження збереженого стану загроз (асинхронно у фоновому пулі)
    try:
        await asyncio.to_thread(threat_manager.load_from_db)
        # Ініціалізація відслідковуваного стану після завантаження
        for r, s in threat_manager.threats.items():
            last_logged_states[r] = {
                "active_threats": {
                    t.threat_id: {
                        "level": t.level,
                        "threat_type": t.threat_type,
                        "detail": t.detail,
                        "confidence": t.confidence,
                        "is_predictive": getattr(t, "is_predictive", False),
                        "is_test": t.is_test
                    }
                    for t in s.active_threats
                    if t.threat_type and t.threat_type != "official_alarm"
                },
                "is_active": s.is_active,
                "level": s.level
            }
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

    # Створення фінальної резервної копії SQLite у Firestore перед вимкненням сервера
    try:
        from mock_mode import backup_sqlite_to_firestore
        await asyncio.to_thread(backup_sqlite_to_firestore)
        print("💾 [Lifespan Shutdown] Фінальний бекап SQLite успішно створено.")
    except Exception as e:
        print(f"⚠️ [Lifespan Shutdown] Помилка створення фінального бекапу: {e}")


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


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Log HTTP exceptions >= 400
    if exc.status_code >= 400:
        safe_run_task(asyncio.to_thread(
            log_error_to_db,
            "server",
            str(exc.detail),
            str(request.url.path),
            f"method={request.method}, status={exc.status_code}",
            "auth" if exc.status_code in [401, 403] else ("500_server" if exc.status_code >= 500 else "general")
        ))
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    error_msg = str(exc.errors())
    safe_run_task(asyncio.to_thread(
        log_error_to_db,
        "server",
        error_msg,
        str(request.url.path),
        f"method={request.method}",
        "general"
    ))
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )

@app.exception_handler(Exception)
async def custom_global_exception_handler(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    error_str = f"{str(exc)}\n{tb}"
    safe_run_task(asyncio.to_thread(
        log_error_to_db,
        "server",
        error_str,
        str(request.url.path),
        f"method={request.method}",
        "systemic"
    ))
    # Trigger Firestore backup so the error log is captured immediately
    try:
        from mock_mode import backup_sqlite_to_firestore
        safe_run_task(asyncio.to_thread(backup_sqlite_to_firestore))
    except Exception:
        pass
    return JSONResponse(
        status_code=500,
        content={"detail": "Внутрішня помилка сервера. Помилку записано в системний лог."},
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
    """Health-check для Render / моніторингу."""
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.2.0",
        "status": "running",
        "mode": "live" if is_live_mode else "mock",
        "telegram_connected": telegram_monitor is not None and telegram_monitor.is_running,
        "shelters_loaded": shelter_manager.total_count,
    }

@app.head("/")
async def root_health():
    """Health-check для Render / моніторингу."""
    return {
        "service": "SirenUA Threat Monitor",
        "version": "1.2.0",
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
async def get_rules(active_only: bool = True, rule_type: str = None, limit: int = 50, threat_type: str = None):
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
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
        
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
            try:
                import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            except Exception:
                from backports import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
            from datetime import datetime
            dt = datetime.now(kiev_tz)
            offset_hours = int(dt.strftime('%z')[:3])
        except Exception:
            offset_hours = 3  # Fallback to Kyiv default (UTC+3)
            
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
async def get_admin_chronology(region: str = None, days: int = 7, threat_type: str = None, was_predictive: int = None, prediction_accuracy: str = None):
    """Хронологія загроз: встановлення → зняття, з match_type."""
    try:
        try:
            try:
                import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            except Exception:
                from backports import zoneinfo
                kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
            
            from datetime import datetime
            dt = datetime.now(kiev_tz)
            offset_hours = int(dt.strftime('%z')[:3])
        except Exception:
            offset_hours = 3  # Fallback to Kyiv default (UTC+3)
            
        tz_modifier = f"'{offset_hours:+d} hours'"
        
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        day_filter = f'-{days} days'
        
        query = '''
            SELECT th.id, th.region, th.threat_level, th.threat_type,
                   th.timestamp as threat_timestamp,
                   th.detail as threat_detail,
                   pe.confidence_at_set, pe.confidence_at_clear,
                   pe.was_predictive, pe.prediction_accuracy,
                   pe.lifecycle_status, pe.duration_seconds,
                   pe.gemini_group_id,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type
            FROM threat_history th
            LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
            LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
            WHERE th.timestamp >= datetime('now', ?)
        '''
        params = [day_filter]
        
        if region:
            from urllib.parse import unquote
            query += " AND th.region = ?"
            params.append(unquote(region))
            
        if threat_type:
            query += " AND th.threat_type = ?"
            params.append(threat_type)
            
        if was_predictive is not None:
            query += " AND pe.was_predictive = ?"
            params.append(was_predictive)
            
        if prediction_accuracy:
            if prediction_accuracy == "match":
                query += " AND pe.prediction_accuracy = 'confirmed'"
            elif prediction_accuracy == "mismatch":
                query += " AND pe.prediction_accuracy = 'overestimated'"
            elif prediction_accuracy == "mitigated":
                query += " AND pe.prediction_accuracy = 'mitigated'"
            elif prediction_accuracy == "active":
                query += " AND (pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL))"
            elif prediction_accuracy == "cleared":
                query += " AND (pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL))"
        
        query += " ORDER BY th.timestamp DESC LIMIT 500"
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        # Daily aggregation
        daily_agg_query = f'''
            SELECT date(datetime(th.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL) THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL) THEN 1 ELSE 0 END) as active,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM threat_history th
            LEFT JOIN paired_events pe ON th.id = pe.threat_event_id
            LEFT JOIN threat_clearings tc ON th.id = tc.original_threat_event_id
            WHERE th.timestamp >= datetime('now', ?)
        '''
        agg_params = [day_filter]
        if region:
            daily_agg_query += " AND th.region = ?"
            agg_params.append(unquote(region))
            
        if threat_type:
            daily_agg_query += " AND th.threat_type = ?"
            agg_params.append(threat_type)
            
        if was_predictive is not None:
            daily_agg_query += " AND pe.was_predictive = ?"
            agg_params.append(was_predictive)
            
        if prediction_accuracy:
            if prediction_accuracy == "match":
                daily_agg_query += " AND pe.prediction_accuracy = 'confirmed'"
            elif prediction_accuracy == "mismatch":
                daily_agg_query += " AND pe.prediction_accuracy = 'overestimated'"
            elif prediction_accuracy == "mitigated":
                daily_agg_query += " AND pe.prediction_accuracy = 'mitigated'"
            elif prediction_accuracy == "active":
                daily_agg_query += " AND (pe.lifecycle_status = 'active' OR (th.threat_type = 'official_alarm' AND tc.id IS NULL))"
            elif prediction_accuracy == "cleared":
                daily_agg_query += " AND (pe.lifecycle_status = 'cleared' OR (th.threat_type = 'official_alarm' AND tc.id IS NOT NULL))"
                
        daily_agg_query += " GROUP BY day ORDER BY day"
        
        cursor.execute(daily_agg_query, agg_params)
        daily_stats = [dict(r) for r in cursor.fetchall()]
        
        conn.close()
        
        events = []
        for row in rows:
            event = dict(row)
            # Determine match_type
            if event.get("threat_type") == "official_alarm":
                if event.get("clearing_timestamp"):
                    event["match_type"] = "cleared"
                else:
                    event["match_type"] = "official"
            elif event.get("prediction_accuracy") == "confirmed":
                event["match_type"] = "match"
            elif event.get("prediction_accuracy") == "mitigated":
                event["match_type"] = "mitigated"
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
async def get_admin_rules_history(days: int = 30, limit: int = 200, rule_type: str = None, action: str = None, threat_type: str = None):
    """Аудит-лог змін правил Gemini."""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        query = "SELECT * FROM gemini_rules_audit WHERE timestamp >= datetime('now', ?)"
        params = [f'-{days} days']
        
        if rule_type:
            query += " AND rule_type = ?"
            params.append(rule_type)
        if action:
            query += " AND action = ?"
            params.append(action)
        if threat_type:
            query += " AND threat_type = ?"
            params.append(threat_type)
            
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(min(limit, 500))
        
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()
        
        return {
            "total": len(rows),
            "entries": [dict(r) for r in rows]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ========================== ADMIN PANEL API v2 ==========================

@app.get("/api/admin/dashboard/stats")
async def get_admin_dashboard_stats():
    """Агреговані статистичні дані для дашборду."""
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
    except Exception:
        offset_hours = 3
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Total events (7d)
        cursor.execute("SELECT COUNT(*) as c FROM paired_events WHERE created_at >= datetime('now', '-7 days')")
        total_7d = cursor.fetchone()["c"]

        # Accuracy breakdown (7d)
        cursor.execute("""
            SELECT
                SUM(CASE WHEN prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                SUM(CASE WHEN prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                SUM(CASE WHEN prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                SUM(CASE WHEN lifecycle_status = 'active' THEN 1 ELSE 0 END) as active,
                COUNT(*) as total
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
        """)
        acc = dict(cursor.fetchone())

        # AI accuracy percentage
        evaluated = (acc["confirmed"] or 0) + (acc["mitigated"] or 0) + (acc["overestimated"] or 0)
        if evaluated > 0:
            accuracy_pct = round(((acc["confirmed"] or 0) + (acc["mitigated"] or 0) * 0.8) / evaluated * 100, 1)
        else:
            accuracy_pct = 0

        # Active threats right now
        cursor.execute("SELECT COUNT(*) as c FROM paired_events WHERE lifecycle_status = 'active'")
        active_now = cursor.fetchone()["c"]

        # Average response time (how early AI detected before alarm)
        cursor.execute("""
            SELECT AVG(
                strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)
            ) as avg_delta
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            JOIN threat_history th_alarm ON th_alarm.region = pe.region
                AND th_alarm.threat_type = 'official_alarm'
                AND th_alarm.threat_level = 'high'
                AND ABS(strftime('%s', th_alarm.timestamp) - strftime('%s', th_ai.timestamp)) < 1800
                AND strftime('%s', th_alarm.timestamp) >= strftime('%s', th_ai.timestamp)
            WHERE pe.created_at >= datetime('now', '-7 days')
                AND pe.was_predictive = 1
                AND pe.threat_type != 'official_alarm'
        """)
        avg_row = cursor.fetchone()
        avg_early_seconds = round(avg_row["avg_delta"]) if avg_row and avg_row["avg_delta"] else None

        # Threats by type (7d)
        cursor.execute("""
            SELECT threat_type, COUNT(*) as count
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
            GROUP BY threat_type ORDER BY count DESC
        """)
        by_type = [dict(r) for r in cursor.fetchall()]

        # Top regions (7d)
        cursor.execute("""
            SELECT region, COUNT(*) as count
            FROM paired_events
            WHERE created_at >= datetime('now', '-7 days') AND threat_type != 'official_alarm'
            GROUP BY region ORDER BY count DESC LIMIT 10
        """)
        top_regions = [dict(r) for r in cursor.fetchall()]

        # Hourly distribution (7d) — UTC to Kyiv
        cursor.execute(f"""
            SELECT CAST(strftime('%H', datetime(th.timestamp, {tz_modifier})) AS INTEGER) as hour,
                   COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th ON pe.threat_event_id = th.id
            WHERE pe.created_at >= datetime('now', '-7 days') AND pe.threat_type != 'official_alarm'
            GROUP BY hour ORDER BY hour
        """)
        hourly = [dict(r) for r in cursor.fetchall()]

        # Errors count (24h)
        cursor.execute("SELECT COUNT(*) as c FROM error_log WHERE timestamp >= datetime('now', '-1 day')")
        errors_24h = cursor.fetchone()["c"]

        conn.close()

        return {
            "total_events_7d": total_7d,
            "accuracy": acc,
            "accuracy_pct": accuracy_pct,
            "active_now": active_now,
            "avg_early_seconds": avg_early_seconds,
            "by_type": by_type,
            "top_regions": top_regions,
            "hourly": hourly,
            "errors_24h": errors_24h
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/admin/chronology/v2")
async def get_admin_chronology_v2(
    region: str = None,
    date_from: str = None,
    date_to: str = None,
    days: int = 7,
    threat_type: str = None,
    match_result: str = None,
    confidence_min: int = None,
    confidence_max: int = None,
    limit: int = 300
):
    """Хронологія з кореляцією AI-детекцій та офіційних тривог.
    
    Для кожної AI-події шукає найближчу офіційну тривогу в ±30хв вікні
    та обчислює time_delta, match_reason, та включає telemetry summary.
    """
    try:
        try:
            import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        except Exception:
            from backports import zoneinfo
            kiev_tz = zoneinfo.ZoneInfo("Europe/Kiev")
        from datetime import datetime
        dt = datetime.now(kiev_tz)
        offset_hours = int(dt.strftime('%z')[:3])
    except Exception:
        offset_hours = 3
    tz_modifier = f"'{offset_hours:+d} hours'"

    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Date filter
        if date_from and date_to:
            date_clause = "AND th_ai.timestamp BETWEEN ? AND ?"
            date_params = [date_from, date_to + " 23:59:59"]
        else:
            date_clause = "AND th_ai.timestamp >= datetime('now', ?)"
            date_params = [f'-{days} days']

        # Build WHERE conditions
        where_extra = ""
        extra_params = []
        if region:
            from urllib.parse import unquote
            where_extra += " AND pe.region = ?"
            extra_params.append(unquote(region))
        if threat_type:
            where_extra += " AND pe.threat_type = ?"
            extra_params.append(threat_type)
        if confidence_min is not None:
            where_extra += " AND pe.confidence_at_set >= ?"
            extra_params.append(confidence_min)
        if confidence_max is not None:
            where_extra += " AND pe.confidence_at_set <= ?"
            extra_params.append(confidence_max)

        # Filter by match_result (applied in post-processing after correlation)
        match_filter = match_result

        # Main query: AI threat events with telemetry
        query = f"""
            SELECT pe.id, pe.region, pe.threat_level, pe.threat_type,
                   pe.confidence_at_set, pe.confidence_at_clear,
                   pe.was_predictive, pe.prediction_accuracy,
                   pe.lifecycle_status, pe.duration_seconds,
                   pe.gemini_group_id,
                   th_ai.timestamp as ai_timestamp,
                   th_ai.detail as threat_detail,
                   td.attack_vector, td.target_count, td.speed_kmh,
                   td.weapon_subtype, td.launch_origin, td.altitude_category,
                   td.distance_to_target_km, td.event_phase,
                   td.source_reliability, td.civilian_risk_level,
                   tc.timestamp as clearing_timestamp,
                   tc.resolution_type
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            LEFT JOIN telemetry_data td ON td.threat_event_id = th_ai.id
            LEFT JOIN threat_clearings tc ON pe.clearing_event_id = tc.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause}
            {where_extra}
            ORDER BY th_ai.timestamp DESC
            LIMIT ?
        """
        params = date_params + extra_params + [min(limit, 500)]
        cursor.execute(query, params)
        ai_events = [dict(r) for r in cursor.fetchall()]

        # Get all official alarm timestamps for correlation
        alarm_query = f"""
            SELECT region, timestamp, threat_level, id
            FROM threat_history
            WHERE threat_type = 'official_alarm'
            AND threat_level = 'high'
            {date_clause.replace('th_ai.timestamp', 'timestamp')}
            ORDER BY timestamp
        """
        cursor.execute(alarm_query, date_params)
        alarm_rows = cursor.fetchall()

        # Build alarm lookup: region -> [(timestamp_epoch, ts_str)]
        from datetime import datetime as dt_cls
        alarm_by_region = {}
        for ar in alarm_rows:
            r = ar["region"]
            if r not in alarm_by_region:
                alarm_by_region[r] = []
            ts_str = ar["timestamp"]
            try:
                ts_epoch = dt_cls.fromisoformat(ts_str.replace('Z', '+00:00') if ts_str else "").timestamp()
            except Exception:
                try:
                    ts_epoch = dt_cls.strptime(ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    continue
            alarm_by_region[r].append({"epoch": ts_epoch, "ts": ts_str})

        # Correlate each AI event with nearest official alarm
        correlated_events = []
        for ev in ai_events:
            ai_ts_str = ev.get("ai_timestamp", "")
            try:
                ai_epoch = dt_cls.fromisoformat(ai_ts_str.replace('Z', '+00:00') if ai_ts_str else "").timestamp()
            except Exception:
                try:
                    ai_epoch = dt_cls.strptime(ai_ts_str, "%Y-%m-%d %H:%M:%S").timestamp()
                except Exception:
                    ai_epoch = None

            # Find nearest alarm within ±30min window
            best_alarm = None
            best_delta = None
            region_alarms = alarm_by_region.get(ev["region"], [])
            if ai_epoch:
                for alarm in region_alarms:
                    delta = alarm["epoch"] - ai_epoch  # positive = AI was first
                    if abs(delta) <= 1800:  # 30 min window
                        if best_delta is None or abs(delta) < abs(best_delta):
                            best_delta = delta
                            best_alarm = alarm

            ev["alarm_timestamp"] = best_alarm["ts"] if best_alarm else None
            ev["time_delta_seconds"] = round(best_delta) if best_delta is not None else None

            # Determine match_type and match_reason
            pred_acc = ev.get("prediction_accuracy")
            lifecycle = ev.get("lifecycle_status")

            if pred_acc == "confirmed" or (best_alarm and best_delta is not None and abs(best_delta) <= 1800):
                ev["match_type"] = "confirmed"
                if best_delta is not None:
                    if best_delta > 0:
                        mins = round(best_delta / 60)
                        ev["match_reason"] = f"AI визначив загрозу за {mins} хв до офіційної тривоги"
                    elif best_delta < 0:
                        mins = round(abs(best_delta) / 60)
                        ev["match_reason"] = f"Офіційна тривога була за {mins} хв до AI-детекції"
                    else:
                        ev["match_reason"] = "AI та офіційна тривога одночасно"
                else:
                    ev["match_reason"] = "Підтверджено через lifecycle"
            elif pred_acc == "mitigated":
                ev["match_type"] = "mitigated"
                ev["match_reason"] = "Загрозу нейтралізовано (ППО/РЕБ)"
            elif pred_acc == "overestimated":
                ev["match_type"] = "overestimated"
                ev["match_reason"] = "Тривога не підтверджена — AI переоцінив загрозу"
            elif lifecycle == "active":
                ev["match_type"] = "active"
                ev["match_reason"] = "Загроза ще активна, очікуємо результат"
            else:
                ev["match_type"] = "cleared"
                ev["match_reason"] = "Знято без кореляції з офіційною тривогою"

            # Telemetry summary
            telem_parts = []
            if ev.get("attack_vector") and ev["attack_vector"] != "unknown":
                telem_parts.append(ev["attack_vector"])
            if ev.get("weapon_subtype"):
                telem_parts.append(ev["weapon_subtype"])
            if ev.get("target_count") and ev["target_count"] > 0:
                telem_parts.append(f"{ev['target_count']} цілей")
            if ev.get("speed_kmh") and ev["speed_kmh"] > 0:
                telem_parts.append(f"{ev['speed_kmh']} км/г")
            if ev.get("launch_origin"):
                telem_parts.append(f"з {ev['launch_origin']}")
            ev["telemetry_summary"] = " | ".join(telem_parts) if telem_parts else None

            correlated_events.append(ev)

        # Apply match_filter
        if match_filter:
            if match_filter == "match":
                correlated_events = [e for e in correlated_events if e["match_type"] == "confirmed"]
            elif match_filter == "mitigated":
                correlated_events = [e for e in correlated_events if e["match_type"] == "mitigated"]
            elif match_filter == "mismatch":
                correlated_events = [e for e in correlated_events if e["match_type"] == "overestimated"]
            elif match_filter == "active":
                correlated_events = [e for e in correlated_events if e["match_type"] == "active"]

        # Aggregate stats
        stats = {
            "confirmed": sum(1 for e in correlated_events if e["match_type"] == "confirmed"),
            "mitigated": sum(1 for e in correlated_events if e["match_type"] == "mitigated"),
            "overestimated": sum(1 for e in correlated_events if e["match_type"] == "overestimated"),
            "active": sum(1 for e in correlated_events if e["match_type"] == "active"),
            "cleared": sum(1 for e in correlated_events if e["match_type"] == "cleared"),
        }

        # Time delta distribution (for histogram)
        deltas = [e["time_delta_seconds"] for e in correlated_events if e["time_delta_seconds"] is not None]
        delta_buckets = {}
        for d in deltas:
            bucket = (d // 60) * 60  # Round to nearest minute
            bucket_label = f"{int(bucket // 60)} хв"
            delta_buckets[bucket_label] = delta_buckets.get(bucket_label, 0) + 1

        # Daily aggregation for charts
        daily_agg_query = f"""
            SELECT date(datetime(th_ai.timestamp, {tz_modifier})) as day,
                   COUNT(*) as total_events,
                   SUM(CASE WHEN pe.lifecycle_status = 'cleared' THEN 1 ELSE 0 END) as cleared,
                   SUM(CASE WHEN pe.prediction_accuracy = 'confirmed' THEN 1 ELSE 0 END) as confirmed,
                   SUM(CASE WHEN pe.prediction_accuracy = 'overestimated' THEN 1 ELSE 0 END) as overestimated,
                   SUM(CASE WHEN pe.prediction_accuracy = 'mitigated' THEN 1 ELSE 0 END) as mitigated,
                   SUM(CASE WHEN pe.was_predictive = 1 THEN 1 ELSE 0 END) as predictive
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause.replace('th_ai.timestamp', 'th_ai.timestamp')}
            {where_extra}
            GROUP BY day ORDER BY day
        """
        agg_params = date_params + extra_params
        cursor.execute(daily_agg_query, agg_params)
        daily_stats = [dict(r) for r in cursor.fetchall()]

        # Threat type breakdown for charts
        cursor.execute(f"""
            SELECT pe.threat_type, pe.prediction_accuracy, COUNT(*) as count
            FROM paired_events pe
            JOIN threat_history th_ai ON pe.threat_event_id = th_ai.id
            WHERE pe.threat_type != 'official_alarm'
            {date_clause.replace('th_ai.timestamp', 'th_ai.timestamp')}
            {where_extra}
            GROUP BY pe.threat_type, pe.prediction_accuracy
        """, date_params + extra_params)
        type_breakdown = [dict(r) for r in cursor.fetchall()]

        conn.close()

        return {
            "total": len(correlated_events),
            "stats": stats,
            "events": correlated_events,
            "daily_stats": daily_stats,
            "delta_distribution": delta_buckets,
            "type_breakdown": type_breakdown
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=str(e))




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
