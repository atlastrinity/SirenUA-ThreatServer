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

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
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
            confidence INTEGER
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
            FOREIGN KEY (original_threat_event_id) REFERENCES threat_history(id)
        )
    ''')
    
    # Indexes for clearings
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_region ON threat_clearings(region)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_group ON threat_clearings(linked_group_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_original ON threat_clearings(original_threat_event_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_resolution ON threat_clearings(resolution_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_clearings_prediction ON threat_clearings(prediction_accuracy_hint)')
    
    conn.commit()
    conn.close()
    print("💾 Аналітична БД ініціалізована (threat_history + telemetry_data + threat_clearings)")

def log_threat_to_db(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None):
    """Log threat event and its telemetry to SQLite. Returns the threat_event_id."""
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO threat_history (region, threat_level, threat_type, detail, confidence) VALUES (?, ?, ?, ?, ?)",
            (region, level, threat_type, detail, confidence)
        )
        event_id = cursor.lastrowid
        
        # Insert telemetry if provided
        if telemetry and isinstance(telemetry, dict) and event_id:
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
                telemetry.get("group_id"),
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
        
        conn.commit()
        conn.close()
        return event_id
    except Exception as e:
        print(f"⚠️ Помилка запису в БД аналітики: {e}")
        return None

def log_threat_to_firestore(region: str, level: str, threat_type: str, detail: str = None, confidence: int = None, telemetry: dict = None, is_test: bool = False):
    """Log threat event to Firebase Firestore."""
    db = get_db()
    if not db:
        return
    try:
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
            
        db.collection('sirenua_history').add(doc_data)
        print(f"🔥 Logged history event to Firestore for {region}: {level} ({threat_type}, is_test={is_test})")
    except Exception as e:
        print(f"⚠️ Помилка запису історії в Firestore: {e}")

def log_clearing_to_db(region: str, clearing_telemetry: dict = None,
                       source_channel: str = None, message_text: str = None,
                       clearing_confidence: int = None, was_predictive: bool = False):
    """Log threat clearing event with full lifecycle data linked to original threat."""
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
                from datetime import datetime
                set_time = datetime.fromisoformat(threat_set_ts.replace('Z', '+00:00') if threat_set_ts else "")
                now = datetime.utcnow()
                threat_duration_sec = int((now - set_time.replace(tzinfo=None)).total_seconds())
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
                threat_set_timestamp, threat_duration_seconds
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            threat_duration_sec
        ))
        
        clearing_id = cursor.lastrowid
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
        return None

# --- WebSockets Manager ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        # Відправляємо оновлення всім клієнтам паралельно
        msg_text = json.dumps(message)
        dead_connections = []

        async def send(connection):
            try:
                await connection.send_text(msg_text)
            except Exception:
                dead_connections.append(connection)

        if self.active_connections:
            await asyncio.gather(*(send(conn) for conn in self.active_connections))
            
        for dead in dead_connections:
            self.disconnect(dead)

ws_manager = ConnectionManager()

# Глобальний менеджер загроз (in-memory)
threat_manager = MockThreatManager()
shelter_manager = ShelterManager()
telegram_monitor = None
is_live_mode = "--live" in sys.argv or os.environ.get("LIVE_MODE", "false").lower() == "true"

# Track last logged threat states to avoid duplicate logging and properly detect changes
last_logged_states = {}  # region -> (level, is_active, threat_type)

def on_threat_changed(region, state, telemetry=None):
    global last_logged_states
    prev_level, prev_active, prev_type = last_logged_states.get(region, ("none", False, None))
    
    # 1. Official air alarm status change logging
    if prev_active != state.is_active:
        log_level = "high" if state.is_active else "none"
        detail = "Повітряна тривога" if state.is_active else "Відбій повітряної тривоги"
        asyncio.create_task(asyncio.to_thread(log_threat_to_db, region, log_level, "official_alarm", detail))
        asyncio.create_task(asyncio.to_thread(log_threat_to_firestore, region, log_level, "official_alarm", detail, is_test=state.is_test))
        
    # 2. AI/Telegram threat level change logging
    if prev_level != state.level:
        current_type = state.threat_type
        if (current_type and current_type != "official_alarm") or (prev_type and prev_type != "official_alarm" and state.level == "none"):
            if state.level != "none":
                asyncio.create_task(asyncio.to_thread(log_threat_to_db, region, state.level, current_type, state.detail, state.confidence, telemetry=telemetry))
                asyncio.create_task(asyncio.to_thread(log_threat_to_firestore, region, state.level, current_type, state.detail, state.confidence, telemetry=telemetry, is_test=state.is_test))
            elif prev_level != "none":
                # Threat has cleared
                asyncio.create_task(asyncio.to_thread(log_threat_to_db, region, "none", prev_type, "Відбій загрози"))
                asyncio.create_task(asyncio.to_thread(log_threat_to_firestore, region, "none", prev_type, "Відбій загрози", is_test=state.is_test))
            
    last_logged_states[region] = (state.level, state.is_active, state.threat_type)

    asyncio.create_task(ws_manager.broadcast({
        "type": "threat_update",
        "region": region,
        "state": state.to_dict()
    }))

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
    """Фонова задача для опитування офіційного API тривог."""
    print("⏳ Запуск фонового опитування офіційних тривог з aerialalerts...")
    url = "https://ubilling.net.ua/aerialalerts/"
    headers = {"User-Agent": "SirenUA-ThreatServer/1.0"}
    
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=5.0) as response:
                    if response.status == 200:
                        data = await response.json()
                        states = data.get("states", {})
                        
                        # Оновлюємо стан кожної області
                        for region_name, state_data in states.items():
                            is_active = state_data.get("alertnow", False)
                            # Перевіряємо та оновлюємо стан на сервері
                            # (це автоматично надішле Push та WebSocket трансляцію)
                            threat_manager.set_alarm_active(region_name, is_active)
                    else:
                        print(f"⚠️ Помилка опитування тривог: HTTP статус {response.status}")
        except Exception as e:
            print(f"⚠️ Помилка під час опитування тривог: {e}")
        
        await asyncio.sleep(5.0)

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager — запуск/зупинка Telegram моніторингу."""
    global telegram_monitor, aerial_alerts_task
    
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

    # Завантаження бази укриттів з OpenStreetMap
    try:
        await shelter_manager.load()
        await shelter_manager.start_refresh_loop()
    except Exception as e:
        print(f"⚠️ Помилка завантаження укриттів: {e}")
    
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
    
    # Determine date range
    if date:
        try:
            target_date = dt.strptime(date, "%Y-%m-%d")
        except ValueError:
            raise HTTPException(status_code=400, detail="Невірний формат дати. Використовуйте YYYY-MM-DD")
    else:
        target_date = dt.utcnow()
    
    date_start = target_date.strftime("%Y-%m-%d 00:00:00")
    date_end = (target_date + timedelta(days=1)).strftime("%Y-%m-%d 00:00:00")
        
    try:
        # Fetch matching documents from Firestore filtered by date range
        docs = await asyncio.to_thread(
            lambda: db.collection('sirenua_history')
                      .where('region', '==', region)
                      .where('timestamp', '>=', date_start)
                      .where('timestamp', '<', date_end)
                      .order_by('timestamp', direction='DESCENDING')
                      .limit(min(limit, 200))
                      .get()
        )
        
        events = []
        for doc in docs:
            d = doc.to_dict()
            events.append(d)
        
        return {
            "region": region,
            "date": target_date.strftime("%Y-%m-%d"),
            "count": len(events),
            "events": events
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint для отримання живих оновлень загроз."""
    await ws_manager.connect(websocket)
    try:
        # Відправляємо поточний стан одразу при підключенні
        await websocket.send_text(json.dumps({
            "type": "initial_state",
            "threats": threat_manager.get_all_threats()
        }))
        
        while True:
            # Очікуємо повідомлень (keep-alive)
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


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
        threat_manager.clear_all()
    else:
        threat_manager.set_scenario(request.scenario)

    return {"status": "ok", "scenario": request.scenario}


@app.post("/api/threats/clear")
async def clear_all_threats():
    """Очистити всі загрози."""
    threat_manager.clear_all(only_test=True)
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
