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

from mock_mode import MockThreatManager
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
            threat_type TEXT
        )
    ''')
    conn.commit()
    conn.close()

def log_threat_to_db(region: str, level: str, threat_type: str):
    if level == "none":
        return
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO threat_history (region, threat_level, threat_type) VALUES (?, ?, ?)",
            (region, level, threat_type)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"⚠️ Помилка запису в БД аналітики: {e}")

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

# Hook up MockThreatManager to WebSockets and DB
def on_threat_changed(region, state):
    log_threat_to_db(region, state.level, state.threat_type)
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
    threat_manager.clear_all()
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
            await telegram_monitor._apply_gemini_analysis(results)
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
