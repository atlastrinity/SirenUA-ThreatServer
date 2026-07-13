import sys
import os
import asyncio
import sqlite3

# Set env keys before importing analyzer to ensure is_configured is True
os.environ["GEMINI_API_KEYS"] = "dummy_key_for_testing"

# Add threat_server path to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.threat_state import MockThreatManager
from core.regions import ALL_REGIONS
from monitor.telegram_monitor import TelegramThreatMonitor
from core.config import DB_PATH
from database.analytics_db import init_analytics_db, on_threat_changed
import google.generativeai as genai

class TestThreatManager(MockThreatManager):
    def __init__(self):
        super().__init__()
        self.sent_notifications = []

    def set_threat(self, region: str, level: str, threat_type=None, detail=None, *args, **kwargs):
        res = super().set_threat(region, level, threat_type, detail, *args, **kwargs)
        self.sent_notifications.append({
            "action": "set",
            "region": region,
            "level": level,
            "type": threat_type,
            "detail": detail
        })
        return res

    def clear_threat(self, region: str, *args, **kwargs) -> bool:
        res = super().clear_threat(region, *args, **kwargs)
        self.sent_notifications.append({
            "action": "clear",
            "region": region,
            "level": "none",
            "type": None,
            "detail": None
        })
        return res

async def main():
    print("==================================================")
    print("🧪 Запуск тестування авто-переоцінки загроз")
    print("==================================================\n")

    # Ініціалізуємо аналітичну БД
    init_analytics_db()

    # Очищаємо таблиці для чистоти тесту
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM paired_events")
    cursor.execute("DELETE FROM threat_history")
    cursor.execute("DELETE FROM threat_clearings")
    cursor.execute("DELETE FROM error_log")
    conn.commit()
    conn.close()

    threat_manager = TestThreatManager()
    threat_manager.on_change = on_threat_changed
    
    monitor = TelegramThreatMonitor(threat_manager)
    monitor.is_running = True

    # Мокаємо асинхронний метод Gemini генерації для тестування переоцінки
    async def mock_generate_content_async(self_model, *args, **kwargs):
        print("   [Мок Gemini] Отримано запит на переоцінку. Повертаю рішення: INACTIVE (expired / overestimated)")
        class MockResponse:
            text = '{"is_active": false, "resolution_type": "expired", "prediction_accuracy": "overestimated", "reasoning_ukr": "Час ETA минув, офіційна сирена не включилася, нових повідомлень про цілі немає."}'
        return MockResponse()

    genai.GenerativeModel.generate_content_async = mock_generate_content_async

    # 1. Симулюємо отримання повідомлень з каналів, щоб наповнити buffers
    print("📌 Крок 1: Отримання вхідних повідомлень...")
    test_msgs = [
        ("monitorwarr", "Зафіксовано рух БПЛА типу Shahed з півдня через Запорізьку область."),
        ("monitorwarr", "Шахед у напрямку Дніпропетровщини."),
        ("kpszsu", "Загроза ударних БПЛА для Запорізької, Дніпропетровської областей!"),
        ("monitorwarr", "Шахед пролітає в бік Полтавщини."),
        ("kpszsu", "Полтавська область — загроза застосування ворожих БПЛА!"),
    ]

    for channel, text in test_msgs:
        await monitor._process_message(text, channel)

    # 2. Симулюємо Gemini-аналіз з предиктивною загрозою для Полтавської області
    print("\n📌 Крок 2: Емуляція отримання предиктивної загрози...")
    region = "Полтавська область"
    
    # Очистимо старі загрози перед тестом
    threat_manager.clear_all()
    threat_manager.sent_notifications.clear()

    results = [{
        "source_channel": "kpszsu",
        "text": "Полтавська область — загроза застосування ворожих БПЛА!",
        "threat_level": "medium",
        "threat_type": "shahed",
        "source_regions": [],
        "target_regions": [{"name": "Полтавська область", "is_predictive": True}],
        "is_clear": False,
        "confidence_score": 70,
        "eta": "~1-2 год",
        "telemetry": {
            "group_id": "shahed_test_1",
            "speed_kmh": 150,
            "distance_to_target_km": 100
        },
        "rules_applied": []
    }]
    
    await monitor._apply_gemini_analysis(results)

    # Дамо циклу подій трохи часу на виконання асинхронних записів у БД
    await asyncio.sleep(0.5)

    # Перевіримо, що таск переоцінки заплановано
    reeval_key = (region, "shahed", "shahed_test_1")
    if reeval_key in monitor._reevaluation_tasks:
        print(f"✅ Таск переоцінки успішно заплановано!")
    else:
        print(f"❌ Помилка: таск переоцінки не заплановано!")

    # 3. Чекаємо виконання переоцінки (ETA 2400 сек + 300 сек grace_period)
    print("\n📌 Крок 3: Очікування виконання авто-переоцінки...")
    
    await monitor._run_predictive_reevaluation(region, "shahed", "shahed_test_1")
    await asyncio.sleep(0.5)

    # 4. Перевіряємо результати в БД та менеджері загроз
    print("\n📌 Крок 4: Перевірка результатів...")
    
    # Загроза має бути знята в менеджері
    state = threat_manager.threats[region]
    print(f"📊 Поточний рівень загрози для {region}: {state.level} (має бути none)")

    # Друкуємо вміст таблиць для відлагодження
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    print("\n=== Вміст threat_history ===")
    cursor.execute("SELECT * FROM threat_history")
    for r in cursor.fetchall():
        print(dict(r))
        
    print("\n=== Вміст paired_events ===")
    cursor.execute("SELECT * FROM paired_events")
    for r in cursor.fetchall():
        print(dict(r))
        
    print("\n=== Вміст error_log ===")
    cursor.execute("SELECT * FROM error_log")
    for r in cursor.fetchall():
        print(dict(r))
        
    conn.close()

if __name__ == "__main__":
    asyncio.run(main())
