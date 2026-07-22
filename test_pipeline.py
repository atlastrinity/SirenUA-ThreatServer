import sys
import os
import asyncio
import re

# Add threat_server path to sys.path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from core.threat_state import MockThreatManager
from core.regions import ALL_REGIONS
from monitor.telegram_monitor import TelegramThreatMonitor

class TestThreatManager(MockThreatManager):
    def __init__(self):
        super().__init__()
        self.sent_notifications = []

    def set_threat(self, region: str, level: str, threat_type=None, detail=None, *args, **kwargs):
        res = super().set_threat(region, level, threat_type, detail, *args, **kwargs)
        self.sent_notifications.append({
            "region": region,
            "level": level,
            "type": threat_type,
            "detail": detail
        })
        return res

    def clear_threat(self, region: str, *args, **kwargs) -> bool:
        res = super().clear_threat(region, *args, **kwargs)
        self.sent_notifications.append({
            "region": region,
            "level": "none",
            "type": None,
            "detail": None
        })
        return res

    def clear_all(self, *args, **kwargs):
        super().clear_all(*args, **kwargs)
        for region in ALL_REGIONS:
            self.sent_notifications.append({
                "region": region,
                "level": "none",
                "type": None,
                "detail": None
            })

async def run_tests():
    print("==================================================")
    print("🧪 Запуск тестування повного циклу парсингу та логіки")
    print("==================================================\n")

    threat_manager = TestThreatManager()
    monitor = TelegramThreatMonitor(threat_manager)
    monitor.is_running = True

    # Тест 1: Зліт МіГ-31К (загальнонаціональна загроза HIGH)
    print("📌 Тест 1: Зліт МіГ-31К...")
    threat_manager.sent_notifications.clear()
    msg = "Увага! Зліт МіГ-31К з аеродрому Саваслейка! Загроза застосування ракет Кинджал по всій території України!"
    await monitor._process_message(msg, "kpszsu")
    
    assert len(threat_manager.sent_notifications) > 0, "Має бути надіслано сповіщення!"
    first_notif = threat_manager.sent_notifications[0]
    print(f"✅ Рівень загрози: {first_notif['level'].upper()}")
    print(f"✅ Тип загрози: {first_notif['type']}")
    print(f"✅ Областей активовано: {len(threat_manager.sent_notifications)}")
    print(f"✅ Приклад деталізації: {first_notif['detail']}")
    assert first_notif["level"] == "high"
    assert first_notif["type"] == "mig31k"
    print("--------------------------------------------------")

    # Тест 2: Шахеди в конкретних областях (MEDIUM)
    print("📌 Тест 2: Рух Шахедів у напрямку конкретних областей...")
    threat_manager.sent_notifications.clear()
    msg = "Шахеди з півдня! Зафіксовано рух ударних БпЛА в Одеській та Миколаївській областях. Напрямок на Кропивницький."
    await monitor._process_message(msg, "monitorwarr")
    
    regions = [n["region"] for n in threat_manager.sent_notifications]
    levels = [n["level"] for n in threat_manager.sent_notifications]
    types = [n["type"] for n in threat_manager.sent_notifications]
    
    print(f"✅ Виявлені області: {regions}")
    print(f"✅ Рівні загроз: {set(levels)}")
    print(f"✅ Типи загроз: {set(types)}")
    print(f"✅ Деталізація для Одеської: {[n['detail'] for n in threat_manager.sent_notifications if 'Одес' in n['region']][0]}")
    
    assert "Одеська область" in regions
    assert "Миколаївська область" in regions
    assert "Кіровоградська область" in regions
    assert all(lvl == "medium" for lvl in levels)
    assert all(t == "shahed" for t in types)
    print("--------------------------------------------------")

    # Тест 3: Загроза балістики (HIGH)
    print("📌 Тест 3: Загроза балістики з Криму...")
    threat_manager.sent_notifications.clear()
    msg = "Загроза балістики з Криму для Херсонської та Запорізької областей!"
    await monitor._process_message(msg, "eRadarrua")
    
    regions = [n["region"] for n in threat_manager.sent_notifications]
    levels = [n["level"] for n in threat_manager.sent_notifications]
    types = [n["type"] for n in threat_manager.sent_notifications]
    
    print(f"✅ Виявлені області: {regions}")
    print(f"✅ Рівні загроз: {set(levels)}")
    print(f"✅ Типи загроз: {set(types)}")
    
    assert "Херсонська область" in regions
    assert "Запорізька область" in regions
    assert all(lvl == "high" for lvl in levels)
    assert all(t == "ballistic" for t in types)
    print("--------------------------------------------------")

    # Тест 4: Ракети в напрямку (HIGH)
    print("📌 Тест 4: Ракети в напрямку області...")
    threat_manager.sent_notifications.clear()
    msg = "Увага! Крилаті ракети в повітряному просторі Київщини, напрямок на Васильків!"
    await monitor._process_message(msg, "vanek_nikolaev")
    
    regions = [n["region"] for n in threat_manager.sent_notifications]
    levels = [n["level"] for n in threat_manager.sent_notifications]
    types = [n["type"] for n in threat_manager.sent_notifications]
    
    print(f"✅ Виявлені області: {regions}")
    print(f"✅ Рівні загроз: {set(levels)}")
    print(f"✅ Типи загроз: {set(types)}")
    
    assert "Київська область" in regions
    assert all(lvl in ("high", "critical") for lvl in levels)
    assert all(t == "cruise_missile" for t in types)
    print("--------------------------------------------------")

    # Тест 5: Частковий відбій (NONE)
    print("📌 Тест 5: Частковий відбій тривоги...")
    threat_manager.sent_notifications.clear()
    msg = "Відбій повітряної тривоги в Одеській та Миколаївській областях."
    await monitor._process_message(msg, "kpszsu")
    
    cleared = [n for n in threat_manager.sent_notifications if n["level"] == "none"]
    regions = [n["region"] for n in cleared]
    print(f"✅ Скасовано загрозу для областей: {regions}")
    
    assert "Одеська область" in regions
    assert "Миколаївська область" in regions
    print("--------------------------------------------------")

    # Тест 6: Повний відбій (NONE для всіх)
    print("📌 Тест 6: Повний відбій...")
    threat_manager.sent_notifications.clear()
    msg = "Відбій загрози для всіх областей. Чисто."
    await monitor._process_message(msg, "kpszsu")
    
    cleared = [n for n in threat_manager.sent_notifications if n["level"] == "none"]
    print(f"✅ Скасовано загрозу для всіх {len(cleared)} областей України.")
    assert len(cleared) >= 24
    print("--------------------------------------------------")

    # Тест 7: Загроза КАБів (LOW, type kab)
    print("📌 Тест 7: Загроза КАБів...")
    threat_manager.sent_notifications.clear()
    msg = "🚀 КАБи на Донеччині"
    await monitor._process_message(msg, "kpszsu")
    
    regions = [n["region"] for n in threat_manager.sent_notifications]
    levels = [n["level"] for n in threat_manager.sent_notifications]
    types = [n["type"] for n in threat_manager.sent_notifications]
    
    print(f"✅ Виявлені області: {regions}")
    print(f"✅ Рівні загроз: {set(levels)}")
    print(f"✅ Типи загроз: {set(types)}")
    print(f"✅ Деталізація: {[n['detail'] for n in threat_manager.sent_notifications if 'Донецьк' in n['region']][0]}")
    
    assert "Донецька область" in regions
    assert all(lvl == "low" for lvl in levels)
    assert all(t == "kab" for t in types)
    print("--------------------------------------------------")

    # Тест 8: Макро-напрямок (Захід)
    print("📌 Тест 8: Макро-напрямок (Захід)...")
    threat_manager.sent_notifications.clear()
    msg = "Увага! Крилаті ракети в напрямку західних областей!"
    await monitor._process_message(msg, "kpszsu")
    regions = [n["region"] for n in threat_manager.sent_notifications]
    print(f"✅ Виявлені області: {regions}")
    assert "Львівська область" in regions
    assert "Хмельницька область" in regions
    assert "Волинська область" in regions
    print("--------------------------------------------------")

    # Тест 9: Специфічне місто (Старокостянтинів)
    print("📌 Тест 9: Специфічне місто (Старокостянтинів)...")
    threat_manager.sent_notifications.clear()
    msg = "БпЛА у бік Старокостянтинова!"
    await monitor._process_message(msg, "monitorwarr")
    regions = [n["region"] for n in threat_manager.sent_notifications]
    print(f"✅ Виявлені області: {regions}")
    assert "Хмельницька область" in regions
    print("--------------------------------------------------")

    # Тест 10: Варіант відмінка (Хмельниччину)
    print("📌 Тест 10: Варіант відмінка (Хмельниччину)...")
    threat_manager.sent_notifications.clear()
    msg = "Ракети на Хмельниччину!"
    await monitor._process_message(msg, "kpszsu")
    regions = [n["region"] for n in threat_manager.sent_notifications]
    print(f"✅ Виявлені області: {regions}")
    assert "Хмельницька область" in regions
    print("--------------------------------------------------")

    # Тест 11: Мікрорайон Києва (Оболонь)
    print("📌 Тест 11: Мікрорайон Києва (Оболонь)...")
    threat_manager.sent_notifications.clear()
    msg = "Шахед на Оболонь!"
    await monitor._process_message(msg, "monitorwarr")
    regions = [n["region"] for n in threat_manager.sent_notifications]
    print(f"✅ Виявлені області: {regions}")
    assert "м. Київ" in regions
    print("--------------------------------------------------")

    # Тест 12: Полтава без пробілу на початку повідомлення
    print("📌 Тест 12: Полтава на початку повідомлення...")
    threat_manager.sent_notifications.clear()
    msg = "Полтава — в укриття!"
    await monitor._process_message(msg, "monitorwarr")
    regions = [n["region"] for n in threat_manager.sent_notifications]
    print(f"✅ Виявлені області: {regions}")
    assert "Полтавська область" in regions
    print("--------------------------------------------------")

    # Тест 13: Змішане повідомлення (відбій + нова загроза)
    print("📌 Тест 13: Змішане повідомлення (відбій + нова загроза)...")
    threat_manager.set_threat("Одеська область", "medium", "shahed", "БпЛА в напрямку Одеси")
    threat_manager.sent_notifications.clear()
    msg = "Відбій повітряної тривоги на Одещині. Натомість зафіксовано пуски ракет у напрямку Хмельниччини!"
    await monitor._process_message(msg, "kpszsu")
    cleared = [n["region"] for n in threat_manager.sent_notifications if n["level"] == "none"]
    set_high = [n["region"] for n in threat_manager.sent_notifications if n["level"] == "high"]
    print(f"✅ Знято загрозу для: {cleared}")
    print(f"✅ Встановлено загрозу для: {set_high}")
    assert "Одеська область" in cleared
    assert "Хмельницька область" in set_high
    assert "Одеська область" not in set_high
    assert "Хмельницька область" not in cleared
    print("--------------------------------------------------")

    # Тест 14: Предиктивний аналіз (Вектори та транзитні області)
    print("📌 Тест 14: Предиктивний аналіз (Вектори та транзитні області)...")
    threat_manager.sent_notifications.clear()
    msg = "Шахеди на Сумщині! Рух у напрямку Київщини."
    await monitor._process_message(msg, "monitorwarr")
    regions = [n["region"] for n in threat_manager.sent_notifications if n["level"] == "medium"]
    print(f"✅ Виявлені області: {regions}")
    assert "Сумська область" in regions
    assert "Київська область" in regions
    assert "Чернігівська область" in regions or "Полтавська область" in regions
    print("--------------------------------------------------")

    # Тест 15: Розрахунок ETA (Кінематика)
    print("📌 Тест 15: Перевірка ETA (Кінематика) для балістики...")
    threat_manager.sent_notifications.clear()
    msg = "Загроза балістики з Криму на Харків!"
    await monitor._process_message(msg, "monitorwarr")
    kharkiv_threat = next((n for n in threat_manager.sent_notifications if n["region"] == "Харківська область"), None)
    print(f"✅ Деталізація загрози Харкова: {kharkiv_threat['detail']}")
    assert "~2-5 хв" in kharkiv_threat["detail"]
    print("--------------------------------------------------")

    print("\n🎉 ВСІ ТЕСТИ ПРОЙДЕНО УСПІШНО! Логіка та парсер працюють ідеально!")
    print("==================================================")
    threat_manager.clear_all()
    threat_manager.save_to_file()
    print("🧹 Тестовий стан успішно очищено з threats_state.json!")

if __name__ == "__main__":
    asyncio.run(run_tests())
