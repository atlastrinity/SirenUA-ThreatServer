import sys
import os
import asyncio
from datetime import datetime, timezone, timedelta

# Add threat_server path to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.threat_state import MockThreatManager, SingleThreat
from core.regions import ALL_REGIONS
from monitor.telegram_monitor import TelegramThreatMonitor


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


async def run_smart_engine_tests():
    print("==================================================")
    print("🧪 Запуск тестування Smart Threat Engine в SirenUA")
    print("==================================================\n")

    threat_manager = TestThreatManager()
    monitor = TelegramThreatMonitor(threat_manager)
    monitor.is_running = True

    # ---------------------------------------------------------
    # Тест 1: Перевірка безпеки станів при спливу ETA предиктивної загрози
    # ---------------------------------------------------------
    print("📌 Тест 1: Перевірка стану при спливу ETA (без фальшивих державних сирен)...")
    region_eta = "Вінницька область"
    threat_type = "shahed"
    group_id = "test_pred_group_1"

    # Встановлюємо предиктивну загрозу
    threat_manager.set_threat(
        region=region_eta,
        level="medium",
        threat_type=threat_type,
        detail="БПЛА з Одеської області прямує в напрямку території",
        confidence=70,
        eta="~15 хв",
        is_predictive=True,
        is_test=False,
        eta_seconds=10,
        telemetry={"group_id": group_id}
    )

    state = threat_manager.threats.get(region_eta)
    assert state is not None
    assert state.is_predictive is True
    assert state.level == "medium"
    print(f"   Початковий стан: level={state.level}, is_predictive={state.is_predictive}")

    # Симулюємо виклик callbacks ескалації ETA після закінчення таймера
    monitor._execute_eta_escalation_callback(
        region=region_eta,
        threat_type=threat_type,
        group_id=group_id,
        original_level="medium"
    )

    state_after = threat_manager.threats.get(region_eta)
    print(f"   Стан після ETA-таймера: level={state_after.level}, is_official_active={getattr(state_after, '_is_official_active', False)}")

    assert getattr(state_after, "_is_official_active", False) is False, "Державна сирена НЕ МОЖЕ ставати активною самовільно без сигналу ДСНС!"
    print("✅ Тест 1 пройдено успішно!\n--------------------------------------------------")

    # ---------------------------------------------------------
    # Тест 2: Загасання довіри (Confidence Decay)
    # ---------------------------------------------------------
    print("📌 Тест 2: Модель загасання довіри (Confidence Decay)...")
    region_decay = "Полтавська область"
    threat_manager.set_threat(
        region=region_decay,
        level="medium",
        threat_type="shahed",
        detail="Тестова загроза для decay",
        confidence=30,
        is_predictive=True,
        is_test=False,
        telemetry={"group_id": "decay_group_1"}
    )

    decay_state = threat_manager.threats.get(region_decay)
    decay_threat = decay_state.active_threats[0]

    # Симулюємо відсутність оновлень > 10 хвилин (600+ секунд)
    old_time = (datetime.now(timezone.utc) - timedelta(seconds=700)).isoformat()
    decay_threat.last_updated_at = old_time
    decay_threat.since = old_time

    # Крок 1 загасання (30% -> 20%)
    monitor._apply_confidence_decay_step()
    print(f"   Крок 1: confidence={decay_threat.confidence}%")
    assert decay_threat.confidence == 20

    # Крок 2 загасання (20% -> 10% < 20% -> авто-очищення)
    monitor._apply_confidence_decay_step()
    decay_state_after = threat_manager.threats.get(region_decay)
    print(f"   Крок 2: level після авто-очищення={decay_state_after.level}")
    assert decay_state_after.level == "none", "Загроза мала бути очищена через confidence < 20%"
    print("✅ Тест 2 пройдено успішно!\n--------------------------------------------------")

    # ---------------------------------------------------------
    # Тест 3: Крос-регіональна передача (Cross-Region Transit)
    # ---------------------------------------------------------
    print("📌 Тест 3: Крос-регіональна передача загроз (Transit Handshake)...")
    source_reg = "Черкаська область"
    target_reg = "Київська область"
    transit_group = "transit_group_777"

    # Встановлюємо загрозу в вихідній області
    threat_manager.set_threat(
        region=source_reg,
        level="high",
        threat_type="shahed",
        detail="БПЛА рухається через область",
        confidence=85,
        is_predictive=False,
        is_test=False,
        telemetry={"group_id": transit_group}
    )

    assert threat_manager.threats[source_reg].level == "high"

    # Симулюємо транзит цілі у цільову область
    monitor._handle_cross_region_transit(
        source_region=source_reg,
        target_region=target_reg,
        threat_type="shahed",
        group_id=transit_group
    )

    assert threat_manager.threats[source_reg].level == "none", f"Загроза для вихідної області {source_reg} мала бути знята при транзиті!"
    print(f"   Вихідна область {source_reg}: level={threat_manager.threats[source_reg].level} (успішно очищено)")
    print("✅ Тест 3 пройдено успішно!\n--------------------------------------------------")

    print("🎉 Всі тести Smart Threat Engine пройшли успішно!")
    threat_manager.clear_all()
    threat_manager.save_to_file()
    print("🧹 Тестовий стан успішно очищено з threats_state.json!")

if __name__ == "__main__":
    asyncio.run(run_smart_engine_tests())
