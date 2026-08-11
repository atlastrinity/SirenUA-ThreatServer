"""
SirenUA Test Scenario Manager Facade.
Coordinates scenario execution, delayed testing, and database scrubbing.
"""

import threading
from typing import Any
from core.config import logger
from testing.scenarios import VALID_SCENARIOS, generate_scenario_threats
from testing.cleaner import (
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    purge_all_test_data,
)

class TestScenarioManager:
    """Менеджер керування тестовими сценаріями та видаленням тестів."""

    def __init__(self):
        self.valid_scenarios = VALID_SCENARIOS

    def apply_scenario(self, scenario_name: str, threat_manager: Any) -> bool:
        """Активує заданий тестовий сценарій або очищує тести (якщо scenario_name == 'clear')."""
        if scenario_name not in self.valid_scenarios:
            logger.warning(f"⚠️ [TestManager] Спроба виклику невідомого сценарію: {scenario_name}")
            return False

        if scenario_name == "clear":
            self.clear_test_mode(threat_manager, only_test=True)
            return True

        threats_map = generate_scenario_threats(scenario_name)
        for region, params in threats_map.items():
            level, threat_type, detail, confidence, eta, is_predictive = params
            threat_manager.set_threat(
                region=region,
                level=level,
                threat_type=threat_type,
                detail=detail,
                confidence=confidence,
                eta=eta,
                is_predictive=is_predictive,
                is_test=True,
            )
        logger.info(f"🚀 [TestManager] Активовано сценарій: '{scenario_name}' ({len(threats_map)} регіонів)")
        return True

    def apply_scenario_with_delay(self, scenario_name: str, delay_seconds: float, threat_manager: Any):
        """Запускає тестовий сценарій через заданий проміжок часу у фоновому потоці."""
        def _runner():
            threading.Event().wait(delay_seconds)
            self.apply_scenario(scenario_name, threat_manager)

        threading.Thread(target=_runner, daemon=True).start()
        logger.info(f"⏳ [TestManager] Заплановано сценарій '{scenario_name}' через {delay_seconds} сек")

    def clear_test_mode(self, threat_manager: Any, only_test: bool = True):
        """Скасовує всі тестові загрози в пам'яті та каскадно вилучає дані з SQLite і Firestore."""
        logger.info("🧹 [TestManager] Очищення тестового режиму та тестових записів...")
        
        # 1. Очищення пам'яті сервера
        if hasattr(threat_manager, "clear_all"):
            threat_manager.clear_all(only_test=only_test)
        
        # 2. Очищення баз даних
        delete_test_history_from_sqlite()
        delete_test_history_from_firestore()
        logger.info("✅ [TestManager] Тестовий режим повністю очищено")

# Singleton екземпляр менеджера тестування
test_scenario_manager = TestScenarioManager()
