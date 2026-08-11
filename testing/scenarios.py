"""
SirenUA Testing Scenarios Module.
Declarative scenario definitions and threat generator functions for mock testing.
"""

from typing import Dict, Tuple
from core.regions import ALL_REGIONS
from core.threat_types import (
    THREAT_MIG31K,
    THREAT_SHAHED,
    THREAT_CRUISE_MISSILE,
    THREAT_TU95,
    THREAT_BALLISTIC,
)

# Registry of valid scenario names
VALID_SCENARIOS = {
    "mig_takeoff",
    "shaheds_south",
    "cruise_missiles_west",
    "massive_attack",
    "ballistic_kharkiv",
    "clear",
}

def generate_scenario_threats(scenario_name: str) -> Dict[str, Tuple]:
    """
    Генерує словник загроз для заданого тестового сценарію.
    Повертає мапу: region -> (level, threat_type, detail, confidence, eta, is_predictive)
    """
    new_threats = {}

    if scenario_name == "mig_takeoff":
        for r in ALL_REGIONS:
            new_threats[r] = (
                "high",
                THREAT_MIG31K,
                "Зафіксовано зліт винищувача МіГ-31К ПКС РФ.\nТип: Кінджал\nНапрямок запуску: Північ\nШвидкість руху: ~3000 км/год\nВисота польоту: надвисока\nОчікуваний час: ~10 хв",
                95,
                "~10 хв",
                False,
            )

    elif scenario_name == "shaheds_south":
        south_regions = [
            "Одеська область", "Миколаївська область",
            "Херсонська область", "Запорізька область",
            "Дніпропетровська область", "Кіровоградська область",
        ]
        for r in south_regions:
            new_threats[r] = (
                "medium",
                THREAT_SHAHED,
                "Виявлено групу БпЛА 'Shahed' з південного напрямку.\nВідстань: ~120 км\nШвидкість руху: ~180 км/год\nКількість цілей: ~5-7\nОчікуваний час: ~45 хв\nПатерн підтверджений аналітикою",
                82,
                "~45 хв",
                True,
            )

    elif scenario_name == "cruise_missiles_west":
        west_regions = [
            "Київська область", "м. Київ", "Житомирська область",
            "Хмельницька область", "Вінницька область",
            "Львівська область", "Рівненська область",
        ]
        for r in west_regions:
            new_threats[r] = (
                "high",
                THREAT_CRUISE_MISSILE,
                "Крилаті ракети Х-101 прямують у західні області.\nВідстань до цілі: ~250 км\nКількість цілей: 4\nТип: Х-101\nШвидкість руху: ~850 км/год\nВисота польоту: середня\nОчікуваний час: ~20 хв\nПатерн підтверджений аналітикою",
                88,
                "~20 хв",
                True,
            )

    elif scenario_name == "massive_attack":
        for r in ALL_REGIONS:
            new_threats[r] = (
                "critical",
                THREAT_TU95,
                "Масований ракетний удар! Зафіксовано пуски з 6х Ту-95МС.\nВідстань до цілі: ~400 км\nКількість цілей: 12+\nТип: Х-101/Х-555\nШвидкість руху: ~850 км/год\nОчікуваний час: ~30-40 хв",
                98,
                "~30-40 хв",
                False,
            )

    elif scenario_name == "ballistic_kharkiv":
        new_threats["Харківська область"] = (
            "critical",
            THREAT_BALLISTIC,
            "Загроза застосування балістичного озброєння з Бєлгорода!\nВідстань до цілі: ~40 км\nТип: Іскандер-М\nШвидкість руху: ~3600 км/год\nОчікуваний час: ~2 хв",
            92,
            "~2 хв",
            False,
        )
        new_threats["Сумська область"] = (
            "medium",
            THREAT_BALLISTIC,
            "Можлива балістична загроза з прикордонних районів РФ.\nОчікуваний час: ~3 хв",
            70,
            "~3 хв",
            True,
        )

    return new_threats
