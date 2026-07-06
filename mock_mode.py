"""
Mock Mode — генератор імітованих загроз для тестування.
Зберігає стан загроз в пам'яті (без бази даних).
"""

from datetime import datetime, timezone
from typing import Optional


# Типи загроз з описами українською
THREAT_TYPES = {
    "mig31k": "МіГ-31К (Кинджал)",
    "tu95": "Ту-95МС (крилаті ракети)",
    "cruise_missile": "Крилаті ракети",
    "shahed": "БПЛА Shahed-136",
    "ballistic": "Балістична ракета",
    "iskander": "Іскандер-М",
}

# Усі області України та ключові слова для їх пошуку в повідомленнях
ALL_REGIONS = {
    "Вінницька область": {"keywords": ["вінниц", "вінничч"]},
    "Волинська область": {"keywords": ["волин", "луцьк", "ковель", "волинь"]},
    "Дніпропетровська область": {"keywords": ["дніпр", "дніпропетр", "крив", "нікопол", "павлогр"]},
    "Донецька область": {"keywords": ["донецьк", "донечч", "маріуп", "краматор", "слав'ян", "бахмут"]},
    "Житомирська область": {"keywords": ["житомир", "бердич", "корост"]},
    "Закарпатська область": {"keywords": ["закарпат", "ужгород", "мукач"]},
    "Запорізька область": {"keywords": ["запоріз", "бердян", "мелітопол", "запоріжж"]},
    "Івано-Франківська область": {"keywords": ["івано-франк", "прикарпат", "коломи"]},
    "Київська область": {"keywords": ["київськ", "київщина", "бровар", "борисп", "ірпін", "буч", "васильк"]},
    "м. Київ": {"keywords": ["київ", "києві", "столиц", "києва"]},
    "Кіровоградська область": {"keywords": ["кіровоград", "кропивниц", "кіровоградщ", "олександрі"]},
    "Луганська область": {"keywords": ["луган", "луганщ", "алчев", "сіверськодон"]},
    "Львівська область": {"keywords": ["львів", "львівщ", "дрогоби", "стрий", "самбір"]},
    "Миколаївська область": {"keywords": ["миколаїв", "миколаївщ", "очаків", "первомайськ"]},
    "Одеська область": {"keywords": ["одес", "одещ", "чорномор", "ізмаїл"]},
    "Полтавська область": {"keywords": ["полтав", "кременчу", "лубни", "миргород"]},
    "Рівненська область": {"keywords": ["рівнен", "рівн", "дубно", "варас"]},
    "Сумська область": {"keywords": ["сумськ", "суми", "сумщ", "конотоп", "шостк"]},
    "Тернопільська область": {"keywords": ["терноп", "чортк", "кременець"]},
    "Харківська область": {"keywords": ["харків", "харківщ", "чугуїв", "ізюм", "куп'янськ"]},
    "Херсонська область": {"keywords": ["херсон", "херсонщ", "кахов", "генічеськ"]},
    "Хмельницька область": {"keywords": ["хмельниц", "поділ", "кам'янець", "шепетівк"]},
    "Черкаська область": {"keywords": ["черкас", "уман", "сміл", "черкащ"]},
    "Чернівецька область": {"keywords": ["чернів", "буковин"]},
    "Чернігівська область": {"keywords": ["чернігів", "чернігівщ", "ніжин", "прилук"]}
}



class ThreatState:
    """Стан загрози для однієї області."""

    def __init__(self):
        self.level: str = "none"  # none, low, medium, high, critical
        self.threat_type: Optional[str] = None
        self.detail: Optional[str] = None
        self.since: Optional[str] = None

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None):
        self.level = level
        self.threat_type = threat_type
        self.detail = detail
        if level != "none":
            self.since = datetime.now(timezone.utc).isoformat()
        else:
            self.since = None

    def to_dict(self) -> dict:
        return {
            "level": self.level,
            "type": self.threat_type,
            "detail": self.detail,
            "since": self.since,
        }

    def clear(self):
        self.level = "none"
        self.threat_type = None
        self.detail = None
        self.since = None


class MockThreatManager:
    """Менеджер загроз — зберігає стан для всіх областей."""

    def __init__(self):
        self.threats: dict[str, ThreatState] = {}
        for region in ALL_REGIONS:
            self.threats[region] = ThreatState()

    def set_threat(self, region: str, level: str,
                   threat_type: Optional[str] = None,
                   detail: Optional[str] = None) -> bool:
        if region not in self.threats:
            return False
        self.threats[region].set_threat(level, threat_type, detail)
        return True

    def clear_threat(self, region: str) -> bool:
        if region not in self.threats:
            return False
        self.threats[region].clear()
        return True

    def clear_all(self):
        for state in self.threats.values():
            state.clear()

    def get_all_threats(self) -> dict:
        return {
            region: state.to_dict()
            for region, state in self.threats.items()
        }

    def set_scenario(self, scenario: str):
        """Встановлює попередньо визначений сценарій для тестування."""
        self.clear_all()

        if scenario == "mig_takeoff":
            # Зліт МіГ-31К — загроза для всієї України
            for region in ALL_REGIONS:
                self.set_threat(region, "high", "mig31k",
                                "Зліт МіГ-31К з аеродрому Сольці")

        elif scenario == "shaheds_south":
            # Шахеди з півдня
            south_regions = [
                "Одеська область", "Миколаївська область",
                "Херсонська область", "Запорізька область",
                "Дніпропетровська область", "Кіровоградська область",
            ]
            for region in south_regions:
                self.set_threat(region, "medium", "shahed",
                                "Шахеди в напрямку з півдня")

        elif scenario == "cruise_missiles_west":
            # Крилаті ракети на захід
            west_regions = [
                "Київська область", "м. Київ", "Житомирська область",
                "Хмельницька область", "Вінницька область",
                "Львівська область", "Рівненська область",
            ]
            for region in west_regions:
                self.set_threat(region, "high", "cruise_missile",
                                "Крилаті ракети Х-101 в напрямку заходу")

        elif scenario == "massive_attack":
            # Масований удар — критична загроза для всіх
            for region in ALL_REGIONS:
                self.set_threat(region, "critical", "tu95",
                                "Масований ракетний удар! Ту-95МС пуски крилатих ракет")

        elif scenario == "ballistic_kharkiv":
            # Балістика на Харків
            self.set_threat("Харківська область", "critical", "ballistic",
                            "Балістична загроза! Іскандер-М")
            self.set_threat("Сумська область", "medium", "ballistic",
                            "Можлива балістична загроза")
