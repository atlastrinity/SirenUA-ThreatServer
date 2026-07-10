"""
Mock Mode — генератор імітованих загроз для тестування.
Зберігає стан загроз в пам'яті (без бази даних).
"""

from datetime import datetime, timezone
from typing import Optional
import time


# Типи загроз з описами українською
THREAT_TYPES = {
    "mig31k": "МіГ-31К (Кинджал)",
    "tu95": "Ту-95МС (крилаті ракети)",
    "cruise_missile": "Крилаті ракети",
    "shahed": "БПЛА Shahed-136",
    "ballistic": "Балістична ракета",
    "iskander": "Іскандер-М",
    "kab": "Керовані авіабомби (КАБ)",
}

# Усі області України та ключові слова для їх пошуку в повідомленнях
ALL_REGIONS = {
    "Вінницька область": {"keywords": ["вінниц", "вінничч", "жмерин", "ладижин", "ладиж", "тульчин", "козятин", "гайсин"]},
    "Волинська область": {"keywords": ["волин", "луцьк", "ковель", "волинь", "володимир", "нововолин"]},
    "Дніпропетровська область": {"keywords": ["дніпр", "дніпропетр", "крив", "нікопол", "павлогр", "кам'янськ", "кам`янськ", "синельник", "новомосков"]},
    "Донецька область": {"keywords": ["донецьк", "донечч", "маріуп", "краматор", "слав'ян", "бахмут", "покровськ", "костянтинівк", "добропілл", "лиман", "дружківк", "торецьк", "avdiivka", "авдіївк"]},
    "Житомирська область": {"keywords": ["житомир", "бердич", "корост", "звягел", "звягель", "новоград", "малин", "овруч"]},
    "Закарпатська область": {"keywords": ["закарпат", "ужгород", "мукач", "берегов", "хуст", "рахів", "тячів"]},
    "Запорізька область": {"keywords": ["запоріз", "бердян", "мелітопол", "запоріжж", "енергодар", "полог", "гуляйпол", "оріхів", "василівк"]},
    "Івано-Франківська область": {"keywords": ["івано-франк", "прикарпат", "коломи", "калуш", "бурштин", "яремч", "буковель", "долин", "косів"]},
    "Київська область": {"keywords": ["київськ", "київщина", "бровар", "борисп", "ірпін", "буч", "васильк", "обухів", "вишгород", "трипіл", "біла церков", "білоцерк", "фастів", "переяслав", "яготин", "чорнобил"]},
    "м. Київ": {"keywords": ["київ", "києві", "столиц", "києва", "троєщин", "оболонь", "рембаз", "осокорк", "жулян", "голосєєв", "голосіїв", "теличк", "соломʼян", "солом'ян", "борщагівк", "печерськ", "поділ", "лук'янів", "шулявк", "дарниц", "позняк", "святошин", "теремк"]},
    "Кіровоградська область": {"keywords": ["кіровоград", "кропивниц", "кіровоградщ", "олександрі", "світловодськ", "знам'ян", "знамян", "новоукраїн"]},
    "Луганська область": {"keywords": ["луган", "луганщ", "алчев", "сіверськодон", "лисичанськ", "кадіївк", "рубіжн", "сватов", "старобільськ"]},
    "Львівська область": {"keywords": ["львів", "львівщ", "дрогоби", "стрий", "самбір", "яворів", "явор", "червоногр", "sheptytskyi", "шептицьк", "золочів", "золоч", "борислав", "трускавец", "новий розділ"]},
    "Миколаївська область": {"keywords": ["миколаїв", "миколаївщ", "очаків", "первомайськ", "вознесенськ", "южноукраїнськ", "баштанк", "новий буг"]},
    "Одеська область": {"keywords": ["одес", "одещ", "чорномор", "ізмаїл", "заток", "южн", "подільськ", "вилков", "білгород-дністров", "болград"]},
    "Полтавська область": {"keywords": ["полтав", "кременчу", "лубни", "лубн", "миргород", "пирятин", "гадяч", "горішні плав", "комсомольськ"]},
    "Рівненська область": {"keywords": ["рівнен", "рівн", "dugno", "дубно", "варас", "вараш", "сарн", "острог", "здолбунів", "костопіль"]},
    "Сумська область": {"keywords": ["сумськ", "суми", "сумщ", "конотоп", "шостк", "охтирк", "глухів", "ромни", "середина-буд", "лебедин", "кролевец"]},
    "Тернопільська область": {"keywords": ["терноп", "чортк", "кременець", "теребовл", "бережан", "бучач", "збараж"]},
    "Харківська область": {"keywords": ["харків", "харківщ", "чугуїв", "ізюм", "куп'янськ", "богодух", "лозов", "люботин", "балаклі", "дергач", "мереф", "вовчанськ"]},
    "Херсонська область": {"keywords": ["херсон", "херсонщ", "кахов", "генічеськ", "берислав", "антонівк", "скадовськ", "олешк"]},
    "Хмельницька область": {"keywords": ["хмельниц", "хмельнич", "поділ", "кам'янець", "шепет", "шепетівк", "старокост", "старкон", "нетішин", "славут", "волочиськ", "дунаївц"]},
    "Черкаська область": {"keywords": ["черкас", "уман", "сміл", "черкащ", "канів", "золотонош", "ватутін", "корсунь"]},
    "Чернівецька область": {"keywords": ["чернів", "буковин", "дністровськ", "хотин", "сторожинець"]},
    "Чернігівська область": {"keywords": ["чернігів", "чернігівщ", "ніжин", "прилук", "новгород-сівер", "бахмач", "ічня", "носівк"]}
}

# Топологічний граф областей України (сусідство)
UKRAINE_TOPOLOGY = {
    "Вінницька область": ["Чернівецька область", "Хмельницька область", "Житомирська область", "Київська область", "Черкаська область", "Кіровоградська область", "Одеська область"],
    "Волинська область": ["Львівська область", "Рівненська область"],
    "Дніпропетровська область": ["Полтавська область", "Кіровоградська область", "Миколаївська область", "Херсонська область", "Запорізька область", "Донецька область", "Харківська область"],
    "Донецька область": ["Луганська область", "Харківська область", "Дніпропетровська область", "Запорізька область"],
    "Житомирська область": ["Рівненська область", "Хмельницька область", "Вінницька область", "Київська область"],
    "Закарпатська область": ["Львівська область", "Івано-Франківська область"],
    "Запорізька область": ["Херсонська область", "Дніпропетровська область", "Донецька область"],
    "Івано-Франківська область": ["Закарпатська область", "Львівська область", "Тернопільська область", "Чернівецька область"],
    "Київська область": ["Житомирська область", "Вінницька область", "Черкаська область", "Полтавська область", "Чернігівська область", "м. Київ"],
    "м. Київ": ["Київська область"],
    "Кіровоградська область": ["Черкаська область", "Вінницька область", "Одеська область", "Миколаївська область", "Дніпропетровська область", "Полтавська область"],
    "Луганська область": ["Харківська область", "Донецька область"],
    "Львівська область": ["Закарпатська область", "Івано-Франківська область", "Тернопільська область", "Рівненська область", "Волинська область"],
    "Миколаївська область": ["Одеська область", "Кіровоградська область", "Дніпропетровська область", "Херсонська область"],
    "Одеська область": ["Вінницька область", "Кіровоградська область", "Миколаївська область"],
    "Полтавська область": ["Сумська область", "Чернігівська область", "Київська область", "Черкаська область", "Кіровоградська область", "Дніпропетровська область", "Харківська область"],
    "Рівненська область": ["Волинська область", "Львівська область", "Тернопільська область", "Хмельницька область", "Житомирська область"],
    "Сумська область": ["Чернігівська область", "Полтавська область", "Харківська область"],
    "Тернопільська область": ["Івано-Франківська область", "Львівська область", "Рівненська область", "Хмельницька область", "Чернівецька область"],
    "Харківська область": ["Сумська область", "Полтавська область", "Дніпропетровська область", "Донецька область", "Луганська область"],
    "Херсонська область": ["Миколаївська область", "Дніпропетровська область", "Запорізька область", "АР Крим"],
    "Хмельницька область": ["Тернопільська область", "Рівненська область", "Житомирська область", "Вінницька область", "Чернівецька область"],
    "Черкаська область": ["Київська область", "Вінницька область", "Кіровоградська область", "Полтавська область"],
    "Чернівецька область": ["Івано-Франківська область", "Тернопільська область", "Хмельницька область", "Вінницька область"],
    "Чернігівська область": ["Київська область", "Полтавська область", "Сумська область"],
    "АР Крим": ["Херсонська область"]
}

# Типові історичні маршрути Шахедів
SHAHED_ROUTES = {
    "route_south": ["Одеська область", "Миколаївська область", "Кіровоградська область", "Черкаська область", "Київська область"],
    "route_west": ["Миколаївська область", "Кіровоградська область", "Вінницька область", "Хмельницька область", "Тернопільська область"],
    "route_east": ["Сумська область", "Полтавська область", "Дніпропетровська область"]
}


import uuid


class SingleThreat:
    """Одна конкретна загроза з унікальним ідентифікатором."""

    LEVEL_PRIORITY = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

    def __init__(self, level: str, threat_type: Optional[str] = None,
                 detail: Optional[str] = None, confidence: Optional[int] = None,
                 eta: Optional[str] = None, is_predictive: bool = False,
                 is_test: bool = False, group_id: Optional[str] = None,
                 paired_event_id: Optional[int] = None,
                 eta_seconds: Optional[int] = None):
        self.threat_id: str = group_id or f"t_{uuid.uuid4().hex[:12]}"
        self.level: str = level
        self.threat_type: Optional[str] = threat_type
        self.detail: Optional[str] = detail
        self.since: str = datetime.now(timezone.utc).isoformat()
        self.eta: Optional[str] = eta
        self.eta_seconds: Optional[int] = eta_seconds  # ETA в секундах для точного розрахунку
        self.confidence: Optional[int] = confidence
        self.is_predictive: bool = is_predictive
        self.is_test: bool = is_test
        self.group_id: Optional[str] = group_id
        self.paired_event_id: Optional[int] = paired_event_id

    def to_dict(self) -> dict:
        return {
            "threat_id": self.threat_id,
            "level": self.level,
            "type": self.threat_type,
            "detail": self.detail,
            "since": self.since,
            "confidence": self.confidence,
            "eta": self.eta,
            "eta_seconds": self.eta_seconds,
            "is_predictive": self.is_predictive,
            "is_test": self.is_test,
            "group_id": self.group_id,
            "paired_event_id": self.paired_event_id,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SingleThreat":
        """Відновлення з словника (для load_from_db/file)."""
        t = cls(
            level=data.get("level", "low"),
            threat_type=data.get("type"),
            detail=data.get("detail"),
            confidence=data.get("confidence"),
            eta=data.get("eta"),
            is_predictive=data.get("is_predictive", False),
            is_test=data.get("is_test", False),
            group_id=data.get("group_id"),
            paired_event_id=data.get("paired_event_id"),
            eta_seconds=data.get("eta_seconds"),
        )
        t.threat_id = data.get("threat_id", t.threat_id)
        t.since = data.get("since", t.since)
        return t


class ThreatState:
    """Стан загроз для однієї області (підтримка множинних загроз)."""

    # Вікно дедуплікації: загрози одного типу в межах 5 хвилин вважаються дублікатами
    DEDUP_WINDOW_SECONDS = 300

    def __init__(self):
        self.active_threats: list[SingleThreat] = []
        self.is_active: bool = False  # Офіційна тривога (alerts.in.ua)
        self.is_test: bool = False

    @property
    def level(self) -> str:
        """Найвищий рівень серед усіх активних загроз."""
        if not self.active_threats:
            return "none"
        return max(self.active_threats,
                   key=lambda t: SingleThreat.LEVEL_PRIORITY.get(t.level, 0)).level

    @property
    def threat_type(self) -> Optional[str]:
        """Тип primary (найновішої) загрози."""
        return self.active_threats[-1].threat_type if self.active_threats else None

    @property
    def detail(self) -> Optional[str]:
        """Detail primary загрози."""
        return self.active_threats[-1].detail if self.active_threats else None

    @property
    def since(self) -> Optional[str]:
        """Час найновішої загрози."""
        return self.active_threats[-1].since if self.active_threats else None

    @property
    def confidence(self) -> Optional[int]:
        """Confidence primary загрози."""
        return self.active_threats[-1].confidence if self.active_threats else None

    @property
    def eta(self) -> Optional[str]:
        """ETA primary загрози."""
        return self.active_threats[-1].eta if self.active_threats else None

    @property
    def is_predictive(self) -> bool:
        return self.active_threats[-1].is_predictive if self.active_threats else False

    def _find_duplicate(self, threat_type: Optional[str], group_id: Optional[str]) -> Optional[SingleThreat]:
        """Шукає дублікат загрози серед активних.
        Дублікатом вважається загроза з:
        1) Тим самим group_id, АБО
        2) Тим самим threat_type (включаючи None для загальних загроз)
        """
        for t in self.active_threats:
            # Точний збіг за group_id
            if group_id and t.group_id and t.group_id == group_id:
                return t
            # Збіг за типом загрози
            if t.threat_type == threat_type:
                return t
        return None

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False,
                   is_test: bool = False, group_id: Optional[str] = None,
                   eta_seconds: Optional[int] = None) -> bool:
        """Додає або оновлює загрозу. Повертає True якщо щось змінилось."""
        if threat_type:
            threat_type = threat_type.lower().strip()
            
        if level == "none":
            return False

        existing = self._find_duplicate(threat_type, group_id)
        if existing:
            # Оновлюємо існуючу загрозу (уточнення)
            changed = False
            
            # Оновлюємо час загрози на поточний
            existing.since = datetime.now(timezone.utc).isoformat()
            changed = True
            
            if confidence is not None and (existing.confidence is None or confidence > existing.confidence):
                existing.confidence = confidence
                changed = True
            if detail and detail != existing.detail:
                existing.detail = detail
                changed = True
            if eta and eta != existing.eta:
                existing.eta = eta
                changed = True
            if eta_seconds and eta_seconds != existing.eta_seconds:
                existing.eta_seconds = eta_seconds
                changed = True
            # Якщо загроза перестала бути предиктивною (стала реальною)
            if existing.is_predictive and not is_predictive:
                existing.is_predictive = False
                changed = True
            if group_id and group_id != existing.group_id:
                existing.group_id = group_id
                changed = True
            if is_test and not existing.is_test:
                existing.is_test = True
                changed = True
            # Підвищуємо рівень, але ніколи не знижуємо
            if SingleThreat.LEVEL_PRIORITY.get(level, 0) > SingleThreat.LEVEL_PRIORITY.get(existing.level, 0):
                existing.level = level
                changed = True
            return changed

        # Нова загроза
        new_threat = SingleThreat(
            level=level,
            threat_type=threat_type,
            detail=detail,
            confidence=confidence,
            eta=eta,
            is_predictive=is_predictive,
            is_test=is_test,
            group_id=group_id,
            eta_seconds=eta_seconds,
        )
        self.active_threats.append(new_threat)
        self.is_test = is_test
        return True

    def clear_by_group_id(self, group_id: str) -> Optional[SingleThreat]:
        """Знімає конкретну загрозу за group_id. Повертає зняту загрозу або None."""
        for i, t in enumerate(self.active_threats):
            if t.group_id and t.group_id == group_id:
                return self.active_threats.pop(i)
        return None

    def clear_by_type(self, threat_type: str) -> Optional[SingleThreat]:
        """Знімає найстарішу загрозу вказаного типу. Повертає зняту загрозу або None."""
        for i, t in enumerate(self.active_threats):
            if t.threat_type == threat_type:
                return self.active_threats.pop(i)
        return None

    def clear_oldest(self) -> Optional[SingleThreat]:
        """Знімає найстарішу загрозу. Повертає зняту загрозу або None."""
        if self.active_threats:
            return self.active_threats.pop(0)
        return None

    def clear_all_threats(self):
        """Знімає всі загрози."""
        self.active_threats.clear()
        self.is_test = False

    def clear(self):
        """Повне очищення (legacy-сумісність)."""
        self.active_threats.clear()
        self.is_active = False
        self.is_test = False

    def to_dict(self) -> dict:
        """Серіалізація — зворотно-сумісний формат + масив active_threats."""
        primary = self.active_threats[-1] if self.active_threats else None
        return {
            # Зворотна сумісність — flat fields від primary загрози
            "level": self.level,
            "type": primary.threat_type if primary else None,
            "detail": primary.detail if primary else None,
            "since": primary.since if primary else None,
            "confidence": primary.confidence if primary else None,
            "eta": primary.eta if primary else None,
            "is_predictive": primary.is_predictive if primary else False,
            "is_active": self.is_active,
            "is_test": self.is_test,
            # Новий масив усіх загроз
            "active_threats": [t.to_dict() for t in self.active_threats],
        }

    def load_from_dict(self, data: dict):
        """Відновлення стану з словника (для load_from_db/file)."""
        self.is_active = data.get("is_active", False)
        self.is_test = data.get("is_test", False)
        # Якщо є масив active_threats — завантажити з нього
        at_list = data.get("active_threats")
        if at_list and isinstance(at_list, list) and len(at_list) > 0:
            self.active_threats = [SingleThreat.from_dict(td) for td in at_list]
        else:
            # Legacy: одна загроза у flat-форматі
            self.active_threats.clear()
            level = data.get("level", "none")
            if level != "none":
                self.active_threats.append(SingleThreat(
                    level=level,
                    threat_type=data.get("type"),
                    detail=data.get("detail"),
                    confidence=data.get("confidence"),
                    eta=data.get("eta"),
                    is_predictive=data.get("is_predictive", False),
                    is_test=data.get("is_test", False),
                    group_id=data.get("group_id"),
                ))

try:
    import firebase_admin
    from firebase_admin import messaging, firestore
    HAS_FIREBASE = True
except ImportError:
    HAS_FIREBASE = False

def get_db():
    if not HAS_FIREBASE or not firebase_admin._apps:
        return None
    try:
        return firestore.client()
    except Exception as e:
        print(f"⚠️ Помилка отримання Firestore клієнта: {e}")
        return None

def backup_sqlite_to_firestore():
    """Стискає всю локальну базу даних SQLite та робить резервну копію у Firestore."""
    import sqlite3
    import os
    import json
    import gzip
    import base64
    
    DB_PATH = "threat_analytics.db"
    if os.path.exists("threat_server"):
        DB_PATH = "threat_server/threat_analytics.db"
        
    db = get_db()
    if not db:
        print("⚠️ [Backup] Firebase не ініціалізовано, пропуск резервного копіювання SQLite.")
        return False
        
    try:
        if not os.path.exists(DB_PATH):
            return False
            
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # Перевірка наявності таблиць перед зчитуванням
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables_in_db = [r["name"] for r in cursor.fetchall()]
        
        backup_data = {}
        target_tables = ["gemini_rules", "paired_events", "threat_history", "threat_clearings", "telemetry_data", "gemini_rules_audit", "error_log"]
        
        for table in target_tables:
            if table in tables_in_db:
                cursor.execute(f"SELECT * FROM {table}")
                backup_data[table] = [dict(row) for row in cursor.fetchall()]
            else:
                backup_data[table] = []
                
        conn.close()
        
        # Додаємо мітку часу
        backup_data["backup_timestamp"] = str(datetime.now(timezone.utc))
        
        json_str = json.dumps(backup_data, ensure_ascii=False)
        compressed = gzip.compress(json_str.encode('utf-8'))
        encoded = base64.b64encode(compressed).decode('utf-8')
        
        db.collection('sirenua_backup').document('sqlite_compressed').set({
            "data": encoded,
            "size_kb": round(len(encoded) / 1024, 2),
            "updated_at": firestore.SERVER_TIMESTAMP
        })
        print(f"💾 [Backup] SQLite успішно збережено у Firestore (розмір: {len(encoded) / 1024:.2f} KB)")
        return True
    except Exception as e:
        print(f"⚠️ [Backup] Помилка резервного копіювання SQLite у Firestore: {e}")
        return False

def restore_sqlite_from_firestore(force: bool = False):
    """Відновлює локальну базу даних SQLite зі стиснутого бекапу в Firestore (якщо локальна БД порожня або примусово)."""
    import sqlite3
    import os
    import json
    import gzip
    import base64
    
    DB_PATH = "threat_analytics.db"
    if os.path.exists("threat_server"):
        DB_PATH = "threat_server/threat_analytics.db"
        
    db = get_db()
    if not db:
        print("⚠️ [Restore] Firebase не ініціалізовано, пропуск відновлення SQLite.")
        return False
        
    try:
        # Перевіряємо чи є дані локально. Якщо правила чи зв'язані події вже є — пропуск відновлення (якщо не примусово)
        if os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            cursor = conn.cursor()
            
            # Перевіряємо наявність таблиць
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='gemini_rules'")
            has_rules_table = cursor.fetchone()
            
            rules_count = 0
            events_count = 0
            if has_rules_table:
                cursor.execute("SELECT COUNT(*) FROM gemini_rules")
                rules_count = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM paired_events")
                events_count = cursor.fetchone()[0]
            conn.close()
            
            if not force and (rules_count > 0 or events_count > 0):
                print("💾 [Restore] Локальна SQLite вже містить дані (rules чи events), пропуск відновлення.")
                return False
                
        doc_ref = db.collection('sirenua_backup').document('sqlite_compressed')
        doc = doc_ref.get()
        if not doc.exists:
            print("⚠️ [Restore] Бекап SQLite не знайдено у Firestore.")
            return False
            
        payload = doc.to_dict()
        encoded = payload.get("data")
        if not encoded:
            print("⚠️ [Restore] Дані бекапу SQLite порожні.")
            return False
            
        compressed = base64.b64decode(encoded)
        json_str = gzip.decompress(compressed).decode('utf-8')
        backup_data = json.loads(json_str)
        
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        tables = [
            ("gemini_rules", ["id", "created_at", "updated_at", "rule_type", "source_region", "target_region", "threat_type", "rule_text", "rule_json", "evidence_count", "accuracy_score", "is_active", "last_validated"]),
            ("paired_events", ["id", "created_at", "region", "threat_event_id", "telemetry_id", "clearing_event_id", "lifecycle_status", "threat_level", "threat_type", "confidence_at_set", "confidence_at_clear", "was_predictive", "prediction_accuracy", "duration_seconds", "gemini_group_id", "rules_applied"]),
            ("threat_history", ["id", "timestamp", "region", "threat_level", "threat_type", "detail", "confidence", "is_test"]),
            ("threat_clearings", ["id", "timestamp", "region", "original_threat_event_id", "linked_group_id", "linked_correlation_group", "resolution_type", "intercepted_count", "total_targets_in_wave", "impact_confirmed", "damage_assessment", "civilian_casualties_reported", "infrastructure_hit", "air_defense_effectiveness", "threat_duration_assessment", "prediction_accuracy_hint", "was_predictive", "original_threat_level", "original_threat_type", "original_confidence", "clearing_confidence", "clearing_context_tags", "source_reliability", "time_of_day_category", "clearing_source_channel", "clearing_message_text", "threat_set_timestamp", "threat_duration_seconds", "is_test"]),
            ("telemetry_data", ["id", "threat_event_id", "group_id", "attack_vector", "target_count", "speed_kmh", "altitude_category", "heading_degrees", "distance_to_target_km", "launch_origin", "weapon_subtype", "engagement_status", "air_defense_active", "multiple_waves", "wave_number", "time_of_day_category", "weather_factor", "source_reliability", "message_context_tags", "strategic_priority", "civilian_risk_level", "event_phase", "correlation_group", "target_cities_coords"]),
            ("gemini_rules_audit", ["id", "timestamp", "action", "rule_type", "rule_text", "source_region", "target_region", "threat_type", "reason"]),
            ("error_log", ["id", "timestamp", "source", "error_type", "message", "endpoint", "context"])
        ]
        
        # Тимчасово вимикаємо перевірку зовнішніх ключів під час відновлення
        cursor.execute("PRAGMA foreign_keys = OFF")
        
        for table_name, columns in tables:
            # Перевіряємо чи таблиця взагалі існує в локальній БД
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name=?", (table_name,))
            if not cursor.fetchone():
                continue
                
            rows = backup_data.get(table_name, [])
            if not rows:
                continue
                
            # Очищуємо таблицю перед відновленням
            cursor.execute(f"DELETE FROM {table_name}")
            
            for row in rows:
                row_keys = [k for k in row.keys() if k in columns]
                placeholders = ", ".join(["?"] * len(row_keys))
                cols_str = ", ".join(row_keys)
                vals = [row[k] for k in row_keys]
                
                cursor.execute(f"INSERT OR REPLACE INTO {table_name} ({cols_str}) VALUES ({placeholders})", vals)
                
        cursor.execute("PRAGMA foreign_keys = ON")
        conn.commit()
        conn.close()
        print("💾 [Restore] SQLite успішно відновлено з бекапу Firestore!")
        return True
    except Exception as e:
        print(f"⚠️ [Restore] Помилка відновлення SQLite з Firestore: {e}")
        return False

# Мапування українських назв областей на відповідні теми (Topics) у Firebase
TOPIC_MAPPING = {
    "Вінницька область": "region_vinnytsia",
    "Волинська область": "region_volyn",
    "Дніпропетровська область": "region_dnipro",
    "Донецька область": "region_donetsk",
    "Житомирська область": "region_zhytomyr",
    "Закарпатська область": "region_zakarpattya",
    "Запорізька область": "region_zaporizhzhya",
    "Івано-Франківська область": "region_if",
    "Київська область": "region_kyiv_oblast",
    "м. Київ": "region_kyiv_city",
    "Кіровоградська область": "region_kirovohrad",
    "Луганська область": "region_luhansk",
    "Львівська область": "region_lviv",
    "Миколаївська область": "region_mykolaiv",
    "Одеська область": "region_odesa",
    "Полтавська область": "region_poltava",
    "Рівненська область": "region_rivne",
    "Сумська область": "region_sumy",
    "Тернопільська область": "region_ternopil",
    "Харківська область": "region_kharkiv",
    "Херсонська область": "region_kherson",
    "Хмельницька область": "region_khmelnytskyi",
    "Черкаська область": "region_cherkasy",
    "Чернівецька область": "region_chernivtsi",
    "Чернігівська область": "region_chernihiv"
}

import asyncio

fcm_queue = None
fcm_worker_task = None

async def fcm_queue_worker():
    global fcm_queue
    while True:
        try:
            item = await fcm_queue.get()
            # Send the FCM notification synchronously in a thread pool so we do not block the event loop
            await asyncio.to_thread(
                _send_fcm_notification_sync,
                item["region"],
                item["level"],
                item["threat_type"],
                item["detail"],
                item["play_sound"],
                item["confidence"],
                item["eta"],
                item.get("is_official_alarm", False),
                item.get("is_test", False)
            )
            # Sleep 1.5 seconds between notifications if it plays sound, to avoid overlapping sounds
            # Otherwise, use a minimal delay (0.05s)
            if item.get("play_sound", True):
                await asyncio.sleep(1.5)
            else:
                await asyncio.sleep(0.05)
            fcm_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"⚠️ Помилка у воркері черги FCM: {e}")
            await asyncio.sleep(1.0)

async def start_fcm_worker():
    global fcm_queue, fcm_worker_task
    if fcm_queue is None:
        fcm_queue = asyncio.Queue()
    if fcm_worker_task is None:
        fcm_worker_task = asyncio.create_task(fcm_queue_worker())
        print("🚀 FCM Queue Worker успішно запущено.")

def send_fcm_notification(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False):
    """Додає Push-сповіщення у чергу відправки FCM (якщо працює асинхронний режим) або відправляє синхронно."""
    global fcm_queue
    if fcm_queue is not None:
        try:
            loop = asyncio.get_running_loop()
            loop.call_soon_threadsafe(
                fcm_queue.put_nowait,
                {
                    "region": region,
                    "level": level,
                    "threat_type": threat_type,
                    "detail": detail,
                    "play_sound": play_sound,
                    "confidence": confidence,
                    "eta": eta,
                    "is_official_alarm": is_official_alarm,
                    "is_test": is_test
                }
            )
            return
        except RuntimeError:
            pass # Event loop not running yet

    _send_fcm_notification_sync(region, level, threat_type, detail, play_sound, confidence, eta, is_official_alarm, is_test)

def _send_fcm_notification_sync(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None, is_official_alarm: bool = False, is_test: bool = False):
    """Надсилає Push-сповіщення у Firebase топік для відповідного регіону (синхронний метод)."""
    if not HAS_FIREBASE:
        return

    topic = TOPIC_MAPPING.get(region)
    if not topic:
        return

    if level == "none":
        if is_official_alarm:
            title = "🟢 Відбій загрози"
            body = f"Загрозу знято в: {region}."
            sound = "clearance.wav"
        else:
            title = "🟢 Відбій повітряної тривоги"
            body = region
            sound = "vidbiy.wav"
        is_critical = False
    else:
        if threat_type is not None:
            type_desc = None
            if threat_type == "mig31k":
                type_desc = "МіГ-31К"
            elif threat_type == "shahed":
                type_desc = "БпЛА"
            elif threat_type == "ballistic":
                type_desc = "Балістика"
            elif threat_type == "cruise_missile":
                type_desc = "Крилаті ракети"
            elif threat_type == "kab":
                type_desc = "КАБ"

            if type_desc:
                title = f"⚠️ Загроза: {type_desc}"
            else:
                title = "⚠️ Загроза"
            sound = "warning.wav"
            # Keep it critical if the region is already under an official alarm
            # so the warning plays even if the device is muted/DND
            is_critical = is_official_alarm
            if detail:
                body = f"{detail}\n{region}"
            else:
                body = region
        else:
            # It's a general official alarm trigger (no specific threat type)
            title = "🚨 Повітряна тривога"
            body = region
            sound = "siren.wav"
            is_critical = True

        extra_info = []
        if confidence is not None:
            extra_info.append(f"Ймовірність: {confidence}%")
        if eta:
            extra_info.append(f"Час: {eta}")
        if extra_info:
            body += f" ({', '.join(extra_info)})"

    # Створюємо Aps з interruption_level для коректного відображення на Lock Screen.
    # Оскільки додаток наразі не має погодженого Apple Critical Alerts entitlement (com.apple.developer.usernotifications.critical-alerts),
    # використання словникової структури CriticalSound та interruption-level = "critical" призводить до того,
    # що iOS мовчки видаляє пуші на закритому екрані. 
    # Замість цього використовуємо стандартне ім'я звуку (рядок) та interruption-level = "time-sensitive",
    # що дозволяє обходити режим DND без додаткових дозволів від Apple.
    if play_sound:
        aps = messaging.Aps(
            alert=messaging.ApsAlert(title=title, body=body),
            sound=sound, 
            badge=1, 
            content_available=True, 
            mutable_content=True,
            custom_data={"interruption-level": "time-sensitive"}
        )
    else:
        aps = messaging.Aps(
            alert=messaging.ApsAlert(title=title, body=body),
            badge=1, 
            content_available=True, 
            mutable_content=True,
            custom_data={"interruption-level": "time-sensitive"}
        )

    data_payload = {
        "region": region,
        "level": level,
        "threat_type": threat_type or "",
        "is_critical": str(is_critical).lower(),
    }
    if confidence is not None:
        data_payload["confidence"] = str(confidence)
    if eta:
        data_payload["eta"] = eta

    message = messaging.Message(
        notification=messaging.Notification(
            title=title,
            body=body,
        ),
        data=data_payload,
        apns=messaging.APNSConfig(
            headers={
                "apns-priority": "10",
                "apns-push-type": "alert",
            },
            payload=messaging.APNSPayload(aps=aps)
        ),
        topic=topic,
    )

    try:
        response = messaging.send(message)
        sound_status = "ЗІ ЗВУКОМ" if play_sound else "БЕЗ ЗВУКУ"
        priority = "CRITICAL" if is_critical else "NORMAL"
        print(f"🚀 FCM Push [{sound_status}|{priority}] sent for {region} (topic: {topic}), confidence: {confidence}%, response: {response}")
    except Exception as e:
        print(f"⚠️ Помилка відправки FCM Push для {region}: {e}")


class MockThreatManager:
    """Менеджер загроз — зберігає стан для всіх областей."""

    def __init__(self):
        import threading
        self.threats: dict[str, ThreatState] = {}
        self.last_sound_time: float = 0.0
        self.real_threats_backup: dict = {}
        self._clear_lock = threading.Lock()
        self._batch_mode: bool = False  # When True, skip individual Firestore saves (batch will save once)
        
        self._save_timer = None
        self._save_real_timer = None
        self._save_lock = threading.Lock()
        self._fcm_batch_buffer = []  # Collects FCM notifications during batch mode
        
        for region in ALL_REGIONS:
            self.threats[region] = ThreatState()

    def save_to_db(self):
        import threading
        with self._save_lock:
            if getattr(self, '_save_timer', None) is not None:
                self._save_timer.cancel()
            self._save_timer = threading.Timer(5.0, self._execute_save_to_db)
            self._save_timer.start()

    def _execute_save_to_db(self):
        import time as _time
        db = get_db()
        if db:
            state_data = {
                region: state.to_dict()
                for region, state in self.threats.items()
            }
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    doc_ref = db.collection('sirenua_state').document('threats')
                    doc_ref.set(state_data)
                    break
                except Exception as e:
                    err_str = str(e)
                    if ("429" in err_str or "Quota" in err_str) and attempt < max_retries - 1:
                        wait = (2 ** attempt) * 5  # 5s, 10s
                        print(f"⚠️ Firestore quota hit saving state, retry {attempt+1}/{max_retries} in {wait}s")
                        _time.sleep(wait)
                    else:
                        print(f"⚠️ Помилка збереження стану загроз у Firebase: {e}")
                        break
        self.save_to_file()

    def load_from_db(self):
        db = get_db()
        if db:
            try:
                doc_ref = db.collection('sirenua_state').document('threats')
                doc = doc_ref.get()
                if doc.exists:
                    state_data = doc.to_dict()
                    for region, data in state_data.items():
                        if region in self.threats:
                            self.threats[region].load_from_dict(data)
                    print("💾 Завантажено збережений стан загроз з Firebase Firestore")
                else:
                    print("⚠️ Документ загроз у Firebase не знайдено.")
                    self.load_from_file()
                
                # Load real threats backup
                self.load_real_threats_from_db()
                if not self.real_threats_backup:
                    for region, state in self.threats.items():
                        if not state.is_test:
                            self.real_threats_backup[region] = state.to_dict()
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз з Firebase: {e}")
                self.load_from_file()
        else:
            self.load_from_file()

    def save_real_threats_to_db(self):
        import threading
        with self._save_lock:
            if getattr(self, '_save_real_timer', None) is not None:
                self._save_real_timer.cancel()
            self._save_real_timer = threading.Timer(2.5, self._execute_save_real_threats_to_db)
            self._save_real_timer.start()

    def _execute_save_real_threats_to_db(self):
        db = get_db()
        if db:
            try:
                doc_ref = db.collection('sirenua_state').document('real_threats')
                doc_ref.set(self.real_threats_backup)
            except Exception as e:
                print(f"⚠️ Помилка збереження резервного копіювання реальних загроз у Firebase: {e}")
        self.save_real_threats_to_file()

    def save_real_threats_to_file(self):
        import json
        import os
        try:
            filepath = "real_threats_state.json"
            if os.path.exists("threat_server"):
                filepath = "threat_server/real_threats_state.json"
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.real_threats_backup, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"⚠️ Помилка збереження резервної копії реальних загроз у файл: {e}")

    def load_real_threats_from_db(self):
        db = get_db()
        loaded = False
        if db:
            try:
                doc_ref = db.collection('sirenua_state').document('real_threats')
                doc = doc_ref.get()
                if doc.exists:
                    self.real_threats_backup = doc.to_dict()
                    print("💾 Завантажено резервну копію реальних загроз з Firebase")
                    loaded = True
            except Exception as e:
                print(f"⚠️ Помилка завантаження резервної копії реальних загроз з Firebase: {e}")
        if not loaded:
            self.load_real_threats_from_file()

    def load_real_threats_from_file(self):
        import json
        import os
        filepath = "real_threats_state.json"
        if os.path.exists("threat_server"):
            filepath = "threat_server/real_threats_state.json"
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    self.real_threats_backup = json.load(f)
                print("💾 Завантажено резервну копію реальних загроз з файлу")
            except Exception as e:
                print(f"⚠️ Помилка завантаження резервної копії реальних загроз з файлу: {e}")

    def save_to_file(self):
        import json
        import os
        try:
            state_data = {
                region: state.to_dict()
                for region, state in self.threats.items()
            }
            filepath = "threats_state.json"
            if os.path.exists("threat_server"):
                filepath = "threat_server/threats_state.json"
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(state_data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"⚠️ Помилка збереження стану загроз: {e}")

    def load_from_file(self):
        import json
        import os
        filepath = "threats_state.json"
        if os.path.exists("threat_server"):
            filepath = "threat_server/threats_state.json"
        if os.path.exists(filepath):
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    state_data = json.load(f)
                for region, data in state_data.items():
                    if region in self.threats:
                        self.threats[region].load_from_dict(data)
                print(f"💾 Завантажено збережений стан загроз з {filepath}")
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз: {e}")

    def set_scenario(self, scenario: str):
        """Встановлює попередньо визначений сценарій для тестування з інтелектуальним оновленням та чергою."""
        
        # Бекап всієї бази SQLite перед початком тестування сценарію
        try:
            backup_sqlite_to_firestore()
        except Exception as e:
            print(f"⚠️ Помилка бекапу SQLite перед сценарієм: {e}")

        # Бекап реальних загроз до тестування
        for region, state in self.threats.items():
            if not state.is_test:
                self.real_threats_backup[region] = state.to_dict()
        self._execute_save_real_threats_to_db()
        
        new_threats = {}
        
        # Format of value: (level, threat_type, detail, confidence, eta, is_predictive)
        if scenario == "mig_takeoff":
            for r in ALL_REGIONS:
                new_threats[r] = (
                    "high", 
                    "mig31k", 
                    "Зафіксовано зліт винищувача МіГ-31К ПКС РФ.\nТип: Кінджал\nНапрямок запуску: Північ\nШвидкість руху: ~3000 км/год\nВисота польоту: надвисока\nОчікуваний час: ~10 хв",
                    95,
                    "~10 хв",
                    False
                )
        elif scenario == "shaheds_south":
            south_regions = [
                "Одеська область", "Миколаївська область",
                "Херсонська область", "Запорізька область",
                "Дніпропетровська область", "Кіровоградська область",
            ]
            for r in south_regions:
                new_threats[r] = (
                    "medium", 
                    "shahed", 
                    "Виявлено групу БпЛА 'Shahed' з південного напрямку.\nВідстань: ~120 км\nШвидкість руху: ~180 км/год\nКількість цілей: ~5-7\nОчікуваний час: ~45 хв\nПатерн підтверджений аналітикою",
                    82,
                    "~45 хв",
                    True
                )
        elif scenario == "cruise_missiles_west":
            west_regions = [
                "Київська область", "м. Київ", "Житомирська область",
                "Хмельницька область", "Вінницька область",
                "Львівська область", "Рівненська область",
            ]
            for r in west_regions:
                new_threats[r] = (
                    "high", 
                    "cruise_missile", 
                    "Крилаті ракети Х-101 прямують у західні області.\nВідстань до цілі: ~250 км\nКількість цілей: 4\nТип: Х-101\nШвидкість руху: ~850 км/год\nВисота польоту: середня\nОчікуваний час: ~20 хв\nПатерн підтверджений аналітикою",
                    88,
                    "~20 хв",
                    True
                )
        elif scenario == "massive_attack":
            for r in ALL_REGIONS:
                new_threats[r] = (
                    "critical", 
                    "tu95", 
                    "Масований ракетний удар! Зафіксовано пуски з 6х Ту-95МС.\nВідстань до цілі: ~400 км\nКількість цілей: 12+\nТип: Х-101/Х-555\nШвидкість руху: ~850 км/год\nОчікуваний час: ~30-40 хв",
                    98,
                    "~30-40 хв",
                    False
                )
        elif scenario == "ballistic_kharkiv":
            new_threats["Харківська область"] = (
                "critical", 
                "ballistic", 
                "Загроза застосування балістичного озброєння з Бєлгорода!\nВідстань до цілі: ~40 км\nТип: Іскандер-М\nШвидкість руху: ~3600 км/год\nОчікуваний час: ~2 хв",
                92,
                "~2 хв",
                False
            )
            new_threats["Сумська область"] = (
                "medium", 
                "ballistic", 
                "Можлива балістична загроза з прикордонних районів РФ.\nОчікуваний час: ~3 хв",
                70,
                "~3 хв",
                True
            )
        
        for region in ALL_REGIONS:
            old_state = self.threats[region]
            if region in new_threats:
                level, t_type, detail, confidence, eta, is_predictive = new_threats[region]
                self.set_threat(
                    region=region,
                    level=level,
                    threat_type=t_type,
                    detail=detail,
                    confidence=confidence,
                    eta=eta,
                    is_predictive=is_predictive,
                    is_test=True
                )
            else:
                if old_state.level != "none" and old_state.is_test:
                    self.clear_threat(region)

    def set_threat(self, region: str, level: str,
                   threat_type: Optional[str] = None,
                   detail: Optional[str] = None,
                   confidence: Optional[int] = None,
                   eta: Optional[str] = None,
                   is_predictive: bool = False,
                   is_test: bool = False,
                   telemetry: dict = None,
                   rules_applied: list = None) -> bool:
        if region not in self.threats:
            return False

        old_state = self.threats[region]
        old_level = old_state.level

        # Витягуємо group_id з телеметрії для дедуплікації
        group_id = None
        if telemetry and isinstance(telemetry, dict):
            group_id = telemetry.get("group_id")

        if not is_test:
            self.real_threats_backup[region] = old_state.to_dict()
            self.save_real_threats_to_db()
        else:
            # Якщо це перша тестова загроза у сесії, робимо бекап SQLite у Firestore
            any_test_active = any(s.is_test for s in self.threats.values())
            if not any_test_active:
                try:
                    backup_sqlite_to_firestore()
                except Exception as backup_err:
                    print(f"⚠️ Помилка бекапу SQLite перед початком тесту: {backup_err}")

            if not old_state.is_test and old_state.level != "none":
                self.real_threats_backup[region] = old_state.to_dict()
                self.save_real_threats_to_db()

        has_changed = self.threats[region].set_threat(
            level, threat_type, detail, confidence, eta,
            is_predictive, is_test, group_id=group_id
        )
        
        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
            
            if self._batch_mode:
                # Buffer FCM during batch — will flush as summary after batch
                self._fcm_batch_buffer.append({
                    "region": region, "level": level, "threat_type": threat_type,
                    "detail": detail, "confidence": confidence, "eta": eta,
                    "is_official_alarm": self.threats[region].is_active,
                    "is_test": self.threats[region].is_test
                })
            else:
                send_fcm_notification(region, level, threat_type, detail, play_sound=play_sound, confidence=confidence, eta=eta, is_official_alarm=self.threats[region].is_active, is_test=self.threats[region].is_test)
            if not self._batch_mode:
                self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region], telemetry=telemetry, rules_applied=rules_applied)
            
        return True

    def flush_fcm_batch(self):
        """Send buffered FCM notifications after batch processing.
        Groups by threat type and sends per-region pushes but with sound only on first."""
        if not self._fcm_batch_buffer:
            return
        
        items = list(self._fcm_batch_buffer)
        self._fcm_batch_buffer.clear()
        
        # Send first notification with sound, rest without (to avoid audio spam)
        for i, item in enumerate(items):
            play_sound = (i == 0)  # Only first push plays sound
            send_fcm_notification(
                region=item["region"],
                level=item["level"],
                threat_type=item["threat_type"],
                detail=item["detail"],
                play_sound=play_sound,
                confidence=item["confidence"],
                eta=item["eta"],
                is_official_alarm=item["is_official_alarm"],
                is_test=item["is_test"]
            )
        print(f"🚀 FCM batch flush: {len(items)} сповіщень (звук тільки у першому)")

    def clear_threat(self, region: str, clearing_telemetry: dict = None,
                     group_id: str = None, threat_type: str = None) -> bool:
        """Знімає конкретну загрозу з області.
        Логіка пошуку загрози для зняття:
        1) За group_id (якщо вказано або є в clearing_telemetry.linked_group_id)
        2) За threat_type (якщо вказано)
        3) Найстаріша загроза (fallback)
        """
        if region not in self.threats:
            return False
        old_state = self.threats[region]
        had_threats = len(old_state.active_threats) > 0

        # Визначаємо group_id та threat_type для пошуку
        linked_gid = group_id
        if not linked_gid and clearing_telemetry and isinstance(clearing_telemetry, dict):
            linked_gid = clearing_telemetry.get("linked_group_id")
        clearing_type = threat_type
        if not clearing_type and clearing_telemetry and isinstance(clearing_telemetry, dict):
            clearing_type = clearing_telemetry.get("threat_type_cleared")

        # Адресне зняття загрози
        removed_threat = None
        if linked_gid:
            removed_threat = old_state.clear_by_group_id(linked_gid)
        if removed_threat is None and clearing_type:
            removed_threat = old_state.clear_by_type(clearing_type)
        if removed_threat is None and had_threats:
            removed_threat = old_state.clear_oldest()

        has_changed = removed_threat is not None

        # Оновлюємо бекап реальних загроз
        if has_changed and (removed_threat is None or not removed_threat.is_test):
            self.real_threats_backup[region] = old_state.to_dict()
            self.save_real_threats_to_db()

        # Якщо більше немає активних загроз — відправляємо FCM "none"
        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now

            current_level = old_state.level  # "none" якщо порожній, або найвищий рівень залишених
            if current_level == "none":
                # Усі загрози зняті — відправляємо FCM про зняття
                send_fcm_notification(region, "none", play_sound=play_sound,
                                      is_official_alarm=old_state.is_active,
                                      is_test=removed_threat.is_test if removed_threat else False)
            # Якщо залишились інші загрози — не відправляємо FCM "none"

            if not self._batch_mode:
                self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region], telemetry=None)
        return True

    def clear_all(self, only_test: bool = False):
        if not self._clear_lock.acquire(blocking=False):
            print("🧹 Clear all operation is already in progress, skipping duplicate request.")
            return
        try:
            any_changed = False
            for region, state in self.threats.items():
                if only_test and not state.is_test:
                    continue
                has_changed = (state.level != "none")
                if has_changed:
                    is_test_flag = state.is_test
                    state.clear()
                    
                    # Apply 10-second sound rule to clearances too, to avoid sound overlap / spamming
                    now = time.time()
                    play_sound = True
                    if now - self.last_sound_time < 10.0:
                        play_sound = False
                    else:
                        self.last_sound_time = now
                        
                    send_fcm_notification(region, "none", play_sound=play_sound, is_test=is_test_flag)
                    any_changed = True
                    if hasattr(self, 'on_change'):
                        self.on_change(region, state, telemetry=None)
            
            # Restore real threats from backup if clearing test
            if only_test:
                for region, data in self.real_threats_backup.items():
                    if region in self.threats:
                        state = self.threats[region]
                        restored_has_changed = (
                            state.level != data.get("level", "none") or
                            state.threat_type != data.get("type") or
                            state.detail != data.get("detail") or
                            state.is_active != data.get("is_active", False) or
                            state.is_test != False
                        )
                        
                        if restored_has_changed:
                            state.load_from_dict(data)
                            state.is_test = False
                            
                            any_changed = True
                            
                            # Send notification to update clients
                            if state.level != "none":
                                send_fcm_notification(region, state.level, state.threat_type, state.detail, confidence=state.confidence, eta=state.eta, is_official_alarm=state.is_active)
                            elif state.is_active:
                                send_fcm_notification(region, "high", is_official_alarm=True, detail="Повітряна тривога")
                            else:
                                send_fcm_notification(region, "none")
                                
                            if hasattr(self, 'on_change'):
                                self.on_change(region, state, telemetry=None)
                
                # Після відновлення очищуємо бекап реальних загроз
                self.real_threats_backup.clear()
                self.save_real_threats_to_db()

            if any_changed:
                self.save_to_db()
                self.save_to_file()
                
            # Відновлення бази SQLite до до-тестового стану з бекапу Firestore (якщо очищуємо лише тести)
            restored_sqlite = False
            if only_test:
                try:
                    restored_sqlite = restore_sqlite_from_firestore(force=True)
                except Exception as e:
                    print(f"⚠️ Помилка примусового відновлення SQLite з Firestore: {e}")

            # Clear mock/test history events from Firestore and SQLite
            try:
                delete_test_history_from_firestore()
                if not restored_sqlite:
                    # Якщо примусове відновлення не відпрацювало (наприклад, офлайн), робимо класичне очищення
                    delete_test_history_from_sqlite()
                    # Негайний бекап очищеної бази в Firestore
                    backup_sqlite_to_firestore()
            except Exception as e:
                print(f"⚠️ Помилка очищення тестової історії: {e}")
        finally:
            self._clear_lock.release()

    def get_all_threats(self) -> dict:
        return {
            region: state.to_dict()
            for region, state in self.threats.items()
        }

    def set_alarm_active(self, region: str, is_active: bool) -> bool:
        if region not in self.threats:
            return False
        
        # Update real threats backup state first
        if region in self.real_threats_backup:
            self.real_threats_backup[region]["is_active"] = is_active
        else:
            self.real_threats_backup[region] = {
                "level": "none",
                "type": None,
                "detail": None,
                "since": None,
                "confidence": None,
                "eta": None,
                "is_predictive": False,
                "is_active": is_active,
                "is_test": False
            }

        # If this region currently has a test threat, do not overwrite its active view state
        if self.threats[region].is_test:
            return False
            
        old_active = self.threats[region].is_active
        if old_active != is_active:
            self.threats[region].is_active = is_active
            
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
            
            # Send Push Notification for official Alarm / Off
            detail = "Повітряна тривога" if is_active else "Відбій повітряної тривоги"
            send_fcm_notification(
                region=region,
                level="high" if is_active else "none",
                threat_type=None,
                detail=detail,
                play_sound=play_sound,
                is_official_alarm=is_active
            )
            
            self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region], telemetry=None)
            return True
        return False

def delete_test_history_from_firestore():
    db = get_db()
    if not db:
        return
    try:
        docs = db.collection('sirenua_history').where('is_test', '==', True).get()
        deleted_count = 0
        for doc in docs:
            doc.reference.delete()
            deleted_count += 1
        print(f"🧹 Видалено {deleted_count} тестових записів з історії Firestore")
    except Exception as e:
        print(f"⚠️ Помилка видалення тестової історії з Firestore: {e}")

def delete_test_history_from_sqlite():
    import sqlite3
    import os
    DB_PATH = "threat_analytics.db"
    if os.path.exists("threat_server"):
        DB_PATH = "threat_server/threat_analytics.db"
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # Delete paired events referencing test threats or test clearings
        cursor.execute('''
            DELETE FROM paired_events 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
               OR clearing_event_id IN (SELECT id FROM threat_clearings WHERE is_test = 1)
        ''')
        paired_deleted = cursor.rowcount

        # Delete telemetry associated with test threat history
        cursor.execute('''
            DELETE FROM telemetry_data 
            WHERE threat_event_id IN (SELECT id FROM threat_history WHERE is_test = 1)
        ''')
        
        # Delete test threat history events
        cursor.execute("DELETE FROM threat_history WHERE is_test = 1")
        threats_deleted = cursor.rowcount
        
        # Delete test threat clearings
        cursor.execute("DELETE FROM threat_clearings WHERE is_test = 1")
        clearings_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        print(f"🧹 Видалено тестові записи з SQLite: {threats_deleted} загроз, {clearings_deleted} відбоїв, {paired_deleted} зв'язаних подій")
    except Exception as e:
        print(f"⚠️ Помилка видалення тестової історії з SQLite: {e}")
