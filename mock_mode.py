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


class ThreatState:
    """Стан загрози для однієї області."""

    def __init__(self):
        self.level: str = "none"  # none, low, medium, high, critical
        self.threat_type: Optional[str] = None
        self.detail: Optional[str] = None
        self.since: Optional[str] = None
        self.eta: Optional[str] = None
        self.confidence: Optional[int] = None  # 0-100% AI confidence
        self.is_predictive: bool = False
        self.is_active: bool = False
        self.is_test: bool = False

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False,
                   is_test: bool = False):
        self.level = level
        self.threat_type = threat_type
        self.detail = detail
        self.confidence = confidence
        self.eta = eta
        self.is_predictive = is_predictive
        self.is_test = is_test
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
            "confidence": self.confidence,
            "eta": self.eta,
            "is_predictive": self.is_predictive,
            "is_active": self.is_active,
            "is_test": self.is_test,
        }

    def clear(self):
        self.level = "none"
        self.threat_type = None
        self.detail = None
        self.since = None
        self.confidence = None
        self.eta = None
        self.is_predictive = False
        self.is_active = False
        self.is_test = False

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
            body = detail if detail else f"Загроза в: {region}."
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

    # Створюємо Aps з interruption_level для коректного відображення на Lock Screen
    if play_sound:
        if is_critical:
            critical_sound = messaging.CriticalSound(name=sound, critical=True, volume=1.0)
        else:
            critical_sound = messaging.CriticalSound(name=sound, critical=False, volume=0.8)
        aps = messaging.Aps(
            alert=messaging.ApsAlert(title=title, body=body),
            sound=critical_sound, 
            badge=1, 
            content_available=True, 
            mutable_content=True,
            custom_data={"interruption-level": "critical" if is_critical else "time-sensitive"}
        )
    else:
        aps = messaging.Aps(
            alert=messaging.ApsAlert(title=title, body=body),
            badge=1, 
            content_available=True, 
            mutable_content=True,
            custom_data={"interruption-level": "critical" if is_critical else "time-sensitive"}
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
                            state = self.threats[region]
                            state.level = data.get("level", "none")
                            state.threat_type = data.get("type")
                            state.detail = data.get("detail")
                            state.since = data.get("since")
                            state.confidence = data.get("confidence")
                            state.eta = data.get("eta")
                            state.is_predictive = data.get("is_predictive", False)
                            state.is_active = data.get("is_active", False)
                            state.is_test = data.get("is_test", False)
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
                        state = self.threats[region]
                        state.level = data.get("level", "none")
                        state.threat_type = data.get("type")
                        state.detail = data.get("detail")
                        state.since = data.get("since")
                        state.confidence = data.get("confidence")
                        state.eta = data.get("eta")
                        state.is_predictive = data.get("is_predictive", False)
                        state.is_active = data.get("is_active", False)
                        state.is_test = data.get("is_test", False)
                print(f"💾 Завантажено збережений стан загроз з {filepath}")
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз: {e}")

    def set_scenario(self, scenario: str):
        """Встановлює попередньо визначений сценарій для тестування з інтелектуальним оновленням та чергою."""
        
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
        has_changed = (old_state.level != level or 
                       old_state.threat_type != threat_type or 
                       old_state.detail != detail or
                       old_state.confidence != confidence or
                       old_state.is_test != is_test)

        if not is_test:
            self.real_threats_backup[region] = {
                "level": level,
                "type": threat_type,
                "detail": detail,
                "since": old_state.since if old_state.level == level else None,
                "confidence": confidence,
                "eta": eta,
                "is_predictive": is_predictive,
                "is_active": old_state.is_active,
                "is_test": False
            }
        else:
            if not old_state.is_test and old_state.level != "none":
                self.real_threats_backup[region] = old_state.to_dict()

        self.threats[region].set_threat(level, threat_type, detail, confidence, eta, is_predictive, is_test)
        
        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
                
            send_fcm_notification(region, level, threat_type, detail, play_sound=play_sound, confidence=confidence, eta=eta, is_official_alarm=self.threats[region].is_active, is_test=self.threats[region].is_test)
            if not self._batch_mode:
                self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region], telemetry=telemetry, rules_applied=rules_applied)
            
        return True

    def clear_threat(self, region: str, clearing_telemetry: dict = None) -> bool:
        if region not in self.threats:
            return False
        old_state = self.threats[region]
        has_changed = (old_state.level != "none")

        if not old_state.is_test:
            if region in self.real_threats_backup:
                self.real_threats_backup[region]["level"] = "none"
                self.real_threats_backup[region]["type"] = None
                self.real_threats_backup[region]["detail"] = None
                self.real_threats_backup[region]["since"] = None
                self.real_threats_backup[region]["confidence"] = None
                self.real_threats_backup[region]["eta"] = None
                self.real_threats_backup[region]["is_predictive"] = False

        keep_active = old_state.is_active if not old_state.is_test else False
        self.threats[region].clear()
        if keep_active:
            self.threats[region].is_active = True

        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
                
            send_fcm_notification(region, "none", play_sound=play_sound, is_official_alarm=keep_active, is_test=old_state.is_test)
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
                            state.level = data.get("level", "none")
                            state.threat_type = data.get("type")
                            state.detail = data.get("detail")
                            state.since = data.get("since")
                            state.confidence = data.get("confidence")
                            state.eta = data.get("eta")
                            state.is_predictive = data.get("is_predictive", False)
                            state.is_active = data.get("is_active", False)
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

            if any_changed:
                self.save_to_db()
                self.save_to_file()
                
            # Clear mock/test history events from Firestore and SQLite
            try:
                delete_test_history_from_firestore()
                delete_test_history_from_sqlite()
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
        print(f"🧹 Видалено тестові записи з SQLite: {threats_deleted} загроз, {clearings_deleted} відбоїв")
    except Exception as e:
        print(f"⚠️ Помилка видалення тестової історії з SQLite: {e}")
