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

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False):
        self.level = level
        self.threat_type = threat_type
        self.detail = detail
        self.confidence = confidence
        self.eta = eta
        self.is_predictive = is_predictive
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
                item["eta"]
            )
            # Sleep 1.5 seconds between notifications to space out the sounds on user devices
            await asyncio.sleep(1.5)
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

def send_fcm_notification(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None):
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
                    "eta": eta
                }
            )
            return
        except RuntimeError:
            pass # Event loop not running yet

    _send_fcm_notification_sync(region, level, threat_type, detail, play_sound, confidence, eta)

def _send_fcm_notification_sync(region: str, level: str, threat_type: Optional[str] = None, detail: Optional[str] = None, play_sound: bool = True, confidence: Optional[int] = None, eta: Optional[str] = None):
    """Надсилає Push-сповіщення у Firebase топік для відповідного регіону (синхронний метод)."""
    if not HAS_FIREBASE:
        return

    topic = TOPIC_MAPPING.get(region)
    if not topic:
        return

    if level == "none":
        title = "🟢 Відбій тривоги!"
        body = f"Відбій повітряної тривоги в: {region}."
        sound = "vidbiy.wav"
        is_critical = False
    else:
        if threat_type == "mig31k":
            title = "🚨 Авіаційна небезпека!"
            sound = "siren.wav"
            is_critical = True
        elif level in ("high", "critical"):
            title = "🚨 Повітряна тривога!"
            sound = "siren.wav"
            is_critical = True
        else:
            title = "⚠️ Попередження про загрозу"
            sound = "warning.wav"
            is_critical = False
            
        body = detail if detail else f"Повітряна тривога в: {region}. Прямуйте в укриття!"
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
            sound=critical_sound, 
            badge=1, 
            content_available=True, 
            mutable_content=True,
            custom_data={"interruption-level": "critical" if is_critical else "time-sensitive"}
        )
    else:
        aps = messaging.Aps(
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
        self.threats: dict[str, ThreatState] = {}
        self.last_sound_time: float = 0.0
        for region in ALL_REGIONS:
            self.threats[region] = ThreatState()

    def save_to_db(self):
        db = get_db()
        if db:
            try:
                state_data = {
                    region: state.to_dict()
                    for region, state in self.threats.items()
                }
                doc_ref = db.collection('sirenua_state').document('threats')
                doc_ref.set(state_data)
            except Exception as e:
                print(f"⚠️ Помилка збереження стану загроз у Firebase: {e}")
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
                    print("💾 Завантажено збережений стан загроз з Firebase Firestore")
                else:
                    print("⚠️ Документ загроз у Firebase не знайдено.")
                    self.load_from_file()
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз з Firebase: {e}")
                self.load_from_file()
        else:
            self.load_from_file()

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
                print(f"💾 Завантажено збережений стан загроз з {filepath}")
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз: {e}")

    def set_threat(self, region: str, level: str,
                   threat_type: Optional[str] = None,
                   detail: Optional[str] = None,
                   confidence: Optional[int] = None,
                   eta: Optional[str] = None,
                   is_predictive: bool = False) -> bool:
        if region not in self.threats:
            return False
            
        old_state = self.threats[region]
        has_changed = (old_state.level != level or 
                       old_state.threat_type != threat_type or 
                       old_state.detail != detail or
                       old_state.confidence != confidence)
                       
        self.threats[region].set_threat(level, threat_type, detail, confidence, eta, is_predictive)
        
        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
                
            send_fcm_notification(region, level, threat_type, detail, play_sound=play_sound, confidence=confidence, eta=eta)
            self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region])
            
        return True

    def clear_threat(self, region: str) -> bool:
        if region not in self.threats:
            return False
        old_state = self.threats[region]
        has_changed = (old_state.level != "none")
        self.threats[region].clear()
        if has_changed:
            import time
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
                
            send_fcm_notification(region, "none", play_sound=play_sound)
            self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region])
        return True

    def clear_all(self):
        any_changed = False
        for region, state in self.threats.items():
            has_changed = (state.level != "none")
            if has_changed:
                state.clear()
                send_fcm_notification(region, "none")
                any_changed = True
                if hasattr(self, 'on_change'):
                    self.on_change(region, state)
        if any_changed:
            self.save_to_db()
            self.save_to_file()

    def get_all_threats(self) -> dict:
        return {
            region: state.to_dict()
            for region, state in self.threats.items()
        }

    def set_alarm_active(self, region: str, is_active: bool) -> bool:
        if region not in self.threats:
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
            detail = f"Офіційне повідомлення про повітряну тривогу в: {region}!" if is_active else f"Відбій повітряної тривоги в: {region}."
            send_fcm_notification(
                region=region,
                level="high" if is_active else "none",
                threat_type=None,
                detail=detail,
                play_sound=play_sound
            )
            
            self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region])
            return True
        return False

    def set_scenario(self, scenario: str):
        """Встановлює попередньо визначений сценарій для тестування з інтелектуальним оновленням та чергою."""
        new_threats = {}
        if scenario == "mig_takeoff":
            for r in ALL_REGIONS:
                new_threats[r] = ("high", "mig31k", "Зліт МіГ-31К з аеродрому Сольці")
        elif scenario == "shaheds_south":
            south_regions = [
                "Одеська область", "Миколаївська область",
                "Херсонська область", "Запорізька область",
                "Дніпропетровська область", "Кіровоградська область",
            ]
            for r in south_regions:
                new_threats[r] = ("medium", "shahed", "Шахеди в напрямку з півдня")
        elif scenario == "cruise_missiles_west":
            west_regions = [
                "Київська область", "м. Київ", "Житомирська область",
                "Хмельницька область", "Вінницька область",
                "Львівська область", "Рівненська область",
            ]
            for r in west_regions:
                new_threats[r] = ("high", "cruise_missile", "Крилаті ракети Х-101 в напрямку заходу")
        elif scenario == "massive_attack":
            for r in ALL_REGIONS:
                new_threats[r] = ("critical", "tu95", "Масований ракетний удар! Ту-95МС пуски крилатих ракет")
        elif scenario == "ballistic_kharkiv":
            new_threats["Харківська область"] = ("critical", "ballistic", "Балістична загроза! Іскандер-М")
            new_threats["Сумська область"] = ("medium", "ballistic", "Можлива балістична загроза")

        for region in ALL_REGIONS:
            old_state = self.threats[region]
            if region in new_threats:
                level, t_type, detail = new_threats[region]
                if old_state.level != level or old_state.threat_type != t_type or old_state.detail != detail:
                    self.set_threat(region, level, t_type, detail)
            else:
                if old_state.level != "none":
                    self.clear_threat(region)
