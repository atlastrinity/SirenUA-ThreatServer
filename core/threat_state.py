"""
SirenUA Threat State Models and Manager.
Handles SingleThreat info, regional ThreatState lists, and MockThreatManager.
"""

from datetime import datetime, timezone
import uuid
import os
import json
import time
import threading
from typing import Optional, List, Dict

from core.regions import ALL_REGIONS
from database.db_helpers import (
    get_db,
    backup_sqlite_to_firestore,
    restore_sqlite_from_firestore,
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    send_fcm_notification,
)

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

    def clear(self):
        self.active_threats.clear()
        self.is_test = False

    def clear_by_group_id(self, group_id: str) -> Optional[SingleThreat]:
        for i, t in enumerate(self.active_threats):
            if t.group_id == group_id:
                return self.active_threats.pop(i)
        return None

    def clear_by_type(self, threat_type: str) -> Optional[SingleThreat]:
        for i, t in enumerate(self.active_threats):
            if t.threat_type == threat_type:
                return self.active_threats.pop(i)
        return None

    def to_dict(self) -> dict:
        """Серіалізація — зворотно-сумісний формат + масив active_threats."""
        primary = self.active_threats[-1] if self.active_threats else None
        return {
            "level": self.level,
            "type": primary.threat_type if primary else None,
            "detail": primary.detail if primary else None,
            "since": primary.since if primary else None,
            "confidence": primary.confidence if primary else None,
            "eta": primary.eta if primary else None,
            "is_predictive": self.is_predictive,
            "is_active": self.is_active,
            "is_test": self.is_test,
            "active_threats": [t.to_dict() for t in self.active_threats],
        }

    def load_from_dict(self, data: dict):
        self.is_active = data.get("is_active", False)
        self.is_test = data.get("is_test", False)
        if "active_threats" in data:
            self.active_threats = [SingleThreat.from_dict(t) for t in data["active_threats"]]
        else:
            self.active_threats = []
            level = data.get("level", "none")
            if level != "none":
                t = SingleThreat(
                    level=level,
                    threat_type=data.get("type"),
                    detail=data.get("detail"),
                    confidence=data.get("confidence"),
                    eta=data.get("eta"),
                    is_predictive=data.get("is_predictive", False),
                    is_test=self.is_test
                )
                if data.get("since"):
                    t.since = data["since"]
                self.active_threats.append(t)

    def set_threat(self, level: str, threat_type: Optional[str] = None,
                   detail: Optional[str] = None, confidence: Optional[int] = None,
                   eta: Optional[str] = None, is_predictive: bool = False,
                   is_test: bool = False, group_id: Optional[str] = None,
                   eta_seconds: Optional[int] = None) -> bool:
        if level == "none":
            self.clear()
            return True

        self.is_test = is_test

        # Дедуплікація: перевіряємо чи є вже така загроза
        if group_id:
            for existing in self.active_threats:
                if existing.group_id == group_id:
                    changed = False
                    if existing.level != level:
                        existing.level = level
                        changed = True
                    if detail and existing.detail != detail:
                        existing.detail = detail
                        changed = True
                    if confidence is not None and existing.confidence != confidence:
                        existing.confidence = confidence
                        changed = True
                    if eta and existing.eta != eta:
                        existing.eta = eta
                        changed = True
                    if eta_seconds is not None and existing.eta_seconds != eta_seconds:
                        existing.eta_seconds = eta_seconds
                        changed = True
                    if existing.is_predictive != is_predictive:
                        existing.is_predictive = is_predictive
                        changed = True
                    return changed

        # Розумна дедуплікація за часовим вікном (якщо немає group_id)
        now = time.time()
        for existing in self.active_threats:
            if existing.threat_type == threat_type:
                try:
                    since_str = existing.since.replace("Z", "+00:00")
                    since_dt = datetime.fromisoformat(since_str)
                    elapsed = now - since_dt.timestamp()
                    if elapsed < self.DEDUP_WINDOW_SECONDS:
                        # Оновлюємо існуючу загрозу в рамках вікна
                        changed = False
                        if existing.level != level:
                            existing.level = level
                            changed = True
                        if detail and existing.detail != detail:
                            existing.detail = detail
                            changed = True
                        if confidence is not None and existing.confidence != confidence:
                            existing.confidence = confidence
                            changed = True
                        if eta and existing.eta != eta:
                            existing.eta = eta
                            changed = True
                        if eta_seconds is not None and existing.eta_seconds != eta_seconds:
                            existing.eta_seconds = eta_seconds
                            changed = True
                        if existing.is_predictive != is_predictive:
                            existing.is_predictive = is_predictive
                            changed = True
                        return changed
                except Exception:
                    pass

        # Додаємо нову загрозу
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
        return True


class MockThreatManager:
    """Менеджер загроз — зберігає стан для всіх областей."""

    def __init__(self):
        self.threats: dict[str, ThreatState] = {}
        self.last_sound_time: float = 0.0
        self.real_threats_backup: dict = {}
        self._clear_lock = threading.Lock()
        self._batch_mode: bool = False
        
        self._save_timer = None
        self._save_real_timer = None
        self._save_lock = threading.Lock()
        self._fcm_batch_buffer = []
        
        for region in ALL_REGIONS:
            self.threats[region] = ThreatState()

    def save_to_db(self):
        with self._save_lock:
            if getattr(self, '_save_timer', None) is not None:
                self._save_timer.cancel()
            self._save_timer = threading.Timer(5.0, self._execute_save_to_db)
            self._save_timer.start()

    def _execute_save_to_db(self):
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
                        wait = (2 ** attempt) * 5
                        print(f"⚠️ Firestore quota hit saving state, retry {attempt+1}/{max_retries} in {wait}s")
                        time.sleep(wait)
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

    def set_threat(self, region: str, level: str,
                   threat_type: Optional[str] = None,
                   detail: Optional[str] = None,
                   confidence: Optional[int] = None,
                   eta: Optional[str] = None,
                   is_predictive: bool = False,
                   is_test: bool = False,
                   telemetry: dict = None,
                   rules_applied: list = None,
                   eta_seconds: Optional[int] = None) -> bool:
        if region not in self.threats:
            return False

        old_state = self.threats[region]
        old_level = old_state.level

        group_id = None
        if telemetry and isinstance(telemetry, dict):
            group_id = telemetry.get("group_id")

        if eta_seconds is None and telemetry and isinstance(telemetry, dict):
            speed = telemetry.get("speed_kmh")
            dist = telemetry.get("distance_to_target_km")
            if speed and dist and speed > 0:
                eta_seconds = int((dist / speed) * 3600)

        if not is_test:
            self.real_threats_backup[region] = old_state.to_dict()
            self.save_real_threats_to_db()
        else:
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
            is_predictive, is_test, group_id=group_id,
            eta_seconds=eta_seconds
        )
        
        if has_changed:
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now
            
            if self._batch_mode:
                self._fcm_batch_buffer.append({
                    "region": region,
                    "level": level,
                    "threat_type": threat_type,
                    "detail": detail,
                    "play_sound": play_sound,
                    "confidence": confidence,
                    "eta": eta,
                    "is_official_alarm": self.threats[region].is_active,
                    "is_test": self.threats[region].is_test
                })
            else:
                send_fcm_notification(region, level, threat_type, detail, play_sound=play_sound, confidence=confidence, eta=eta, is_official_alarm=self.threats[region].is_active, is_test=self.threats[region].is_test)
            
            self.save_to_db()
            if hasattr(self, 'on_change'):
                self.on_change(region, self.threats[region], telemetry=telemetry)
            return True
        return False

    def flush_fcm_batch(self):
        if not self._fcm_batch_buffer:
            return
        items = list(self._fcm_batch_buffer)
        self._fcm_batch_buffer.clear()
        
        # Обмеження звукового спаму: звук дозволено програвати лише на першому сповіщенні з батчу
        for i, item in enumerate(items):
            play_sound = (i == 0)
            send_fcm_notification(
                item["region"],
                item["level"],
                item["threat_type"],
                item["detail"],
                play_sound=play_sound,
                confidence=item["confidence"],
                eta=item["eta"],
                is_official_alarm=item["is_official_alarm"],
                is_test=item["is_test"]
            )
        print(f"🚀 FCM batch flush: {len(items)} сповіщень (звук тільки у першому)")

    def clear_threat(self, region: str, clearing_telemetry: dict = None,
                      group_id: str = None, threat_type: str = None) -> bool:
        if region not in self.threats:
            return False
        old_state = self.threats[region]
        had_threats = len(old_state.active_threats) > 0

        linked_gid = group_id
        if not linked_gid and clearing_telemetry and isinstance(clearing_telemetry, dict):
            linked_gid = clearing_telemetry.get("linked_group_id")
        clearing_type = threat_type
        if not clearing_type and clearing_telemetry and isinstance(clearing_telemetry, dict):
            clearing_type = clearing_telemetry.get("threat_type_cleared")

        removed_threat = None
        if linked_gid:
            removed_threat = old_state.clear_by_group_id(linked_gid)
        if removed_threat is None and clearing_type:
            removed_threat = old_state.clear_by_type(clearing_type)
        if removed_threat is None and had_threats:
            removed_threats = []
            while old_state.active_threats:
                removed_threats.append(old_state.active_threats.pop(0))
            if removed_threats:
                removed_threat = removed_threats[-1]

        has_changed = removed_threat is not None

        if has_changed and (removed_threat is None or not removed_threat.is_test):
            self.real_threats_backup[region] = old_state.to_dict()
            self.save_real_threats_to_db()

        if has_changed:
            now = time.time()
            play_sound = True
            if now - self.last_sound_time < 10.0:
                play_sound = False
            else:
                self.last_sound_time = now

            current_level = old_state.level
            if current_level == "none":
                send_fcm_notification(region, "none", play_sound=play_sound,
                                      is_official_alarm=old_state.is_active,
                                      is_test=removed_threat.is_test if removed_threat else False)

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
                    
                    now = time.time()
                    play_sound = True
                    if now - self.last_sound_time < 10.0:
                        play_sound = False
                    else:
                        self.last_sound_time = now
                        
                    send_fcm_notification(region, "none", play_sound=play_sound, is_test=is_test_flag)
                    
                    if not is_test_flag:
                        self.real_threats_backup[region] = state.to_dict()
                    any_changed = True
                    
            if any_changed:
                self._execute_save_to_db()
                self._execute_save_real_threats_to_db()
                if only_test:
                    try:
                        delete_test_history_from_sqlite()
                        delete_test_history_from_firestore()
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

        if not self.threats[region].is_test:
            has_changed = (self.threats[region].is_active != is_active)
            self.threats[region].is_active = is_active
            if has_changed:
                self.save_real_threats_to_db()
                self.save_to_db()
                if hasattr(self, 'on_change'):
                    self.on_change(region, self.threats[region], telemetry=None)
                return True
        else:
            if region in self.real_threats_backup:
                self.real_threats_backup[region]["is_active"] = is_active
                self.save_real_threats_to_db()
            return True
        return False

    def reset_to_real_threats(self):
        print("🧹 Скидання тестових загроз до реального стану...")
        backup_loaded = False
        try:
            db = get_db()
            if db:
                doc_ref = db.collection('sirenua_state').document('real_threats')
                doc = doc_ref.get()
                if doc.exists:
                    self.real_threats_backup = doc.to_dict()
                    backup_loaded = True
        except Exception as e:
            print(f"⚠️ Помилка отримання бекапу реальних загроз з Firebase: {e}")

        if not backup_loaded:
            self.load_real_threats_from_file()

        for region, data in self.real_threats_backup.items():
            if region in self.threats:
                self.threats[region].load_from_dict(data)

        self._execute_save_to_db()
        try:
            delete_test_history_from_sqlite()
            delete_test_history_from_firestore()
        except Exception as e:
            print(f"⚠️ Помилка очищення тестової історії: {e}")

    def set_scenario_with_delay(self, scenario: str, delay_seconds: float):
        threading.Thread(target=self._run_scenario_with_delay, args=(scenario, delay_seconds), daemon=True).start()

    def _run_scenario_with_delay(self, scenario: str, delay_seconds: float):
        time.sleep(delay_seconds)
        self.set_scenario(scenario)
