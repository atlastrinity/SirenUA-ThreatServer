"""
MockThreatManager state coordinator and DB persistence manager.
"""

from datetime import datetime, timezone
import os
import json
import time
import threading
from typing import Optional

from core.regions import ALL_REGIONS
from core.threats.single_threat import SingleThreat
from core.threats.threat_state_model import ThreatState
from database.db_helpers import (
    get_db,
    backup_sqlite_to_firestore,
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    send_fcm_notification,
    run_firestore_with_retry,
)
from core.threat_types import (
    THREAT_SHAHED,
    THREAT_CRUISE_MISSILE,
    THREAT_BALLISTIC,
    THREAT_MIG31K,
    THREAT_TU95,
)


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
            self.threats[region] = ThreatState(region)

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
            try:
                run_firestore_with_retry(
                    lambda: db.collection('sirenua_state').document('threats').set(state_data),
                    operation_name="save_threats_state",
                    context_info="MockThreatManager"
                )
            except Exception:
                pass
        self.save_to_file()

    def load_from_sqlite(self) -> bool:
        """Restores active threat states from local SQLite database (paired_events & telemetry_data)."""
        try:
            import sqlite3
            from database.db_helpers import get_sqlite_connection, DB_PATH
            conn = get_sqlite_connection(DB_PATH)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT p.region, p.threat_level, p.threat_type, p.confidence_at_set, p.gemini_group_id,
                       t.attack_vector, t.speed_kmh, t.heading_degrees, t.distance_to_target_km, t.target_cities_coords
                FROM paired_events p
                LEFT JOIN telemetry_data t ON p.telemetry_id = t.id
                WHERE p.lifecycle_status = 'active'
            """)
            rows = cursor.fetchall()
            conn.close()

            if rows:
                restored_count = 0
                for row in rows:
                    region = row["region"]
                    if region in self.threats:
                        telemetry = None
                        if row["gemini_group_id"]:
                            telemetry = {
                                "group_id": row["gemini_group_id"],
                                "attack_vector": row["attack_vector"],
                                "speed_kmh": row["speed_kmh"],
                                "heading_degrees": row["heading_degrees"],
                                "distance_to_target_km": row["distance_to_target_km"],
                            }
                            if row["target_cities_coords"]:
                                try:
                                    telemetry["target_cities_coords"] = json.loads(row["target_cities_coords"])
                                except Exception:
                                    pass

                        self.set_threat(
                            region=region,
                            level=row["threat_level"],
                            threat_type=row["threat_type"],
                            confidence=row["confidence_at_set"],
                            telemetry=telemetry
                        )
                        restored_count += 1
                print(f"💾 Відновлено {restored_count} активних загроз з локальної SQLite.")
                return True
        except Exception as e:
            print(f"⚠️ Помилка відновлення активних загроз з SQLite: {e}")
        return False

    def load_from_db(self):
        loaded = False
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
                    loaded = True
                else:
                    print("⚠️ Документ загроз у Firebase не знайдено.")
            except Exception as e:
                print(f"⚠️ Помилка завантаження стану загроз з Firebase: {e}")

        if not loaded:
            loaded = self.load_from_file()

        if not loaded or not any(s.is_active for s in self.threats.values()):
            self.load_from_sqlite()

        self.load_real_threats_from_db()
        if not self.real_threats_backup:
            for region, state in self.threats.items():
                if not state.is_test:
                    self.real_threats_backup[region] = state.to_dict()

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

    def _atomic_json_save(self, filepath: str, data: dict):
        try:
            backup_dir = os.path.dirname(filepath)
            backup_dir = os.path.join(backup_dir if backup_dir else ".", "backups")
            os.makedirs(backup_dir, exist_ok=True)

            bak_path = filepath + ".bak"
            tmp_path = filepath + ".tmp"

            if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
                try:
                    import shutil
                    shutil.copy2(filepath, bak_path)
                    base_name = os.path.basename(filepath)
                    hist_path = os.path.join(backup_dir, f"{base_name}.bak")
                    shutil.copy2(filepath, hist_path)
                except Exception as b_err:
                    print(f"⚠️ Не вдалося створити бекап {bak_path}: {b_err}")

            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

            os.replace(tmp_path, filepath)
        except Exception as e:
            print(f"⚠️ Помилка атомарного збереження {filepath}: {e}")

    def _atomic_json_load(self, filepath: str) -> Optional[dict]:
        candidates = [filepath, filepath + ".bak"]
        backup_dir = os.path.join(os.path.dirname(filepath) if os.path.dirname(filepath) else ".", "backups")
        hist_path = os.path.join(backup_dir, f"{os.path.basename(filepath)}.bak")
        candidates.append(hist_path)

        for path in candidates:
            if os.path.exists(path) and os.path.getsize(path) > 0:
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    if data:
                        if path != filepath:
                            print(f"🔄 [Auto-Recovery] Відновлено JSON стан з резервної копії: {path}")
                        return data
                except (json.JSONDecodeError, OSError) as err:
                    print(f"⚠️ Файл стану пошкоджено або нечитабельний ({path}): {err}")
        return None

    def save_real_threats_to_file(self):
        filepath = "real_threats_state.json"
        if os.path.exists("threat_server"):
            filepath = "threat_server/real_threats_state.json"
        self._atomic_json_save(filepath, self.real_threats_backup)

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
        data = self._atomic_json_load(filepath)
        if data:
            self.real_threats_backup = data
            print(f"💾 Завантажено резервну копію реальних загроз з {filepath}")

    def save_to_file(self):
        state_data = {
            region: state.to_dict()
            for region, state in self.threats.items()
        }
        filepath = "threats_state.json"
        if os.path.exists("threat_server"):
            filepath = "threat_server/threats_state.json"
        self._atomic_json_save(filepath, state_data)

    def load_from_file(self):
        filepath = "threats_state.json"
        if os.path.exists("threat_server"):
            filepath = "threat_server/threats_state.json"
        state_data = self._atomic_json_load(filepath)
        if state_data:
            for region, data in state_data.items():
                if region in self.threats:
                    self.threats[region].load_from_dict(data)
            print(f"💾 Завантажено збережений стан загроз з {filepath}")
            return True
        return False

    def set_scenario(self, scenario: str):
        new_threats = {}
        
        if scenario == "mig_takeoff":
            for r in ALL_REGIONS:
                new_threats[r] = (
                    "high", 
                    THREAT_MIG31K, 
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
                    THREAT_SHAHED, 
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
                    THREAT_CRUISE_MISSILE, 
                    "Крилаті ракети Х-101 прямують у західні області.\nВідстань до цілі: ~250 км\nКількість цілей: 4\nТип: Х-101\nШвидкість руху: ~850 км/год\nВисота польоту: середня\nОчікуваний час: ~20 хв\nПатерн підтверджений аналітикою",
                    88,
                    "~20 хв",
                    True
                )
        elif scenario == "massive_attack":
            for r in ALL_REGIONS:
                new_threats[r] = (
                    "critical", 
                    THREAT_TU95, 
                    "Масований ракетний удар! Зафіксовано пуски з 6х Ту-95МС.\nВідстань до цілі: ~400 км\nКількість цілей: 12+\nТип: Х-101/Х-555\nШвидкість руху: ~850 км/год\nОчікуваний час: ~30-40 хв",
                    98,
                    "~30-40 хв",
                    False
                )
        elif scenario == "ballistic_kharkiv":
            new_threats["Харківська область"] = (
                "critical", 
                THREAT_BALLISTIC, 
                "Загроза застосування балістичного озброєння з Бєлгорода!\nВідстань до цілі: ~40 км\nТип: Іскандер-М\nШвидкість руху: ~3600 км/год\nОчікуваний час: ~2 хв",
                92,
                "~2 хв",
                False
            )
            new_threats["Сумська область"] = (
                "medium", 
                THREAT_BALLISTIC, 
                "Можлива балістична загроза з прикордонних районів РФ.\nОчікуваний час: ~3 хв",
                70,
                "~3 хв",
                True
            )
        
        self._batch_mode = True
        try:
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
                    if old_state.level != "none":
                        self.clear_threat(region)
        finally:
            self._batch_mode = False
            self.flush_fcm_batch()

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
                    import threading
                    threading.Thread(target=backup_sqlite_to_firestore, daemon=True).start()
                except Exception as backup_err:
                    print(f"⚠️ Помилка бекапу SQLite перед початком тесту: {backup_err}")

            if not old_state.is_test and old_state.level != "none":
                self.real_threats_backup[region] = old_state.to_dict()
                self.save_real_threats_to_db()

        has_changed = self.threats[region].set_threat(
            level, threat_type, detail, confidence, eta,
            is_predictive, is_test, group_id=group_id,
            eta_seconds=eta_seconds, telemetry=telemetry
        )
        
        if level in ["critical", "high"] and not is_predictive:
            self.threats[region]._is_official_active = True
        
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
                try:
                    import threading
                    threading.Thread(
                        target=send_fcm_notification,
                        args=(region, level, threat_type, detail),
                        kwargs={
                            "play_sound": play_sound,
                            "confidence": confidence,
                            "eta": eta,
                            "is_official_alarm": self.threats[region].is_active,
                            "is_test": self.threats[region].is_test
                        },
                        daemon=True
                    ).start()
                except Exception as fcm_err:
                    print(f"⚠️ Помилка старту фонової відправки FCM: {fcm_err}")
            
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
                if only_test:
                    original_count = len(state.active_threats)
                    state.active_threats = [t for t in state.active_threats if not t.is_test]
                    if len(state.active_threats) < original_count:
                        any_changed = True
                        if not state.active_threats:
                            state.clear()
                else:
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
            current_official = getattr(self.threats[region], "_is_official_active", False)
            has_changed = (current_official != is_active)
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
