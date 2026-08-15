"""
MockThreatManager state coordinator and DB persistence manager.
"""

import os
import json
import time
import threading
from typing import Optional

from core.regions import ALL_REGIONS
from core.threats.threat_state_model import ThreatState
from database.db_helpers import (
    get_db,
    backup_sqlite_to_firestore,
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    send_fcm_notification,
    run_firestore_with_retry,
)
from core.notification_policy import FCMNotificationScheduler


class MockThreatManager:
    """Менеджер загроз — зберігає стан для всіх областей."""

    def __init__(self):
        self.threats: dict[str, ThreatState] = {}

        self.real_threats_backup: dict = {}
        self._clear_lock = threading.Lock()
        self._batch_mode: bool = False
        
        self._save_timer = None
        self._save_real_timer = None
        self._save_lock = threading.Lock()
        self._fcm_batch_buffer = []
        self.fcm_scheduler = FCMNotificationScheduler()
        
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
                SELECT p.region, p.threat_level, p.threat_type, p.confidence_at_set, p.gemini_group_id, p.was_predictive,
                       t.attack_vector, t.speed_kmh, t.heading_degrees, t.distance_to_target_km, t.target_cities_coords,
                       th.detail as threat_detail, th.timestamp as threat_timestamp
                FROM paired_events p
                LEFT JOIN telemetry_data t ON p.telemetry_id = t.id
                LEFT JOIN threat_history th ON p.threat_event_id = th.id
                WHERE p.lifecycle_status = 'active'
                ORDER BY p.id ASC
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

                        since_ts = row["threat_timestamp"]
                        if since_ts and isinstance(since_ts, str):
                            if "T" not in since_ts:
                                since_ts = since_ts.replace(" ", "T") + "+00:00"

                        self.threats[region].set_threat(
                            level=row["threat_level"],
                            threat_type=row["threat_type"],
                            detail=row["threat_detail"] or f"Загроза {row['threat_type']}",
                            confidence=row["confidence_at_set"],
                            is_predictive=bool(row["was_predictive"]),
                            group_id=row["gemini_group_id"],
                            telemetry=telemetry,
                            since=since_ts
                        )
                        restored_count += 1
                self._execute_save_to_db()
                print(f"💾 Відновлено {restored_count} активних загроз та траєкторій з локальної SQLite.")
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

        # Always check if active threats need to be restored from SQLite
        has_active_threats = any(len(s.active_threats) > 0 for s in self.threats.values())
        if not has_active_threats:
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
            unique_suffix = f"{os.getpid()}_{threading.get_ident()}_{time.time_ns()}"
            tmp_path = f"{filepath}.{unique_suffix}.tmp"

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
        from testing import test_scenario_manager
        test_scenario_manager.apply_scenario(scenario, self)

    def set_threat(self, region: str, level: str,
                   threat_type: Optional[str] = None,
                   detail: Optional[str] = None,
                   confidence: Optional[int] = None,
                   eta: Optional[str] = None,
                   is_predictive: bool = False,
                   is_test: bool = False,
                   telemetry: dict = None,
                   rules_applied: list = None,
                   eta_seconds: Optional[int] = None,
                   group_id: Optional[str] = None) -> bool:
        from core.regions import REGION_ALIASES, PERMANENTLY_OCCUPIED_REGIONS
        norm_region = REGION_ALIASES.get(region, region)
        if norm_region not in self.threats or norm_region in PERMANENTLY_OCCUPIED_REGIONS:
            return False
        region = norm_region

        old_state = self.threats[region]
        old_level = old_state.level

        if not group_id and telemetry and isinstance(telemetry, dict):
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
        
        if has_changed:
            is_official = (threat_type == "official_alarm")
            if self._batch_mode:
                self._fcm_batch_buffer.append({
                    "region": region,
                    "level": level,
                    "threat_type": threat_type,
                    "detail": detail,
                    "confidence": confidence,
                    "eta": eta,
                    "is_official_alarm": is_official,
                    "is_test": self.threats[region].is_test
                })
            else:
                self.fcm_scheduler.schedule_notification(
                    region=region,
                    level=level,
                    threat_type=threat_type,
                    detail=detail,
                    confidence=confidence,
                    eta=eta,
                    is_official_alarm=is_official,
                    is_test=self.threats[region].is_test,
                    active_check_fn=lambda r: r in self.threats and (self.threats[r].level != "none" if level != "none" else self.threats[r].level == "none")
                )
            
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
        
        for item in items:
            send_fcm_notification(
                item["region"],
                item["level"],
                item["threat_type"],
                item["detail"],
                confidence=item["confidence"],
                eta=item["eta"],
                is_official_alarm=item["is_official_alarm"],
                is_test=item["is_test"]
            )
        print(f"🚀 FCM batch flush: {len(items)} сповіщень")

    def clear_threat(self, region: str, clearing_telemetry: dict = None,
                      group_id: str = None, threat_type: str = None) -> bool:
        from core.regions import PERMANENTLY_OCCUPIED_REGIONS
        if region not in self.threats or region in PERMANENTLY_OCCUPIED_REGIONS:
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
            current_level = old_state.level
            if current_level == "none":
                # Якщо сповіщення було в пендінгу на верифікаційній паузі — скасовуємо його
                if not self.fcm_scheduler.cancel_pending(region):
                    send_fcm_notification(region, "none",
                                          threat_type=threat_type,
                                          is_official_alarm=(threat_type == "official_alarm"),
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
                    had_test_flag = state.is_test
                    state.active_threats = [t for t in state.active_threats if not t.is_test]
                    if len(state.active_threats) < original_count or had_test_flag:
                        any_changed = True
                        if not state.active_threats:
                            state.clear()
                            send_fcm_notification(region, "none", is_test=True)
                        else:
                            state.is_test = any(t.is_test for t in state.active_threats)
                else:
                    has_changed = (state.level != "none")
                    if has_changed:
                        is_test_flag = state.is_test
                        state.clear()
                        
                        self.fcm_scheduler.cancel_pending(region)
                        send_fcm_notification(region, "none", is_test=is_test_flag)
                        
                        if not is_test_flag:
                            self.real_threats_backup[region] = state.to_dict()
                        any_changed = True
                    
            if any_changed:
                self._execute_save_to_db()
                self._execute_save_real_threats_to_db()

                # Trigger post-mortem reflection when real threat waves clear
                if not only_test:
                    try:
                        import asyncio
                        from analyzer.rules.post_mortem import GeminiPostMortemAnalyzer
                        analyzer = GeminiPostMortemAnalyzer()
                        try:
                            loop = asyncio.get_running_loop()
                            loop.create_task(analyzer.run_post_mortem(hours=3))
                        except RuntimeError:
                            pass
                    except Exception as pm_err:
                        print(f"⚠️ [ThreatManager] Помилка запуску Post-Mortem: {pm_err}")

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

    def set_alarm_active(self, region: str, is_active: bool, alert_type: Optional[str] = None) -> bool:
        from core.regions import PERMANENTLY_OCCUPIED_REGIONS
        if region not in self.threats or region in PERMANENTLY_OCCUPIED_REGIONS:
            return False
        
        if region in self.real_threats_backup:
            self.real_threats_backup[region]["is_active"] = is_active
            if alert_type:
                self.real_threats_backup[region]["official_alert_type"] = alert_type
            elif not is_active:
                self.real_threats_backup[region]["official_alert_type"] = None
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
                "official_alert_type": alert_type if is_active else None,
                "is_test": False
            }

        if not self.threats[region].is_test:
            current_official = getattr(self.threats[region], "_is_official_active", False)
            current_alert_type = getattr(self.threats[region], "official_alert_type", None)
            has_changed = (current_official != is_active) or (is_active and alert_type and current_alert_type != alert_type)
            self.threats[region].is_active = is_active
            self.threats[region].official_alert_type = alert_type if is_active else None
            
            if has_changed:
                level_str = "high" if is_active else "none"
                
                # Determine detailed notification and threat type based on official alert type
                threat_type_code = "official_alarm"
                alert_type_lower = (alert_type or "").lower()
                if alert_type_lower in ("artillery", "art"):
                    threat_type_code = "artillery"
                    detail_str = "Загроза артилерійського обстрілу" if is_active else "Відбій загрози артобстрілу"
                elif alert_type_lower in ("urban_fights", "urban"):
                    threat_type_code = "urban_fights"
                    detail_str = "Вуличні бої" if is_active else "Відбій загрози вуличних боїв"
                elif alert_type_lower in ("chemical", "chem"):
                    threat_type_code = "chemical"
                    detail_str = "Хімічна небезпека" if is_active else "Відбій хімічної небезпеки"
                elif alert_type_lower in ("nuclear", "nuc"):
                    threat_type_code = "nuclear"
                    detail_str = "Радіаційна небезпека" if is_active else "Відбій радіаційної небезпеки"
                else:
                    detail_str = "Повітряна тривога" if is_active else "Відбій повітряної тривоги"

                send_fcm_notification(
                    region=region,
                    level=level_str,
                    threat_type=threat_type_code,
                    detail=detail_str,
                    is_official_alarm=is_active,
                    is_test=False
                )
                self.save_real_threats_to_db()
                self.save_to_db()
                if hasattr(self, 'on_change'):
                    self.on_change(region, self.threats[region], telemetry=None)
                return True
        else:
            if region in self.real_threats_backup:
                self.real_threats_backup[region]["is_active"] = is_active
                if alert_type:
                    self.real_threats_backup[region]["official_alert_type"] = alert_type
                elif not is_active:
                    self.real_threats_backup[region]["official_alert_type"] = None
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
