"""
Unit tests for multi-threat group tracking, separation across all threat types,
and intelligent Telegram multi-channel deduplication.
"""

import pytest
from core.threats.threat_state_model import ThreatState
from core.threats.threat_manager import MockThreatManager


class MockScheduler:
    def schedule_notification(self, **kwargs):
        pass
    def cancel_pending(self, region):
        return False


def create_test_manager():
    mgr = MockThreatManager()
    mgr.fcm_scheduler = MockScheduler()
    return mgr


class TestMultiThreatTrackingAndDedup:

    def test_same_type_distinct_groups_retained(self):
        """Перевірка: дві групи одного типу (Shahed) з різними цілями/group_id зберігаються окремо."""
        state = ThreatState(region_name="Одеська область")

        # Група 1: на Одесу
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="1-ша група БпЛА курсом на Одесу",
            confidence=90,
            eta="~20 хв",
            group_id="shahed_odesa_1",
            telemetry={"group_id": "shahed_odesa_1", "final_target_cities": ["Одеса"]}
        )

        # Група 2: на Ізмаїл
        state.set_threat(
            level="medium",
            threat_type="shahed",
            detail="2-га група БпЛА з моря на Ізмаїл",
            confidence=85,
            eta="~45 хв",
            group_id="shahed_izmail_2",
            telemetry={"group_id": "shahed_izmail_2", "final_target_cities": ["Ізмаїл"]}
        )

        assert len(state.active_threats) == 2
        gids = [t.group_id for t in state.active_threats]
        assert "shahed_odesa_1" in gids
        assert "shahed_izmail_2" in gids

        # Рівень області — найвищий серед загроз (high)
        assert state.level == "high"

    def test_telegram_channel_duplicate_deduplication(self):
        """Перевірка: дублюючі повідомлення з різних каналів про одну ціль оновлюють існуючу загрозу."""
        state = ThreatState(region_name="Одеська область")

        # Канал 1 (kpszsu)
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="БпЛА в напрямку Одеси з Чорного моря",
            confidence=85,
            eta="~30 хв",
            telemetry={"final_target_cities": ["Одеса"], "attack_vector": "sea_to_coast"}
        )
        assert len(state.active_threats) == 1
        initial_threat_id = state.active_threats[0].threat_id

        # Канал 2 (vanek_nikolaev, через 20 секунд про ту саму загрозу)
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="Шахеди курсом на Одесу",
            confidence=95,
            eta="~25 хв",
            telemetry={"final_target_cities": ["Одеса"], "attack_vector": "sea_to_coast"}
        )

        # Має залишитися 1 загроза (дедуплікована і оновлена)
        assert len(state.active_threats) == 1
        assert state.active_threats[0].threat_id == initial_threat_id
        assert state.active_threats[0].confidence == 95
        assert state.active_threats[0].eta == "~25 хв"

    def test_kab_multiple_waves_support(self):
        """Перевірка: кілька хвиль КАБів у Харківській області зберігаються окремо."""
        state = ThreatState(region_name="Харківська область")

        state.set_threat(
            level="high",
            threat_type="kab",
            detail="Пуски КАБ на Харків",
            confidence=90,
            eta="~5 хв",
            telemetry={"final_target_cities": ["Харків"], "wave_number": 1}
        )

        state.set_threat(
            level="high",
            threat_type="kab",
            detail="Повторні пуски КАБ на Чугуїв",
            confidence=90,
            eta="~5 хв",
            telemetry={"final_target_cities": ["Чугуїв"], "wave_number": 2}
        )

        assert len(state.active_threats) == 2

    def test_cruise_missile_multiple_groups(self):
        """Перевірка: кілька груп крилатих ракет з різними напрямками зберігаються окремо."""
        state = ThreatState(region_name="Київська область")

        state.set_threat(
            level="critical",
            threat_type="cruise_missile",
            detail="1-ша група крилатих ракет на Київ",
            confidence=95,
            eta="~10 хв",
            group_id="missile_kyiv_1",
            telemetry={"final_target_cities": ["Київ"]}
        )

        state.set_threat(
            level="critical",
            threat_type="cruise_missile",
            detail="2-га група крилатих ракет на Білу Церкву",
            confidence=95,
            eta="~15 хв",
            group_id="missile_bc_2",
            telemetry={"final_target_cities": ["Біла Церква"]}
        )

        assert len(state.active_threats) == 2

    def test_mixed_threat_types_coexistence(self):
        """Перевірка: різні типи загроз (Shahed + Cruise Missile + Ballistic) одночасно активні."""
        state = ThreatState(region_name="Дніпропетровська область")

        state.set_threat(level="medium", threat_type="shahed", detail="БпЛА на Дніпро")
        state.set_threat(level="high", threat_type="cruise_missile", detail="Ракета на Кривий Ріг")
        state.set_threat(level="critical", threat_type="ballistic", detail="Балістика на Павлоград")

        assert len(state.active_threats) == 3
        types = [t.threat_type for t in state.active_threats]
        assert "shahed" in types
        assert "cruise_missile" in types
        assert "ballistic" in types

        # Загальний рівень має бути critical
        assert state.level == "critical"
        assert state.threat_type == "ballistic"

    def test_selective_clear_by_group_id_in_manager(self):
        """Перевірка: ThreatManager.clear_threat знімає тільки цільову групу."""
        mgr = create_test_manager()
        region = "Одеська область"

        mgr.set_threat(region, "medium", "shahed", detail="Група 1 на Одесу", telemetry={"group_id": "shahed_g1"})
        mgr.set_threat(region, "high", "shahed", detail="Група 2 на Ізмаїл", telemetry={"group_id": "shahed_g2"})

        assert len(mgr.threats[region].active_threats) == 2

        # Знімаємо тільки групу 1
        mgr.clear_threat(region, group_id="shahed_g1")
        assert len(mgr.threats[region].active_threats) == 1
        assert mgr.threats[region].active_threats[0].group_id == "shahed_g2"
        assert mgr.threats[region].level == "high"

        # Знімаємо групу 2
        mgr.clear_threat(region, group_id="shahed_g2")
        assert len(mgr.threats[region].active_threats) == 0
        assert mgr.threats[region].level == "none"

    def test_serialization_contains_all_active_threats(self):
        """Перевірка: to_dict() серіалізує всі загрози з координатами для карти та карток."""
        state = ThreatState(region_name="Одеська область")

        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="БпЛА з Чорного моря на Одесу",
            group_id="shahed_1",
            telemetry={"group_id": "shahed_1", "origin_latitude": 45.2, "origin_longitude": 31.0}
        )
        state.set_threat(
            level="medium",
            threat_type="shahed",
            detail="БпЛА з Криму на Ізмаїл",
            group_id="shahed_2",
            telemetry={"group_id": "shahed_2", "origin_latitude": 45.0, "origin_longitude": 35.8}
        )

        d = state.to_dict()
        assert "active_threats" in d
        assert len(d["active_threats"]) == 2
        assert d["active_threats"][0]["group_id"] == "shahed_1"
        assert d["active_threats"][0]["origin_latitude"] == 45.2
        assert d["active_threats"][1]["group_id"] == "shahed_2"
        assert d["active_threats"][1]["origin_latitude"] == 45.0

    def test_wave_group_id_normalization_dedup(self):
        """Перевірка: '_wave2' та '_w2' нормалізуються і дедуплікуються в одну загрозу."""
        state = ThreatState(region_name="Одеська область")

        # Канал 1: повідомлення о 10:40 з ID ..._wave2
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="Нова група з 6 БпЛА у напрямку Чорноморська/Одеси",
            confidence=90,
            eta="~30-50 хв",
            group_id="shahed_odesa_sea_wave2",
            telemetry={
                "group_id": "shahed_odesa_sea_wave2",
                "target_count": 6,
                "launch_origin": "Чорне море",
                "attack_vector": "sea_to_coast",
                "final_target_cities": ["Одеса", "Чорноморськ"],
                "wave_number": 2
            }
        )
        assert len(state.active_threats) == 1

        # Канал 2: повідомлення о 10:51 з ID ..._w2 про ту саму групу
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="Нова група з 6 БпЛА у напрямку Чорноморська/Одеси",
            confidence=95,
            eta="~30-40 хв",
            group_id="shahed_odesa_sea_w2",
            telemetry={
                "group_id": "shahed_odesa_sea_w2",
                "target_count": 6,
                "launch_origin": "Чорне море",
                "attack_vector": "sea_to_coast",
                "final_target_cities": ["Одеса", "Чорноморськ"],
                "wave_number": 2
            }
        )

        # Має бути рівно 1 загроза з оновленим confidence=95
        assert len(state.active_threats) == 1
        assert state.active_threats[0].confidence == 95
        assert state.active_threats[0].eta == "~30-40 хв"

    def test_all_threat_types_telemetry_signature_dedup(self):
        """Перевірка дедуплікації для крилатих ракет, балістики, КАБів та авіації."""
        # 1. Крилаті ракети (Калібр / Х-101)
        state_missile = ThreatState(region_name="Київська область")
        state_missile.set_threat(
            level="critical",
            threat_type="cruise_missile",
            detail="Крилаті ракети з Каспію курсом на Васильків/Київ",
            group_id="missile_caspian_wave1",
            telemetry={"launch_origin": "Каспійське море", "attack_vector": "east_to_west", "final_target_cities": ["Київ", "Васильків"], "target_count": 4}
        )
        state_missile.set_threat(
            level="critical",
            threat_type="kh101",
            detail="Х-101 з Каспію в напрямку Києва/Василькова",
            group_id="missile_caspian_w1",
            telemetry={"launch_origin": "Каспійське море", "attack_vector": "east_to_west", "final_target_cities": ["Київ", "Васильків"], "target_count": 4}
        )
        assert len(state_missile.active_threats) == 1

        # 2. Балістика (Іскандер-М)
        state_bal = ThreatState(region_name="Харківська область")
        state_bal.set_threat(
            level="critical",
            threat_type="ballistic",
            detail="Загроза балістики з Бєлгородської області",
            group_id="bal_belgorod_1",
            telemetry={"launch_origin": "Бєлгородська область", "attack_vector": "north_to_south", "final_target_cities": ["Харків"]}
        )
        state_bal.set_threat(
            level="critical",
            threat_type="iskander_m",
            detail="Пуск Іскандер-М з Бєлгорода на Харків",
            group_id="bal_belgorod_launch1",
            telemetry={"launch_origin": "Бєлгородська область", "attack_vector": "north_to_south", "final_target_cities": ["Харків"]}
        )
        assert len(state_bal.active_threats) == 1

        # 3. МіГ-31К (Кинджал)
        state_mig = ThreatState(region_name="м. Київ")
        state_mig.set_threat(
            level="critical",
            threat_type="mig31k",
            detail="Зліт МіГ-31К з аеродрому Саваслейка",
            group_id="mig31k_savasleyka_w1",
            telemetry={"launch_origin": "Саваслейка", "weapon_subtype": "Х-47М2 Кинджал"}
        )
        state_mig.set_threat(
            level="critical",
            threat_type="kinzhal",
            detail="Швидкісна ціль (Кинджал) на Київ",
            group_id="mig31k_savasleyka_wave1",
            telemetry={"launch_origin": "Саваслейка", "weapon_subtype": "Х-47М2 Кинджал"}
        )
        assert len(state_mig.active_threats) == 1

    def test_tu22m3_cross_channel_origin_variation_dedup(self):
        """
        Перевірка: повідомлення eRadarrua ('tu22m3_south_sea_1', 'Акваторія Чорного моря')
        та kpszsu ('tu22m3_black_sea_1', 'Акваторія Чорного моря (Флот РФ)') для Одеської,
        Миколаївської та Херсонської областей успішно дедуплікуються в 1 загрозу.
        """
        for region in ["Одеська область", "Миколаївська область", "Херсонська область"]:
            state = ThreatState(region_name=region)

            # Канал 1: eRadarrua
            state.set_threat(
                level="high",
                threat_type="tu22m3",
                detail="Загроза пусків Х-22 на південному напрямку",
                confidence=65,
                eta="~3-10 хв",
                group_id="tu22m3_south_sea_1",
                telemetry={
                    "group_id": "tu22m3_south_sea_1",
                    "attack_vector": "sea_to_coast",
                    "target_count": 1,
                    "speed_kmh": 4200,
                    "launch_origin": "Акваторія Чорного моря",
                    "weapon_subtype": "Х-22",
                    "final_target_cities": ["Одеса", "Миколаїв"]
                }
            )
            assert len(state.active_threats) == 1

            # Канал 2: kpszsu (через кілька секунд)
            state.set_threat(
                level="high",
                threat_type="tu22m3",
                detail="Ту-22м3 в акваторії Чорного моря. Загроза пусків ракет Х-22!",
                confidence=72,
                eta="~3-10 хв",
                group_id="tu22m3_black_sea_1",
                telemetry={
                    "group_id": "tu22m3_black_sea_1",
                    "attack_vector": "sea_to_coast",
                    "target_count": 1,
                    "speed_kmh": 4200,
                    "launch_origin": "Акваторія Чорного моря (Флот РФ)",
                    "weapon_subtype": "Х-22/Х-32",
                    "final_target_cities": ["Одеса", "Миколаїв", "Херсон"]
                }
            )

            # Переконуємося, що не створено 2-й картки
            assert len(state.active_threats) == 1
            assert state.active_threats[0].confidence == 72
            assert state.level == "high"

    def test_shahed_origin_parenthesis_variation_dedup(self):
        """Перевірка дедуплікації при варіаціях назви точки пуску (з дужками РФ та без)."""
        state = ThreatState(region_name="Миколаївська область")
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="Шахеди курсом на Миколаїв",
            group_id="shahed_akhtarsk_1",
            telemetry={
                "launch_origin": "Приморсько-Ахтарськ (Краснодарський край РФ)",
                "attack_vector": "northeast_to_southwest",
                "final_target_cities": ["Миколаїв"],
                "target_count": 2
            }
        )
        state.set_threat(
            level="high",
            threat_type="shahed",
            detail="2 БпЛА на Миколаїв",
            group_id="shahed_primorsko_akhtarsk_w1",
            telemetry={
                "launch_origin": "Приморсько-Ахтарськ",
                "attack_vector": "northeast_to_southwest",
                "final_target_cities": ["Миколаїв"],
                "target_count": 2
            }
        )
        assert len(state.active_threats) == 1


