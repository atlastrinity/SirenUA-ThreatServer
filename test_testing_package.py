"""
Unit tests for the modular testing package (testing/).
Verifies scenario generation, manager execution, and cleaner scrubbing.
"""

from testing import (
    VALID_SCENARIOS,
    generate_scenario_threats,
    test_scenario_manager,
    delete_test_history_from_sqlite,
    delete_test_history_from_firestore,
    purge_all_test_data,
)
from core.threats.threat_manager import MockThreatManager

def test_testing_package_scenarios():
    assert "shaheds_south" in VALID_SCENARIOS
    assert "mig_takeoff" in VALID_SCENARIOS
    assert "clear" in VALID_SCENARIOS

    threats = generate_scenario_threats("shaheds_south")
    assert "Одеська область" in threats
    assert "Миколаївська область" in threats
    assert threats["Одеська область"][0] == "medium"
    assert threats["Одеська область"][1] == "shahed"

def test_testing_package_manager_and_cleaner():
    tm = MockThreatManager()
    
    # 1. Apply scenario
    applied = test_scenario_manager.apply_scenario("shaheds_south", tm)
    assert applied is True
    assert tm.threats["Одеська область"].level == "medium"
    assert tm.threats["Одеська область"].active_threats[0].is_test is True

    # 2. Clear scenario
    cleared = test_scenario_manager.apply_scenario("clear", tm)
    assert cleared is True
    assert tm.threats["Одеська область"].level == "none"
    assert len(tm.threats["Одеська область"].active_threats) == 0

    # 3. Test purge_all_test_data
    purge_res = purge_all_test_data()
    assert purge_res["status"] == "success"
    assert "sqlite" in purge_res
    print("✅ testing package unit test passed successfully!")
