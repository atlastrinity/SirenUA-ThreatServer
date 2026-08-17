"""
Comprehensive Test Suite for Admin Console Endpoints and Cross-Tab Symmetry.
Verifies that all 16 admin console endpoints return HTTP 200 and maintain
100% mathematical symmetry across Dashboard, Chronology, Correlation, and Analytics.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient

# Ensure SirenUA-ThreatServer is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__) + "/.."))

from server import app

client = TestClient(app)


class TestAdminConsoleEndpointsHealth:
    """Тестування доступності та коректності відповідей усіх 16 ендпоінтів адмін-панелі."""

    @pytest.mark.parametrize(
        "endpoint",
        [
            "/api/admin/dashboard/stats",
            "/api/admin/chronology?days=7",
            "/api/admin/chronology/v2?days=7",
            "/api/admin/palantir/overview",
            "/api/admin/palantir/reports",
            "/api/analytics/rules",
            "/api/admin/rules/history",
            "/api/admin/rules/metrics_by_region",
            "/api/admin/errors/stats",
            "/api/admin/errors",
            "/api/admin/analytics/trajectory_heatmap?days=7",
            "/api/admin/analytics/launch_origins?days=7",
            "/api/admin/analytics/region_risk_matrix?days=7",
            "/api/admin/analytics/threat_type_distribution?days=7",
            "/api/admin/analytics/daily_summary?days=7",
            "/api/admin/analytics/flight_corridors?days=7",
        ],
    )
    def test_endpoint_returns_200_and_valid_json(self, endpoint):
        """Перевіряє HTTP 200 та непорожню валідну JSON-структуру."""
        response = client.get(endpoint)
        assert response.status_code == 200, f"Endpoint {endpoint} returned status {response.status_code}"
        data = response.json()
        assert isinstance(data, (dict, list)), f"Endpoint {endpoint} returned unexpected type: {type(data)}"


class TestAdminConsoleCrossTabSymmetry:
    """Перевірка математичної симетрії показників між різними вкладками консолі."""

    def test_7d_total_events_symmetry(self):
        """Перевіряє, що загальна кількість подій за 7 днів однакова на всіх вкладках."""
        dash = client.get("/api/admin/dashboard/stats").json()
        chr_v1 = client.get("/api/admin/chronology?days=7").json()
        chr_v2 = client.get("/api/admin/chronology/v2?days=7").json()
        daily = client.get("/api/admin/analytics/daily_summary?days=7").json()
        types = client.get("/api/admin/analytics/threat_type_distribution?days=7").json()

        total_dash = dash["total_events_7d"]
        total_chr1 = chr_v1["total"]
        total_chr2 = chr_v2["total"]
        total_daily = sum(s["total_events"] for s in daily["summaries"])
        total_types = sum(types["totals"].values())

        # All 5 aggregations must match 100%
        assert total_dash == total_chr1 == total_chr2 == total_daily == total_types
        assert total_dash > 0

    def test_dashboard_internal_breakdown_symmetry(self):
        """Перевіряє, що суми за типами та по годинах на Дашборді точно дорівнюють total_events_7d."""
        dash = client.get("/api/admin/dashboard/stats").json()
        total = dash["total_events_7d"]
        sum_by_type = sum(item["count"] for item in dash["by_type"])
        sum_hourly = sum(item["count"] for item in dash["hourly"])

        assert sum_by_type == total, f"Sum by type ({sum_by_type}) != total ({total})"
        assert sum_hourly == total, f"Sum hourly ({sum_hourly}) != total ({total})"

    def test_accuracy_counters_symmetry(self):
        """Перевіряє абсолютну узгодженість лічильників точності ШІ між Дашбордом, Хронологією та Кореляцією."""
        dash = client.get("/api/admin/dashboard/stats").json()
        chr_v1 = client.get("/api/admin/chronology?days=7").json()
        chr_v2 = client.get("/api/admin/chronology/v2?days=7").json()

        # Dashboard accuracy
        dash_confirmed = dash["accuracy"]["confirmed"]
        dash_mitigated = dash["accuracy"]["mitigated"]
        dash_overestimated = dash["accuracy"]["overestimated"]

        # Chronology v1 match types
        chr1_confirmed = len([e for e in chr_v1["events"] if e.get("match_type") == "confirmed"])
        chr1_mitigated = len([e for e in chr_v1["events"] if e.get("match_type") == "mitigated"])
        chr1_overestimated = len([e for e in chr_v1["events"] if e.get("match_type") == "overestimated"])

        # Correlation v2 stats
        chr2_confirmed = chr_v2["stats"]["confirmed"]
        chr2_mitigated = chr_v2["stats"]["mitigated"]
        chr2_overestimated = chr_v2["stats"]["overestimated"]

        assert dash_confirmed == chr1_confirmed == chr2_confirmed, (
            f"Confirmed mismatch: Dash={dash_confirmed}, Chr1={chr1_confirmed}, Chr2={chr2_confirmed}"
        )
        assert dash_mitigated == chr1_mitigated == chr2_mitigated, (
            f"Mitigated mismatch: Dash={dash_mitigated}, Chr1={chr1_mitigated}, Chr2={chr2_mitigated}"
        )
        assert dash_overestimated == chr1_overestimated == chr2_overestimated, (
            f"Overestimated mismatch: Dash={dash_overestimated}, Chr1={chr1_overestimated}, Chr2={chr2_overestimated}"
        )

    def test_complete_sum_equality_invariant(self):
        """Перевіряє, що у всіх вкладках сума 5 взаємовиключних категорій точно дорівнює загальній кількості."""
        dash = client.get("/api/admin/dashboard/stats").json()
        chr_v1 = client.get("/api/admin/chronology?days=7").json()
        chr_v2 = client.get("/api/admin/chronology/v2?days=7").json()

        # 1. Dashboard: confirmed + mitigated + overestimated + active + cleared == total_events_7d
        dash_acc = dash["accuracy"]
        dash_sum = (
            (dash_acc["confirmed"] or 0)
            + (dash_acc["mitigated"] or 0)
            + (dash_acc["overestimated"] or 0)
            + (dash_acc["active"] or 0)
            + (dash_acc["cleared"] or 0)
        )
        assert dash_sum == dash["total_events_7d"] == dash_acc["total"], (
            f"Dashboard sum ({dash_sum}) != total_events_7d ({dash['total_events_7d']})"
        )

        # 2. Chronology v1 stats: confirmed + mitigated + overestimated + active + cleared == period_total
        chr1_stats = chr_v1["stats"]
        chr1_sum = (
            (chr1_stats["confirmed"] or 0)
            + (chr1_stats["mitigated"] or 0)
            + (chr1_stats["overestimated"] or 0)
            + (chr1_stats["active"] or 0)
            + (chr1_stats["cleared"] or 0)
        )
        assert chr1_sum == chr_v1["period_total"] == dash["total_events_7d"], (
            f"Chr v1 sum ({chr1_sum}) != period_total ({chr_v1['period_total']})"
        )

        # 3. Correlation v2 stats: confirmed + mitigated + overestimated + active + cleared == period_total
        chr2_stats = chr_v2["stats"]
        chr2_sum = (
            (chr2_stats["confirmed"] or 0)
            + (chr2_stats["mitigated"] or 0)
            + (chr2_stats["overestimated"] or 0)
            + (chr2_stats["active"] or 0)
            + (chr2_stats["cleared"] or 0)
        )
        assert chr2_sum == chr_v2["period_total"] == dash["total_events_7d"], (
            f"Chr v2 sum ({chr2_sum}) != period_total ({chr_v2['period_total']})"
        )


class TestAdminConsoleFilteringSymmetry:
    """Перевірка симетрії фільтрації за часом, регіонами, типами загроз та точністю."""

    @pytest.mark.parametrize("days", [1, 7, 30])
    def test_multi_period_filter_symmetry(self, days):
        """Перевіряє симетричність фільтрації за 1, 7, 30 днів."""
        c1 = client.get(f"/api/admin/chronology?days={days}").json()
        c2 = client.get(f"/api/admin/chronology/v2?days={days}").json()
        daily = client.get(f"/api/admin/analytics/daily_summary?days={days}").json()
        types = client.get(f"/api/admin/analytics/threat_type_distribution?days={days}").json()

        t_c1 = c1["total"]
        t_c2 = c2["total"]
        t_daily = sum(s["total_events"] for s in daily["summaries"])
        t_types = sum(types["totals"].values())

        assert t_c1 == t_c2 == t_daily == t_types

    @pytest.mark.parametrize("region", ["Харківська область", "Одеська область", "Полтавська область"])
    def test_region_filter_symmetry(self, region):
        """Перевіряє однаковість результатів фільтру за областю у Хронології v1 та Кореляції v2."""
        c1 = client.get(f"/api/admin/chronology?days=7&region={region}").json()
        c2 = client.get(f"/api/admin/chronology/v2?days=7&region={region}").json()

        assert c1["total"] == c2["total"]
        assert len(c1["events"]) == len(c2["events"])

    @pytest.mark.parametrize("threat_type", ["shahed", "kab", "mig31k"])
    def test_threat_type_filter_symmetry(self, threat_type):
        """Перевіряє однаковість фільтрації за типом загрози."""
        c1 = client.get(f"/api/admin/chronology?days=7&threat_type={threat_type}").json()
        c2 = client.get(f"/api/admin/chronology/v2?days=7&threat_type={threat_type}").json()

        assert c1["total"] == c2["total"]
        assert len(c1["events"]) == len(c2["events"])

    @pytest.mark.parametrize(
        "v1_filter,v2_filter",
        [
            ("match", "match"),
            ("mitigated", "mitigated"),
            ("mismatch", "mismatch"),
        ],
    )
    def test_accuracy_filter_symmetry(self, v1_filter, v2_filter):
        """Перевіряє коректність фільтру точності на обох версіях Хронології."""
        c1 = client.get(f"/api/admin/chronology?days=7&prediction_accuracy={v1_filter}").json()
        c2 = client.get(f"/api/admin/chronology/v2?days=7&match_result={v2_filter}").json()

        assert c1["total"] == c2["total"]
        assert len(c1["events"]) == len(c2["events"])


class TestAdminConsoleErrorManagement:
    """Перевірка ендпоінтів моніторингу та очищення системних помилок."""

    def test_error_summary_and_stats(self):
        """Перевіряє ендпоінти статистики помилок."""
        summary = client.get("/api/admin/errors/summary").json()
        stats = client.get("/api/admin/errors/stats").json()

        assert "total" in summary
        assert "by_source" in summary
        assert "by_type" in summary
        assert "total" in stats
        assert "hourly" in stats
