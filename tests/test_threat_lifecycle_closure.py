import pytest
import sqlite3
from datetime import datetime, timezone, timedelta
from database.connection import get_sqlite_connection
from database.analytics_db import log_threat_to_db, log_clearing_to_db
from services.missile_lifecycle_service import cleanup_stale_paired_events


def test_threat_full_lifecycle_logging(tmp_path, monkeypatch):
    """
    Test that every created threat event has a full lifecycle:
    1. Threat creation -> logged in threat_history (high) and paired_events (active).
    2. Threat clearing/timeout -> logged in threat_history (none), paired_events (cleared), and threat_clearings.
    """
    test_db = str(tmp_path / "test_lifecycle.db")
    monkeypatch.setenv("DB_PATH", test_db)
    
    import core.config
    monkeypatch.setattr(core.config, "DB_PATH", test_db)

    # Initialize schema
    from database.schema import init_analytics_db_tables_only
    init_analytics_db_tables_only(test_db)

    region = "Тестова область"
    threat_type = "shahed"
    group_id = "test_shahed_grp_101"
    
    # 1. Log threat start
    t_id = log_threat_to_db(
        region=region,
        level="high",
        threat_type=threat_type,
        detail="БпЛА Shahed курсом на Тестове",
        confidence=90,
        telemetry={"group_id": group_id},
        is_test=False,
        event_timestamp="2026-08-21 20:00:00"
    )
    assert t_id is not None

    conn = get_sqlite_connection(test_db)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM paired_events WHERE threat_event_id = ?", (t_id,))
    pe = c.fetchone()
    assert pe is not None
    assert pe["lifecycle_status"] == "active"
    assert pe["gemini_group_id"] == group_id

    # 2. Simulate stale paired event older than 2 hours
    c.execute("UPDATE paired_events SET created_at = datetime('now', '-3 hours') WHERE id = ?", (pe["id"],))
    conn.commit()
    conn.close()

    # 3. Run cleanup
    cleared = cleanup_stale_paired_events()
    assert cleared >= 1

    # 4. Verify paired_events is cleared and threat_history has 'none'
    conn = get_sqlite_connection(test_db)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("SELECT * FROM paired_events WHERE threat_event_id = ?", (t_id,))
    pe_after = c.fetchone()
    assert pe_after["lifecycle_status"] == "cleared"
    assert pe_after["clearing_event_id"] is not None
    assert pe_after["duration_seconds"] is not None

    c.execute("SELECT * FROM threat_history WHERE region = ? AND threat_level = 'none'", (region,))
    th_clear = c.fetchone()
    assert th_clear is not None
    assert "Відбій" in th_clear["detail"]

    c.execute("SELECT * FROM threat_clearings WHERE original_threat_event_id = ?", (t_id,))
    tc = c.fetchone()
    assert tc is not None
    assert tc["resolution_type"] == "expired"
    conn.close()
