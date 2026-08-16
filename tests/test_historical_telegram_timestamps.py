import asyncio
import pytest
import sqlite3
from datetime import datetime, timezone, timedelta

import core.config
from core.threats.threat_manager import MockThreatManager
from database.threat_logger import log_threat_to_db, log_threat_to_firestore
from database.clearing_logger import log_clearing_to_db
from database.connection import get_sqlite_connection
from monitor.telegram_monitor import TelegramThreatMonitor

TEST_REGIONS = ('Сумська область', 'Харківська область')

@pytest.fixture
def clean_db():
    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM paired_events WHERE region IN (?, ?)", TEST_REGIONS)
    c.execute("DELETE FROM threat_clearings WHERE region IN (?, ?)", TEST_REGIONS)
    c.execute("DELETE FROM threat_history WHERE region IN (?, ?)", TEST_REGIONS)
    conn.commit()
    conn.close()
    yield
    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("DELETE FROM paired_events WHERE region IN (?, ?)", TEST_REGIONS)
    c.execute("DELETE FROM threat_clearings WHERE region IN (?, ?)", TEST_REGIONS)
    c.execute("DELETE FROM threat_history WHERE region IN (?, ?)", TEST_REGIONS)
    conn.commit()
    conn.close()


def test_historical_threat_and_clearing_timestamps(clean_db):
    """Verifies that explicit historical timestamps from Telegram messages are properly recorded in DB."""
    threat_time = "2026-08-15 12:00:00"
    clear_time = "2026-08-15 12:45:00"  # 45 minutes = 2700 seconds later

    # 1. Log threat with historical timestamp
    event_id = log_threat_to_db(
        region="Сумська область",
        level="high",
        threat_type="shahed",
        detail="БпЛА з Курщини",
        confidence=90,
        event_timestamp=threat_time
    )
    assert event_id is not None

    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, threat_type, threat_level FROM threat_history WHERE id = ?", (event_id,))
    row = c.fetchone()
    assert row is not None
    assert row[0] == threat_time
    assert row[1] == "shahed"
    assert row[2] == "high"

    # Verify paired_events created_at
    c.execute("SELECT created_at, lifecycle_status FROM paired_events WHERE threat_event_id = ?", (event_id,))
    pe_row = c.fetchone()
    assert pe_row is not None
    assert pe_row[0] == threat_time
    assert pe_row[1] == "active"
    conn.close()

    # 2. Log clearing with historical timestamp
    clearing_id = log_clearing_to_db(
        region="Сумська область",
        threat_type="shahed",
        message_text="Чисто по БпЛА на Сумщині",
        clearing_confidence=95,
        clearing_timestamp=clear_time
    )
    assert clearing_id is not None

    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, threat_duration_seconds, resolution_type FROM threat_clearings WHERE id = ?", (clearing_id,))
    tc_row = c.fetchone()
    assert tc_row is not None
    assert tc_row[0] == clear_time
    assert tc_row[1] == 2700  # Exact 45 minutes (2700 seconds), NOT 0 seconds!

    # Verify paired_events updated duration
    c.execute("SELECT lifecycle_status, duration_seconds FROM paired_events WHERE threat_event_id = ?", (event_id,))
    pe_updated = c.fetchone()
    assert pe_updated is not None
    assert pe_updated[0] == "cleared"
    assert pe_updated[1] == 2700
    conn.close()


@pytest.mark.asyncio
async def test_telegram_monitor_process_message_with_historical_date(clean_db):
    """Verifies that TelegramThreatMonitor preserves message_date throughout regex processing."""
    from database.analytics_db import on_threat_changed
    manager = MockThreatManager()
    manager.on_change = on_threat_changed
    monitor = TelegramThreatMonitor(manager)

    threat_iso = "2026-08-15T14:10:00+00:00"
    clear_iso = "2026-08-15T14:40:00+00:00"

    # Process threat message from 14:10
    await monitor._process_message_regex(
        text="Пуск КАБ на Сумщину",
        channel="kpszsu",
        message_date=threat_iso
    )
    await asyncio.sleep(0.2)

    state = manager.get_threat("Сумська область")
    assert state is not None
    assert len(state.active_threats) > 0
    threat = state.active_threats[0]
    assert threat.since == threat_iso

    # Process clear message from 14:40
    await monitor._process_message_regex(
        text="Відбій по КАБ Сумщина",
        channel="kpszsu",
        message_date=clear_iso
    )
    await asyncio.sleep(0.2)

    state_after = manager.get_threat("Сумська область")
    assert len(state_after.active_threats) == 0

    # Verify DB records
    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, threat_duration_seconds FROM threat_clearings WHERE region = 'Сумська область' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    assert row is not None
    assert row[0] == "2026-08-15 14:40:00"
    assert row[1] == 1800  # 30 minutes duration (1800s)
    conn.close()


@pytest.mark.asyncio
async def test_gemini_analysis_with_historical_date(clean_db):
    """Verifies that Gemini analysis results carry historical message timestamps into active threats and clearing records."""
    from database.analytics_db import on_threat_changed
    manager = MockThreatManager()
    manager.on_change = on_threat_changed
    monitor = TelegramThreatMonitor(manager)

    threat_time = "2026-08-15T09:00:00+00:00"
    clear_time = "2026-08-15T09:25:00+00:00"

    gemini_threat_result = {
        "threat_level": "high",
        "threat_type": "shahed",
        "target_regions": [{"name": "Харківська область", "detail": "БпЛА в напрямку Харкова"}],
        "confidence_score": 90,
        "source_channel": "monitor",
        "message_date": threat_time
    }

    await monitor._apply_gemini_analysis([gemini_threat_result])
    await asyncio.sleep(0.2)

    state = manager.get_threat("Харківська область")
    assert state is not None
    assert len(state.active_threats) > 0
    assert state.active_threats[0].since == threat_time

    gemini_clear_result = {
        "is_clear": True,
        "threat_type": "shahed",
        "target_regions": ["Харківська область"],
        "confidence_score": 95,
        "source_channel": "monitor",
        "text": "Харківщина чисто",
        "clearing_telemetry": {"resolution_type": "shot_down"},
        "message_date": clear_time
    }

    await monitor._apply_gemini_analysis([gemini_clear_result])
    await asyncio.sleep(0.2)

    state_after = manager.get_threat("Харківська область")
    assert len(state_after.active_threats) == 0

    conn = get_sqlite_connection(core.config.DB_PATH)
    c = conn.cursor()
    c.execute("SELECT timestamp, threat_duration_seconds FROM threat_clearings WHERE region = 'Харківська область' ORDER BY id DESC LIMIT 1")
    row = c.fetchone()
    assert row is not None
    assert row[0] == "2026-08-15 09:25:00"
    assert row[1] == 1500  # 25 minutes (1500s)
    conn.close()

