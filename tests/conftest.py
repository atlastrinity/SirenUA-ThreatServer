"""
Pytest configuration and test database isolation fixture.
Ensures running tests NEVER locks or corrupts the live threat_analytics.db.
"""
import os
import tempfile
import pytest

# Point DB_PATH to an isolated temporary test database before any tests import core/database modules
_test_db = tempfile.NamedTemporaryFile(suffix="_test_threat_analytics.db", delete=False)
_test_db_path = _test_db.name
_test_db.close()

os.environ["DB_PATH"] = _test_db_path
os.environ["IS_TEST_ENV"] = "true"

from database.schema import init_analytics_db_tables_only

@pytest.fixture(scope="session", autouse=True)
def setup_isolated_test_db():
    """Initializes schema in the isolated test database and cleans up on session finish."""
    init_analytics_db_tables_only(_test_db_path)
    yield _test_db_path
    if os.path.exists(_test_db_path):
        try:
            os.remove(_test_db_path)
        except Exception:
            pass
