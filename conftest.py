"""
Pytest configuration and global fixtures for SirenUA-ThreatServer.
Guarantees 100% isolated test database and prevents any pollution of production database.
"""

import os
import sys
import tempfile
import pytest

# Ensure server root is on sys.path
SERVER_ROOT = os.path.abspath(os.path.dirname(__file__))
if SERVER_ROOT not in sys.path:
    sys.path.insert(0, SERVER_ROOT)


@pytest.fixture(scope="session", autouse=True)
def isolated_test_database():
    """
    Session-wide fixture that redirects DB_PATH to a dedicated temporary SQLite database.
    Guarantees that production threat_analytics.db is never touched during test runs.
    """
    # Create isolated temp database
    temp_dir = tempfile.mkdtemp(prefix="sirenua_test_db_")
    test_db_path = os.path.join(temp_dir, "test_threat_analytics.db")

    # Set environment variable
    os.environ["DB_PATH"] = test_db_path
    os.environ["IS_TEST_ENVIRONMENT"] = "true"

    # Initialize schema on the isolated test database
    import core.config
    import database.connection
    import database.schema

    core.config.DB_PATH = test_db_path
    database.connection.DB_PATH = test_db_path

    # Build full schema tables
    database.schema.init_analytics_db(test_db_path)

    yield test_db_path

    # Cleanup temporary database
    try:
        if os.path.exists(test_db_path):
            os.remove(test_db_path)
        if os.path.exists(temp_dir):
            import shutil
            shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass
