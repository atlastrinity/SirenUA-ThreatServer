"""
Database repository for gemini_rules and gemini_rules_audit tables.
"""

import json
import sqlite3
from typing import List, Dict, Any, Optional
from database.db_helpers import get_sqlite_connection
from analyzer.rules.models import GeminiRule


class GeminiRulesRepository:
    """Handles read/write operations for learned Gemini rules and audit logs."""

    def __init__(self, db_path: str = "threat_analytics.db"):
        self.db_path = db_path

    def fetch_active_rules(self, min_accuracy: float = 0.50) -> List[Dict[str, Any]]:
        """Returns all active rules matching accuracy threshold."""
        conn = get_sqlite_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            cursor.execute('''
                SELECT * FROM gemini_rules
                WHERE is_active = 1 AND accuracy_score >= ?
                ORDER BY evidence_count DESC, accuracy_score DESC
            ''', (min_accuracy,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def fetch_rules_by_region(self, region_name: Optional[str] = None) -> List[Dict[str, Any]]:
        """Fetches active rules relevant to a specific region or all regions."""
        conn = get_sqlite_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        try:
            if region_name:
                cursor.execute('''
                    SELECT * FROM gemini_rules
                    WHERE is_active = 1
                      AND (target_region = ? OR source_region = ? OR target_region IS NULL)
                    ORDER BY evidence_count DESC, accuracy_score DESC
                ''', (region_name, region_name))
            else:
                cursor.execute('''
                    SELECT * FROM gemini_rules
                    WHERE is_active = 1
                    ORDER BY target_region, source_region, evidence_count DESC
                ''')
            rows = cursor.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()

    def log_audit_entry(
        self,
        action: str,
        rule_type: Optional[str] = None,
        rule_text: Optional[str] = None,
        source_region: Optional[str] = None,
        target_region: Optional[str] = None,
        threat_type: Optional[str] = None,
        reason: Optional[str] = None
    ):
        """Records a rule change in gemini_rules_audit table."""
        conn = get_sqlite_connection(self.db_path)
        cursor = conn.cursor()
        try:
            cursor.execute('''
                INSERT INTO gemini_rules_audit (
                    action, rule_type, rule_text, source_region, target_region, threat_type, reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (action, rule_type, rule_text, source_region, target_region, threat_type, reason))
            conn.commit()
        except Exception as e:
            print(f"⚠️ [Rules Repository] Помилка запису audit log: {e}")
        finally:
            conn.close()
