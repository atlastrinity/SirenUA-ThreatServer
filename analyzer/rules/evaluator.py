"""
Rules Evaluator & Context Generator for Gemini Prompting.
Loads active learned rules, formats them into structured prompt context, and evaluates confidence corrections per region/region group.
"""

import json
import sqlite3
from typing import Dict, Any, List, Optional
from database.db_helpers import get_sqlite_connection
from analyzer.rules.repository import GeminiRulesRepository


def build_rules_prompt_context(db_path: str = "threat_analytics.db", target_region: Optional[str] = None) -> str:
    """
    Loads active learned rules from DB and formats them as context for Gemini prompt.
    Feeds active rules with solid evidence (>= 3 events) and high accuracy (>= 60%).
    """
    repo = GeminiRulesRepository(db_path)
    rules = repo.fetch_rules_by_region(target_region)
    valid_rules = [r for r in rules if r.get("evidence_count", 0) >= 3 and r.get("accuracy_score", 0) >= 0.60]

    if not valid_rules:
        return ""

    ctx = "ІСТОРИЧНІ ПРАВИЛА ТА НАВЧЕНІ ШАБЛОНИ (Застосовуй для точнішого аналізу):\n"
    for i, rule in enumerate(valid_rules, 1):
        ctx += f"{i}. [{rule['rule_type'].upper()}] {rule['rule_text']} (Довіра: {int(rule['accuracy_score']*100)}%)\n"
    return ctx


class GeminiRulesEvaluator:
    """Evaluates rules against incoming threats and region groups."""

    def __init__(self, db_path: str = "threat_analytics.db"):
        self.db_path = db_path
        self.repo = GeminiRulesRepository(db_path)

    def get_confidence_corrections(self) -> Dict[str, int]:
        """
        Loads confidence correction rules for predictive engine.
        Returns map: {(region, threat_type): correction_value}
        """
        conn = get_sqlite_connection(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        corrections = {}
        try:
            cursor.execute('''
                SELECT target_region, threat_type, rule_json
                FROM gemini_rules
                WHERE rule_type = 'confidence_correction' AND is_active = 1
            ''')
            for row in cursor.fetchall():
                try:
                    rjson = json.loads(row["rule_json"]) if row["rule_json"] else {}
                    corr = rjson.get("correction", 0)
                    if corr != 0:
                        corrections[(row["target_region"], row["threat_type"])] = corr
                except Exception:
                    pass
            return corrections
        finally:
            conn.close()

    def evaluate_rules_for_region_group(self, regions: List[str]) -> List[Dict[str, Any]]:
        """Finds all active rules applying to any region in a given region group list."""
        all_rules = []
        for reg in regions:
            reg_rules = self.repo.fetch_rules_by_region(reg)
            for r in reg_rules:
                if r not in all_rules:
                    all_rules.append(r)
        return all_rules
