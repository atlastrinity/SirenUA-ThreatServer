"""
Rules learning and pattern audit engine facade for GeminiThreatAnalyzer.
Delegates to analyzer.rules micro-package.
"""

from typing import Optional, Callable
from analyzer.rules.learner import GeminiRulesLearner
from analyzer.rules.decay import apply_rule_decay


class RulesEngine(GeminiRulesLearner):
    """Backward-compatible proxy class delegating to GeminiRulesLearner."""

    def __init__(self, db_path: str = "threat_analytics.db", rule_audit_callback: Optional[Callable] = None):
        super().__init__(db_path=db_path, rule_audit_callback=rule_audit_callback)

    def _decay_outdated_rules(self, cursor):
        return apply_rule_decay(cursor, self._rule_audit_callback)
