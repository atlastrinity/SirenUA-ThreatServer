"""
Gemini Rules Engine Package.
Handles autonomous learning, persistence, decay, and prompt-context evaluation for Gemini rules.
"""

from analyzer.rules.models import GeminiRule, RuleType, RuleAuditLogEntry
from analyzer.rules.repository import GeminiRulesRepository
from analyzer.rules.decay import apply_rule_decay
from analyzer.rules.learner import GeminiRulesLearner
from analyzer.rules.evaluator import GeminiRulesEvaluator, build_rules_prompt_context

__all__ = [
    "GeminiRule",
    "RuleType",
    "RuleAuditLogEntry",
    "GeminiRulesRepository",
    "apply_rule_decay",
    "GeminiRulesLearner",
    "GeminiRulesEvaluator",
    "build_rules_prompt_context",
]
